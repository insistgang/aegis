"""本机模型切换、凭据隔离和 MiniMax 工具协议兼容。全部离线。"""

import io
import http.client
import json
import threading
import urllib.error
from urllib.request import Request, urlopen

import pytest

from aegis.agent import AgentConfigError, LiveChat, live_backend_from_env, run_tool_agent
from aegis.serve import make_server


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    for name in (
        "AEGIS_LLM_API_KEY", "KIMI_API_KEY", "MINIMAX_API_KEY", "AEGIS_LLM_BASE_URL",
        "AEGIS_LLM_MODEL", "AEGIS_LLM_REASONING_EFFORT", "AEGIS_LLM_MAX_COMPLETION_TOKENS",
        "AEGIS_LLM_KEYS_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AEGIS_LLM_CONFIG", str(tmp_path / "local.json"))


def configure(monkeypatch, tmp_path):
    credentials = tmp_path / "keys.txt"
    credentials.write_text(
        "url:https://api.kimi.com/coding/v1\nkey:kimi-test-secret\n\n"
        "url:https://api.minimaxi.com/v1\nkey:minimax-test-secret\n"
    )
    config = {
        "base_url": "https://api.minimaxi.com/v1",
        "model": "MiniMax-M3.1-Flash-Preview",
        "keys_file": str(credentials),
        "reasoning_effort": "low",
        "max_completion_tokens": 1024,
    }
    (tmp_path / "local.json").write_text(json.dumps(config))
    return config


def test_local_config_selects_only_the_matching_provider_key(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("KIMI_API_KEY", "must-not-send-to-minimax")
    backend = live_backend_from_env()
    assert backend.model == "MiniMax-M3.1-Flash-Preview"
    assert backend.api_key == "minimax-test-secret"
    assert backend.reasoning_effort == "low"
    assert backend.max_completion_tokens == 1024
    assert backend.api_key not in repr(backend)


def test_explicit_environment_overrides_local_config(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "explicit-secret")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "explicit-model")
    assert live_backend_from_env().api_key == "explicit-secret"
    assert live_backend_from_env().model == "explicit-model"


def test_minimax_does_not_fall_back_to_a_kimi_key(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://api.minimaxi.com/v1")
    monkeypatch.setenv("KIMI_API_KEY", "wrong-provider-secret")
    with pytest.raises(AgentConfigError):
        live_backend_from_env()


def test_minimax_tool_roundtrip_preserves_reasoning_and_records_model(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    backend = live_backend_from_env()
    requests = []
    responses = [
        {"role": "assistant", "content": "", "reasoning_content": "Need the README.",
         "tool_calls": [{"id": "read", "type": "function", "function": {
             "name": "fs_read", "arguments": '{"path":"README.md"}'}}]},
        {"role": "assistant", "content": "安装说明已读取。", "reasoning_content": "Done."},
    ]

    def respond(request, timeout):
        requests.append(json.loads(request.data))
        message = responses[len(requests) - 1]
        return io.BytesIO(json.dumps({
            "model": "MiniMax-M3.1-Flash-Preview",
            "choices": [{"finish_reason": "tool_calls" if message.get("tool_calls") else "stop", "message": message}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }).encode())

    monkeypatch.setattr("aegis.agent.urllib.request.urlopen", respond)
    result = run_tool_agent("读取 README 并总结用法", "# 项目说明", backend)
    assert result["steps"][0]["executed"] is True
    assert requests[0]["reasoning_effort"] == "low"
    assert requests[0]["max_completion_tokens"] == 1024
    assert requests[1]["messages"][3]["reasoning_content"] == "Need the README."
    assert result["llm"]["model"] == result["llm"]["reported_model"] == backend.model
    assert result["llm"]["usage"]["total_tokens"] == 30
    assert backend.api_key not in json.dumps(result)


@pytest.mark.parametrize("payload", [
    {"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": ""}}]},
    {"base_resp": {"status_code": 1008, "status_msg": "insufficient quota"}},
])
def test_incomplete_or_rejected_responses_are_not_reported_as_success(monkeypatch, payload):
    monkeypatch.setattr("aegis.agent.urllib.request.urlopen", lambda *a, **k: io.BytesIO(json.dumps(payload).encode()))
    with pytest.raises(AgentConfigError):
        LiveChat("https://api.minimaxi.com/v1", "test-secret", "MiniMax-M3.1-Flash-Preview").complete([], [])


def test_api_error_redacts_the_api_key(monkeypatch):
    def reject(*args, **kwargs):
        raise urllib.error.HTTPError("https://api.minimaxi.com/v1", 403, "Forbidden", {}, io.BytesIO(b"test-secret"))

    monkeypatch.setattr("aegis.agent.urllib.request.urlopen", reject)
    with pytest.raises(AgentConfigError) as error:
        LiveChat("https://api.minimaxi.com/v1", "test-secret", "MiniMax-M3.1-Flash-Preview").complete([], [])
    assert "test-secret" not in str(error.value)


def test_panel_model_configuration_is_public_without_secrets(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    server = make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/llm") as response:
            data = json.load(response)
        assert data["configured"] is True
        assert data["model"] == "MiniMax-M3.1-Flash-Preview"
        assert data["reasoning_effort"] == "low"
        assert "secret" not in json.dumps(data)
        assert "keys_file" not in data and "api_key" not in data
    finally:
        server.shutdown()
        server.server_close()


def test_corpus_output_separates_minimax_from_existing_kimi_results(monkeypatch, tmp_path):
    from scripts.run_kimi_corpus import default_output

    configure(monkeypatch, tmp_path)
    assert default_output().name == "minimax_m3_1_flash_preview_runs.jsonl"


def test_corpus_resume_rejects_a_different_models_records(tmp_path):
    from scripts.run_kimi_corpus import done_ids

    path = tmp_path / "mixed.jsonl"
    path.write_text(json.dumps({"id": "c00001", "ok": True, "llm": {"model": "other-model"}}) + "\n")
    with pytest.raises(AgentConfigError):
        done_ids(path, model="MiniMax-M3.1-Flash-Preview")


def test_cli_reports_the_configured_model_without_its_key(monkeypatch, tmp_path, capsys):
    from aegis.__main__ import main

    configure(monkeypatch, tmp_path)
    monkeypatch.setattr(LiveChat, "complete", lambda *a: {"role": "assistant", "content": "已读取。"})
    assert main(["agent", "--backend", "live", "--text", "# 项目说明"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["llm"]["model"] == "MiniMax-M3.1-Flash-Preview"
    assert "minimax-test-secret" not in output


@pytest.fixture
def agent_endpoint(monkeypatch):
    from aegis.agent import ScriptedChat

    def backend():
        return ScriptedChat([{"role": "assistant", "content": "离线接口已调用。"}])

    monkeypatch.setattr("aegis.agent.live_backend_from_env", backend)
    server = make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("origin,content_type,status", [
    ("https://attacker.example", "application/json", 403),
    ("null", "application/json", 403),
    ("same", "text/plain", 415),
    (None, "text/plain", 415),
])
def test_agent_endpoint_rejects_cross_origin_and_simple_requests(
    monkeypatch, agent_endpoint, origin, content_type, status,
):
    def forbidden_backend():
        raise AssertionError("被拒绝的请求不得调用模型")

    monkeypatch.setattr("aegis.agent.live_backend_from_env", forbidden_backend)
    headers = {"Content-Type": content_type}
    if origin is not None:
        headers["Origin"] = agent_endpoint if origin == "same" else origin
    request = Request(
        agent_endpoint + "/api/agent/run",
        data=json.dumps({"backend": "live", "text": "# 文档"}).encode(),
        headers=headers,
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urlopen(request)
    assert error.value.code == status


@pytest.mark.parametrize("browser_origin", [False, True])
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_agent_endpoint_accepts_same_origin_and_programmatic_json(agent_endpoint, browser_origin, host):
    authority = f"{host}:{agent_endpoint.rsplit(':', 1)[1]}"
    headers = {"Content-Type": "application/json; charset=utf-8", "Host": authority}
    if browser_origin:
        headers["Origin"] = f"http://{authority}"
    request = Request(
        agent_endpoint + "/api/agent/run",
        data=json.dumps({"backend": "live", "text": "# 文档"}).encode(),
        headers=headers,
    )
    with urlopen(request) as response:
        assert json.load(response)["answer"] == "离线接口已调用。"


@pytest.mark.parametrize("host,origin", [
    ("attacker.example:{port}", "http://attacker.example:{port}"),
    ("attacker.example:{port}", None),
    ("localhost:{wrong_port}", "http://localhost:{wrong_port}"),
    ("localhost:not-a-port", "http://localhost:not-a-port"),
    ("localhost:{port}/", "http://localhost:{port}/"),
    ("user@localhost:{port}", "http://user@localhost:{port}"),
    ("localhost:{port}", "http://localhost:{port}/"),
    ("localhost:{port}", "http://localhost:{port}?"),
    ("localhost:{port}", "https://localhost:{port}"),
    ("[::1", "http://[::1"),
])
def test_agent_endpoint_rejects_forged_or_malformed_host_and_origin(monkeypatch, agent_endpoint, host, origin):
    def forbidden_backend():
        raise AssertionError("非法 Host 或 Origin 不得调用模型")

    monkeypatch.setattr("aegis.agent.live_backend_from_env", forbidden_backend)
    port = int(agent_endpoint.rsplit(":", 1)[1])
    values = {"port": port, "wrong_port": port - 1}
    headers = {"Content-Type": "application/json", "Host": host.format(**values)}
    if origin is not None:
        headers["Origin"] = origin.format(**values)
    request = Request(
        agent_endpoint + "/api/agent/run",
        data=json.dumps({"backend": "live", "text": "# 文档"}).encode(),
        headers=headers,
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urlopen(request)
    assert error.value.code == 403


@pytest.mark.parametrize("duplicated", ["Host", "Origin"])
def test_agent_endpoint_rejects_duplicate_origin_or_host(monkeypatch, agent_endpoint, duplicated):
    def forbidden_backend():
        raise AssertionError("重复边界请求头不得调用模型")

    monkeypatch.setattr("aegis.agent.live_backend_from_env", forbidden_backend)
    port = int(agent_endpoint.rsplit(":", 1)[1])
    body = json.dumps({"backend": "live", "text": "# 文档"}).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port)
    try:
        connection.putrequest("POST", "/api/agent/run", skip_host=True)
        for name, value in (("Host", f"127.0.0.1:{port}"), ("Origin", agent_endpoint)):
            connection.putheader(name, value)
            if name == duplicated:
                connection.putheader(name, value)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        assert connection.getresponse().status == 403
    finally:
        connection.close()


def test_one_turn_corpus_observation_is_not_marked_complete(monkeypatch, tmp_path):
    from scripts.run_kimi_corpus import done_ids, one

    configure(monkeypatch, tmp_path)
    calls = []

    def tool_response(*args):
        calls.append(1)
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "read", "type": "function", "function": {
                "name": "fs_read", "arguments": '{"path":"README.md"}',
            },
        }]}

    monkeypatch.setattr(LiveChat, "complete", tool_response)
    result = one({
        "id": "partial", "text": "# 项目说明", "channel": "resource",
        "label": 0, "split": "test", "family": "summarize", "lang": "zh",
    })
    assert len(calls) == 1
    assert result["ok"] is False
    assert result["completed"] is False
    assert result["status"] == "incomplete"
    output = tmp_path / "results.jsonl"
    output.write_text(json.dumps(result) + "\n")
    assert done_ids(output, model="MiniMax-M3.1-Flash-Preview") == set()


def test_resume_does_not_skip_legacy_empty_answers_or_explicitly_incomplete_records(tmp_path):
    from scripts.run_kimi_corpus import done_ids

    records = [
        {"id": "old-partial", "ok": True, "status": "finished", "answer": ""},
        {"id": "new-partial", "ok": True, "status": "incomplete", "completed": False},
        {"id": "done", "ok": True, "status": "finished", "completed": True, "answer": "完成。"},
    ]
    for record in records:
        record["llm"] = {"model": "test-model"}
    output = tmp_path / "results.jsonl"
    output.write_text("\n".join(json.dumps(record) for record in records))
    assert done_ids(output, model="test-model") == {"done"}


@pytest.mark.parametrize("field,value", [
    ("base_url", 123),
    ("base_url", []),
    ("base_url", "not-an-http-url"),
    ("model", ["test-model"]),
    ("keys_file", {"path": "keys.txt"}),
    ("reasoning_effort", ["low"]),
    ("max_completion_tokens", True),
    ("max_completion_tokens", 1.5),
])
def test_invalid_local_config_has_a_controlled_error(monkeypatch, tmp_path, field, value):
    from aegis.agent import llm_settings

    config = tmp_path / "invalid.json"
    config.write_text(json.dumps({field: value}))
    monkeypatch.setenv("AEGIS_LLM_CONFIG", str(config))
    with pytest.raises(AgentConfigError):
        llm_settings()


def test_panel_invalid_config_returns_json_error_instead_of_dropping_connection(monkeypatch, tmp_path):
    config = tmp_path / "invalid.json"
    config.write_text(json.dumps({"base_url": 123}))
    monkeypatch.setenv("AEGIS_LLM_CONFIG", str(config))
    server = make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/llm")
        assert error.value.code == 400
        assert json.load(error.value)["configured"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_scripted_panel_run_still_works_with_invalid_live_config(monkeypatch, tmp_path):
    config = tmp_path / "invalid.json"
    config.write_text(json.dumps({"reasoning_effort": ["low"]}))
    monkeypatch.setenv("AEGIS_LLM_CONFIG", str(config))
    server = make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_address[1]}/api/agent/run",
            data=json.dumps({"backend": "scripted", "text": "# 项目说明"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request) as response:
            result = json.load(response)
        assert result["model_backend"] == "ScriptedChat"
        assert result["completed"] is True
        assert result["configured_live"] is False
    finally:
        server.shutdown()
        server.server_close()
