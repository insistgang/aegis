"""CLI 不把耗尽回合但未取得最终回答的演练报为成功。"""

import json

from aegis.__main__ import main


def test_agent_cli_returns_failure_for_incomplete_tool_loop(monkeypatch, capsys):
    import aegis.agent as agent

    scripted = agent.ScriptedChat
    call = {
        "role": "assistant", "content": "",
        "tool_calls": [{"id": "read", "type": "function", "function": {
            "name": "fs_read", "arguments": '{"path":"README.md"}',
        }}],
    }
    monkeypatch.setattr(agent, "ScriptedChat", lambda turns: scripted([call]))
    code = main(["agent", "--text", "# 普通项目文档"])
    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["status"] == "incomplete"
