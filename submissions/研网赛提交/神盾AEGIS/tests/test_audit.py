import json
import subprocess
import sys
from pathlib import Path

from aegis.audit import AuditStore
from aegis.guard import AegisGuard
from aegis.models import Decision


def test_sqlite_audit_redacts_secrets_persists_and_exports_in_new_process(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    export_path = tmp_path / "export.json"

    raw_secret_akia = "AKIAIOSFODNN7EXAMPLE"
    raw_secret_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nQUARANTINE_DATA\n-----END OPENSSH PRIVATE KEY-----"
    raw_secret_aws = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # 1. 运行守卫，写入一条含示例密钥的阻断记录
    guard = AegisGuard(audit_db=db_path)
    session_id = "test_audit_session"
    
    # 模拟用户输入
    user_verdict = guard.inspect_user(session_id, "请帮我更新 SSH 授权密钥")
    assert user_verdict.decision == Decision.ALLOW

    # 模拟攻击或敏感写入行为，参数中包含明文密钥材料
    content = f"{raw_secret_akia}\n{raw_secret_key}\n{raw_secret_aws}"
    blocked_verdict = guard.inspect_tool_call(
        session_id,
        "fs.write",
        {"path": "~/.ssh/authorized_keys", "content": content},
    )
    assert blocked_verdict.decision == Decision.BLOCK
    assert "fs-write-sensitive" in [p["id"] for p in blocked_verdict.policies]

    # 保存快照同步
    guard.snapshot(session_id)

    # 2. 释放连接与对象
    del guard

    # 3. 校验数据库文件本身在落盘时就已经脱敏
    db_bytes = db_path.read_bytes()
    assert raw_secret_akia.encode() not in db_bytes
    assert b"BEGIN OPENSSH PRIVATE KEY" not in db_bytes
    assert b"wJalrXUtnFEMI" not in db_bytes

    # 4. 用全新的独立子进程调用 CLI 导出 JSON
    cmd = [
        sys.executable,
        "-m",
        "aegis",
        "audit",
        "export",
        "--db",
        str(db_path),
        "--session",
        session_id,
        "--output",
        str(export_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert res.returncode == 0

    # 5. 校验导出的 JSON 文件内容
    exported_text = export_path.read_text(encoding="utf-8")

    # 必须不含任何密钥原文
    assert raw_secret_akia not in exported_text
    assert "AKIA" not in exported_text
    assert "BEGIN OPENSSH PRIVATE KEY" not in exported_text
    assert "wJalrXUtnFEMI" not in exported_text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in exported_text

    # 决策、策略编号、路径、DAG 和影响面仍然完整保留
    data = json.loads(exported_text)
    assert "sessions" in data
    assert len(data["sessions"]) == 1
    sess = data["sessions"][0]
    assert sess["session_id"] == session_id

    # 影响面存在且保留路径与阻断决策
    impacts = sess["impact"]
    assert any(imp["type"] == "credential" and "~/.ssh/authorized_keys" in imp["value"] and imp["decision"] == "block" for imp in impacts)

    # DAG 存在且包含节点与边
    dag = sess["dag"]
    assert len(dag.get("nodes", [])) > 0
    assert any(n["kind"] == "tool" and n["decision"] == "block" for n in dag["nodes"])

    # 记录中包含决策、策略编号和阻断
    records = sess["records"]
    assert len(records) >= 2  # user + tool
    tool_rec = next(r for r in records if r["tool"] == "fs.write")
    assert tool_rec["decision"] == "block"
    assert "fs-write-sensitive" in tool_rec["policy_ids"]
    assert tool_rec["action"] != ""
    assert "detail" in tool_rec
    # 参数详情里的敏感密钥被脱敏占位符取代
    assert "«redacted»" in str(tool_rec["detail"])
