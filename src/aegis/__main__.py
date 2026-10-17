"""命令行：demo、scan、serve、proxy。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.runner import run_all, run_scenario, summary
from aegis.serve import serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="神盾 AEGIS：LLM Agent 闭环防护")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="回放全部场景")
    scan = sub.add_parser("scan", help="检查一段文本")
    scan.add_argument("--channel", default="resource", choices=["user", "resource", "memory", "tool_desc"])
    scan.add_argument("--text", default="")
    scan.add_argument("--file", default="")
    scan.add_argument("--op", default="read", choices=["read", "write"])

    panel = sub.add_parser("serve", help="打开本地研判看板")
    panel.add_argument("--host", default="127.0.0.1")
    panel.add_argument("--port", type=int, default=8765)

    proxy = sub.add_parser("proxy", help="作为 MCP 中间代理转发上游 stdio server")
    proxy.add_argument("--name", default="upstream")
    proxy.add_argument("--config", default=None, help="多上游配置文件路径（JSON 或 YAML）")
    proxy.add_argument("upstream", nargs=argparse.REMAINDER)

    show = sub.add_parser("show", help="打印一个场景的研判结论")
    show.add_argument("scenario")

    audit = sub.add_parser("audit", help="SQLite 审计记录与导出")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_export = audit_sub.add_parser("export", help="导出 JSON 审计记录")
    audit_export.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    audit_export.add_argument("--session", default=None, help="指定会话 ID（可选）")
    audit_export.add_argument("--output", default=None, help="输出 JSON 文件路径（默认标准输出）")

    args = parser.parse_args(argv)
    if args.command == "demo":
        return _demo()
    if args.command == "scan":
        return _scan(args)
    if args.command == "serve":
        serve(args.host, args.port)
        return 0
    if args.command == "proxy":
        from aegis.proxy import serve_stdio

        upstream = list(args.upstream)
        if upstream and upstream[0] == "--":
            upstream = upstream[1:]
        return serve_stdio(upstream, server_name=args.name, config_path=args.config)
    if args.command == "show":
        report = run_scenario(args.scenario)
        print(report["narrative"])
        print(report["mermaid"])
        return 0 if report["passed"] else 1
    if args.command == "audit":
        from aegis.audit import AuditStore

        store = AuditStore(args.db)
        if args.audit_command == "export":
            content = store.export_json(session_id=args.session, output_path=args.output)
            if not args.output:
                print(content)
            return 0
    return 2


def _demo() -> int:
    reports = run_all()
    totals = summary(reports)
    width = max(len(item["id"]) for item in reports)
    for report in reports:
        mark = "PASS" if report["passed"] else "FAIL"
        print(f"{mark}  {report['id']:<{width}}  {report['title']}")
        if report["passed"]:
            continue
        for step in report["steps"]:
            if not step["ok"]:
                print(f"      {step['op']} {step['tool']} 期望 {step['expect']} 实际 {step['got']}")
                print(f"      {step['verdict']['explanation']}")
    print(
        f"\n{totals['passed_scenarios']}/{totals['scenarios']} 个场景，"
        f"{totals['passed_steps']}/{totals['steps']} 步"
    )
    return 0 if totals["passed_scenarios"] == totals["scenarios"] else 1


def _scan(args) -> int:
    from aegis.serve import _scan as scan_payload

    text = args.text
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    if not text:
        print("需要 --text 或 --file", file=sys.stderr)
        return 2
    result = scan_payload({"channel": args.channel, "text": text, "op": args.op, "source": args.file or "cli"})
    print(json.dumps(result["verdict"], ensure_ascii=False, indent=2))
    return 0 if result["verdict"]["decision"] == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
