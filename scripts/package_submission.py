"""组装本次Python源码提交包及文件指纹，不读取密钥或调用模型。"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
NAME = "尹纪元+神盾AEGIS+可执行程序.zip"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    review = json.loads((ROOT / "docs/evidence/submission_review.json").read_text())
    summary = json.loads((ROOT / "data/corpus/minimax_m3_1_flash_preview_summary.json").read_text())
    assert review["pytest_passed"] > 10000 and review["scenarios_passed"] == 31 and review["steps_passed"] == 91
    assert review["pdf_pages"] > 0 and review["pdf_visual_reviewed_pages"] == review["pdf_pages"]
    assert len(review["code_revision"]) == 40 and all(c in "0123456789abcdef" for c in review["code_revision"])
    assert summary["successful_unique"] == 10000 and summary["unresolved_failed_unique"] == 0
    assert digest(ROOT / "data/corpus/minimax_m3_1_flash_preview_runs.jsonl") == summary["raw_results_sha256"]
    paired = {}
    for layer, expected_rows in [("replay", 72), ("live", 48)]:
        result = json.loads((ROOT / f"data/evaluation/paired_{layer}_summary.json").read_text())
        assert result["rows"] == expected_rows
        assert digest(ROOT / f"data/evaluation/paired_{layer}_runs.jsonl") == result["raw_sha256"]
        paired[layer] = {k: result[k] for k in ["rows", "raw_sha256", "http_receipts", "usage"]}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stage = OUT / "package-stage" / stamp / "神盾AEGIS"
    stage.mkdir(parents=True, exist_ok=False)

    def copy(path: Path) -> None:
        assert path.is_file() and not path.is_symlink()
        relative = path.relative_to(ROOT)
        assert not any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in relative.parts)
        assert path.name != ".aegis.local.json" and not path.name.startswith(".env")
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

    for name in ["README.md", "ROADMAP.md", "LICENSE", "pyproject.toml", "Dockerfile", "Makefile", ".gitignore"]:
        copy(ROOT / name)
    for directory in ["src", "tests", "scripts", "docs", "examples", ".github"]:
        for path in sorted((ROOT / directory).rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if any(
                part in {"__pycache__", ".pytest_cache", ".git", ".venv", "build", "dist"}
                or part.endswith(".egg-info") for part in path.relative_to(ROOT).parts
            ) or path.suffix in {".pyc", ".pyo"}:
                continue
            if path.name == ".DS_Store" or path.name.startswith(".env"):
                continue
            copy(path)
    for path in sorted((ROOT / "data/corpus").iterdir()):
        if not path.is_file() or path.suffix not in {".json", ".jsonl"}:
            continue
        if path.name in {"injection_10k.jsonl", "row_oracle.json", "manifest.json"} or path.name.startswith("minimax_m3_1_flash_preview_"):
            copy(path)
    for name in ["paired_manifest.json", "paired_replay_runs.jsonl", "paired_replay_summary.json",
                 "paired_live_runs.jsonl", "paired_live_summary.json", "injecagent_adapted_cases.json",
                 "LICENCE_InjecAgent.txt", "development_live_incident.json", "development_live_interrupted_runs.jsonl"]:
        copy(ROOT / "data/evaluation" / name)
    copy(OUT / "demo/paired_eval.html")
    for kind, ext in [("pdf", "pdf"), ("docx", "docx")]:
        copy(OUT / kind / f"尹纪元+神盾AEGIS+作品文档.{ext}")
    (stage / "交付说明.txt").write_text(
        "神盾 AEGIS Python可运行源码提交包\n"
        "需要Python 3.11及以上；安装与验证见README。不是Windows独立编译程序。\n"
        "完整作品文档在output/pdf和output/docx；两种格式同源。\n"
        "历史 MiniMax 实测证据在 data/corpus；新攻防对照、原始回执和公开来源许可在 data/evaluation。\n"
        "打开 output/demo/paired_eval.html 查看离线对照；现场演示与源码讲解见 docs。\n"
        "未完成的 Kimi 记录不进入本包。不含实际 API 密钥。\n"
        f"已验证代码基线：{review['code_revision']}\n"
        "历史实测在交付修复前完成，原始结果不回填修改。\n",
        encoding="utf-8",
    )
    files = [
        {"path": str(p.relative_to(stage)), "bytes": p.stat().st_size, "sha256": digest(p)}
        for p in sorted(stage.rglob("*")) if p.is_file()
    ]
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "validated_code_revision": review["code_revision"],
        "validation": {k: review[k] for k in ["pytest_passed", "scenarios_passed", "steps_passed", "pdf_pages", "pdf_visual_reviewed_pages"]},
        "historical_model": summary["model"],
        "historical_completed_samples": summary["successful_unique"],
        "paired_evaluation": paired,
        "files": files,
        "exclusions": ["actual keys", ".aegis.local.json", ".env*", ".venv", ".git", "runtime locks", "caches"],
    }
    (stage / "delivery_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    archive = OUT / NAME
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in sorted(stage.rglob("*")):
            if path.is_file(): z.write(path, Path("神盾AEGIS") / path.relative_to(stage))
    external = {
        **manifest,
        "archive": {"path": NAME, "bytes": archive.stat().st_size, "sha256": digest(archive)},
        "package_source_directory": str(stage.relative_to(ROOT)),
    }
    (OUT / "提交清单.json").write_text(json.dumps(external, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "source_files": len(files), "stage": str(stage)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
