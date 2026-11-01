# MiniMax 全量实测方法快照

本目录于 2026-10-18 归档运行结束后的本机执行器文件，用于审阅 [全量实测报告](../../MiniMax全量实测报告.md) 的方法。

| 文件 | 内容 |
| --- | --- |
| [full_runner_snapshot.py.txt](full_runner_snapshot.py.txt) | 原始语料遍历、模型工具循环、HTTP 响应回执、断点、限流退避与进度记录 |
| [watcher_snapshot.py.txt](watcher_snapshot.py.txt) | 失败恢复、完成核验与初版报告生成逻辑 |
| [manifest.json](manifest.json) | 两份快照的 SHA256 和字节数 |

快照以 `.txt` 保存，避免被误认作已发布的运行入口。它们包含 `/tmp` 和本机文件布局假设。运行中曾调整并发、请求间隔与恢复逻辑，某些进程还在使用修改前已加载的版本；前 100 条分层初测来自单独的临时驱动。因此，这些快照不构成所有历史进程源码的逐版本归档，也不保证逐 token 复现。

本次工作区含未提交改动，没有开跑时完整代码的独立冻结提交；快照用于审阅最终文件，不作为完整历史版本的替代。

完整实验参数还需结合 `data/corpus/minimax_m3_1_flash_preview_stratified_100_manifest.json`、`minimax_m3_1_flash_preview_speed_tuning.json`、`minimax_m3_1_flash_preview_progress.json` 与逐条 JSONL 回执。报告中的结果来自逐条记录重算，而不是重新执行这些快照。

监督快照内的初版报告生成器早于本次人工审阅修订。当前权威文字是 `docs/MiniMax全量实测报告.md`，不要用快照覆盖它。

本次全量运行统一使用 `MiniMax-M3.1-Flash-Preview`、`reasoning_effort=low`、最多三个模型回合。通用 `scripts/run_kimi_corpus.py` 每条仅一个回合，任务措辞也不同，不能混作同一协议。

本目录不含密钥或逐条模型回答，不会调用模型；本次报告更新也没有发起新的付费请求。原始 `*_runs.jsonl` 被 Git 忽略，应作为单独的数据附件留存。
