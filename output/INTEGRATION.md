# 神盾 AEGIS 整合交付说明

> 本文件说明**源码仓库**与**竞赛交付包**两份原件的关系，以及整合后的可追溯状态。
> 核对日期：2026-10-31。核对方式：本地只读比对 + 隔离环境重新验证。

## 一、两份原件

| 原件 | 位置 | 性质 |
| --- | --- | --- |
| 源码仓库 | `/Users/insistgang/Desktop/个人工具/secruity_game` | Git 仓库，`main` 分支，远端 `git@github.com:insistgang/aegis.git`（**私有**） |
| 竞赛交付包 | `/Users/insistgang/Desktop/研网赛提交/神盾AEGIS` | 纯目录快照，**非 Git 仓库** |

两者内容高度重合，但角色不同：仓库承载开发历史与可追溯提交，交付包承载最终提交稿、实测证据与清单。

## 二、提交与基线关系

源码仓库当前 HEAD 为 `5978f8f552cae7085c594e8fb195f89e14161330`，本地与远端实时值一致（`git ls-remote` 核对，分叉 0/0）。

交付包《交付说明.txt》声明的**已验证代码基线为 `b98951800a29b09f238bd0c6583d086396711f4d`**，该基线是 `5978f8f` 的直接父提交。

两者之间的差异**只有文档与交付产物，没有任何源码改动**：

```
$ git diff --stat b989518..5978f8f
 ROADMAP.md                                         |   2 +-
 docs/evidence/submission_review.json              |  53 ++++---
 docs/...记录.md                                     |   2 +
 output/docx/...作品文档.docx                       | Bin 671586 -> 674495 bytes
 output/pdf/...作品文档.pdf                         | Bin 1140090 -> 1211058 bytes
 output/...源码交付包.zip                             | Bin 7199643 -> 7433159 bytes
 output/提交清单.json                                 | 170 ++++++++++++-------
 7 files changed, 154 insertions(+), 73 deletions(-)
```

即：`b989518` 的代码已被验证，`5978f8f` 只把作品文档从 22 页更新为 24 页、并同步重打源码包与清单。**交付包对应的代码逻辑与仓库 HEAD 完全等价**。

## 三、文件级比对结果

对仓库 144 个跟踪文件与交付包 147 个文件做逐文件 blob 哈希比对：

- **共同文件 142 个：内容 100% 一致，0 处差异。**
- 交付包独有 5 个：`交付说明.txt`、`delivery_manifest.json`、`data/corpus/` 下 3 个 MiniMax 实测 JSONL。
- 仓库独有 2 个：`output/提交清单.json`、`output/尹纪元+神盾AEGIS+可执行程序.zip`。

两份清单 `output/提交清单.json` 与交付包 `delivery_manifest.json` 的**核心字段完全相同**（`created_at_utc`、`validated_code_revision`、`validation`、`historical_model`、`historical_completed_samples`、`paired_evaluation`、`danger_probe`、`files`（均 146 条）、`exclusions`）；仓库版另含 `archive`（打包文件 sha256）与 `package_source_directory`（打包来源目录）两个键，是**更新的超集**。

交付包与仓库的打包暂存目录 `output/package-stage/20261018T124045Z/神盾AEGIS` 经 `diff -rq` 比对**零差异**，证明交付包即该次打包产物本身。

源码交付 ZIP 的 sha256 `640d9a0134aa3dbaf78f706aa7af716f05e39521a1912c11c31c91b88fa514ce` 与清单 `archive.sha256` 记录**一致**。

## 四、隔离环境重新验证

将交付包复制到独立目录 `/tmp/aegis-verify`，新建虚拟环境仅从本地依赖安装（PyYAML、pytest），**不调用任何外部模型接口**：

| 验证项 | 结果 | 与交付声明比对 |
| --- | --- | --- |
| `pytest` 全量 | **10397 项全部通过**（31.61 秒） | 与 `validation.pytest_passed = 10397` 一致 |
| 场景回归 `aegis demo` | **31/31 场景、91/91 步通过** | 与 `validation.scenarios_passed / steps_passed` 一致 |
| 146 个交付文件 SHA256 + 字节数 | **146/146 全部匹配**，0 缺失 0 不匹配 | 与 `files[]` 记录一致 |
| CLI 可用性 | `aegis --help` 正常，七个子命令齐备（demo/scan/serve/proxy/show/audit/agent） | — |
| 密钥排除 | `.aegis.local.json`、`.env*`、`.venv`、`.git` 均不在包内；密钥样式扫描仅命中 `QUARANTINE` / `QUARANTINE_DATA` 等**伪造隔离夹具** | 与 `exclusions[]` 一致 |
| 离线演示 | `output/demo/paired_eval.html` 1,856,088 字节，四组归档数据齐备 | — |

> **环境说明**：直接在 WorkBuddy 宿主环境下运行时会出现 6 项 failed + 71 项 error，根因是宿主注入的 `sitecustomize.py` 拦截文件操作（`FileExistsError`）与测试夹具中的 `python -m aegis` 子进程找不到已安装包。用 `python -S` 并显式补齐 `site-packages` 与 `src` 路径后全部通过。**这是宿主环境干扰，不是交付包缺陷**——记录于此以免后续复验者误判。

## 五、实测数据的存放位置

3 个 MiniMax 实测 JSONL（约 20 MB）被 `.gitignore` 的 `data/corpus/*_runs.jsonl` 规则排除，**不作为散文件跟踪在 Git 中**，但：

- 三者**物理存在于**源码仓库工作区 `data/corpus/`；
- 三者**完整包含在交付源码包内**，`delivery_manifest.json` 记录了各自 SHA256 与字节数，与本地实测值逐项一致；
- 解压后**可按报告中的路径与 SHA256 独立核验**。

这是有意设计而非遗漏，README《最新提交文件》章节已说明该逻辑。原始模型记录不进入 Git 历史，可避免仓库体积膨胀，同时不损失证据可核验性。

## 六、整合后状态与可追溯性

| 项目 | 状态 |
| --- | --- |
| 源码仓库 → 远端 | 已同步，`5978f8f`，分叉 0/0 |
| 交付产物（PDF / DOCX / 提交清单 / 源码 ZIP） | 全部在远端私有仓库 `output/`，本地与远端 blob 哈希一致 |
| 交付包 → 打包暂存目录 | `diff -rq` 零差异 |
| 交付包 → 仓库 HEAD | 142 个共同文件内容 100% 一致 |
| 交付包基线 `b989518` → 仓库 HEAD `5978f8f` | 仅 7 个文档/产物文件变化，无源码改动 |

任何一环都可独立复核：仓库侧用 `git show`、`git ls-tree`；交付包侧用 `delivery_manifest.json` 的 SHA256；打包侧用 ZIP 指纹 `640d9a01…`。

## 七、边界声明

- 本次整合**未修改任何原始文件**：两份原件保持原样，本文件为新增说明。
- 交付包内 **PDF 与 Word 同源 24 页、19 张表、6 幅图**，PDF 1,211,058 字节，24 页均完成视觉复核（依据 `docs/交付复核记录.md` 与交付清单记录）。
- 本文件记录的是**交付一致性与可复现性**，不代表重新执行了真实模型实测。MiniMax 10000 条实测结果为历史记录，其原始结果不回填修改。
- 公开数据为六例适配，**不是完整基准，也不是真实企业流量**；默认 token 为审计分词；企业部署、压力容量与大规模独立对抗效果尚未验证。
