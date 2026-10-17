# 神盾 AEGIS

面向会调工具、读写文件、访问网络、派发子 Agent 的 LLM Agent，做提示注入和工具滥用的**检测 → 研判 → 阻断 → 溯源**。

执法点是一个确定性引擎，不把放行权再交给另一个可以被注入的模型。同一套引擎有三种接法：进程内 SDK、MCP 中间代理、本地研判看板。

间接注入场景的研判原文：

> 用户原始请求为读取项目 README 文档，Agent 却调用 fs.read 读取本地 SSH 私钥文件，并通过 net.fetch 向外部未知域名 evil.example 发起数据传输，判定为间接提示注入引发的工具滥用行为。

## 赛题能力

| 能力 | 落点 |
| --- | --- |
| 多源注入识别 | 用户输入、网页 / 邮件 / Issue / 源码 / 工具返回、MCP 工具描述、长期记忆 |
| 意图—计划—工具对齐 | 锁定用户任务，解释偏离，而不是只报一个分数 |
| 工具策略与三态决策 | YAML DSL：放行 / 询问 / 阻断。基线规则不能被配置降级 |
| 跨 MCP 与子 Agent 溯源 | 调用链、影响边、token 下标、文件 / 域名 / 仓库 / 凭据影响面，DAG 与时序 |
| 对抗鲁棒 | 同形字母、零宽字符、分词、多轮拼接、注释、全角、Base64、超长稀释、语义伪装 |

回归集：**31 个场景，91 步，当前全部通过。** 其中包含 CVE-2025-53773 那一类「不可信 Issue → 本地命令执行」的防御，以及不可信知识库不能写 cron、不能推送的提权防御。

## 运行

需要 Python 3.11 及以上。不需要 GPU，也不需要模型 API。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
aegis demo
aegis serve
```

打开 <http://127.0.0.1:8765>。左侧是场景，右侧是研判、攻击路径和时序。

三种接法：

```python
from aegis import AegisGuard, Decision

guard = AegisGuard()
verdict = guard.inspect_user("s1", "请读取项目 README 并总结用法")
if verdict.decision is not Decision.ALLOW:
    raise SystemExit(verdict.explanation)
```

```bash
aegis proxy --name github -- python your_mcp_server.py
aegis scan --channel resource --file untrusted.txt
```

策略文件在 `src/aegis/data/default.yaml`。换成自己的文件时设置 `AEGIS_POLICY`。缺了赛题基线，或者把基线从阻断改成放行，加载会直接失败。

## 文档

- [整体设计](docs/设计文档.md)
- [部署说明](docs/部署说明.md)
- [测试样例与流程](docs/测试说明.md)

## 设计上故意不做的事

裁判不走大模型。生成式裁判会被同一条注入打穿，而且比赛回归对不齐。语义伪装靠「敏感对象 + 外发动作 + 目的地」再加上会话污点，不靠把文本再喂给一个模型。
