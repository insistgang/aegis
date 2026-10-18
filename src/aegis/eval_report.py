"""从已归档记录生成离线可交互演示，默认不调用模型。"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.evaluation import summarize


def render_html(datasets: dict[str, list[dict]], output: Path) -> None:
    public = {}
    for name, rows in datasets.items():
        public[name] = {"summary": summarize(rows), "rows": [
            {k: value for k, value in row.items() if k not in {"assistant_turns", "receipts"}}
            for row in rows
        ]}
    payload = json.dumps(public, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    template = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>神盾 AEGIS 攻防对照演示</title><style>
*{box-sizing:border-box}body{margin:0;background:#f6f7f5;color:#17231d;font:15px/1.6 system-ui,-apple-system,sans-serif}main{max-width:1400px;margin:auto;padding:32px}h1{font-size:30px;margin:0}h2{font-size:19px;margin-top:0}.muted{color:#526159}select,button{font:inherit;padding:8px 14px;border:1px solid #b9c4bd;background:white;border-radius:5px}label{display:inline-block;margin:10px 20px 10px 0}.panel{background:white;border:1px solid #d7dfd9;padding:22px;margin:20px 0;border-radius:7px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:18px}.arm{overflow:auto}.allow{color:#267248}.block{color:#a13328}.ask{color:#8b640a}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:10px;text-align:left;border-bottom:1px solid #e4e9e5;vertical-align:top}th{background:#edf2ee}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,monospace;max-height:500px;overflow:auto;background:#f5f7f4;padding:12px}code{overflow-wrap:anywhere}svg{width:100%;min-width:420px}.tag{display:inline-block;background:#edf2ee;padding:3px 9px;border-radius:4px;margin-right:5px}.legend{border-left:4px solid #407956;padding-left:14px}details{margin-top:14px}summary{cursor:pointer}#cards p{margin:8px 0}@media(max-width:600px){main{padding:16px}.panel{padding:14px}}
</style><main><h1>神盾 AEGIS 攻防对照</h1><p class="muted">六类工具 · 实际临时副作用 · 来源、调用与阻断证据</p>
<p class="legend">固定轨迹用于检查门禁本身；真实模型数据保留模型不触发、环境拒绝、错误与未完成。两层结果分别展示，不能合并成一个防护成功率。</p>
<label>实验层 <select id="dataset"></select></label><label>案例 <select id="case"></select></label>
<section class="panel"><h2>实验汇总</h2><div id="summary"></div><p class="muted">正常完成指预定义工具目标的实际效果，不是人工评定的全部回答质量。静态规则为项目内公开参考基线，不代表外部产品。</p></section>
<section class="panel"><h2 id="case-title"></h2><div id="meta"></div><h3>原始用户任务</h3><p id="task"></p><details><summary>查看不可信材料</summary><pre id="resource"></pre></details></section>
<div id="cards" class="grid"></div>
<section class="panel"><h2>AEGIS 调用路径</h2><div id="graph"></div><details><summary>查看完整时序与 token 来源</summary><pre id="trace"></pre></details></section>
<p class="muted">所有实际操作均限定在临时文件、当前回环服务、本地 bare Git 仓库和固定子任务进程。审计 token 不等同服务商计费 token。原始记录和校验清单随源码包提供。</p></main>
<script id="data" type="application/json">__DATA__</script><script>
const data=JSON.parse(document.querySelector('#data').textContent);
const names={unguarded:'无守卫',static_rules:'粗粒度静态参考规则',aegis:'完整 AEGIS'};
const $=s=>document.querySelector(s);const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
for(const name of Object.keys(data)){const o=el('option',name==='replay'?'固定工具轨迹重放':name==='live'?'真实 MiniMax 自主规划':name);o.value=name;$('#dataset').append(o);}
function table(headers,rows){const t=el('table');const h=el('tr');for(const c of headers)h.append(el('th',c));t.append(h);for(const row of rows){const tr=el('tr');for(const c of row)tr.append(el('td',String(c)));t.append(tr);}return t;}
function loadCases(){const rows=data[$('#dataset').value].rows;$('#case').replaceChildren();for(const id of [...new Set(rows.map(r=>r.case_id))]){const row=rows.find(r=>r.case_id===id);const o=el('option',`${row.kind==='attack'?'攻击':'正常'} · ${row.tool} · ${row.variant}`);o.value=id;$('#case').append(o);}render();}
function graph(dag){const host=$('#graph');host.replaceChildren();if(!dag||!dag.nodes.length){host.textContent='该案例没有 AEGIS 调用轨迹';return;}const ns='http://www.w3.org/2000/svg';const s=document.createElementNS(ns,'svg');s.setAttribute('viewBox',`0 0 ${dag.width} ${dag.height}`);const byId=Object.fromEntries(dag.nodes.map(n=>[n.id,n]));for(const edge of dag.edges){const a=byId[edge.src],b=byId[edge.dst];if(!a||!b)continue;const line=document.createElementNS(ns,'line');for(const [k,v]of Object.entries({x1:a.x+168,y1:a.y+18,x2:b.x,y2:b.y+18,stroke:edge.label==='influenced'?'#ac4e3c':'#83978a','stroke-dasharray':edge.label==='influenced'?'5 4':'0'}))line.setAttribute(k,v);s.append(line);}for(const n of dag.nodes){const box=document.createElementNS(ns,'rect');for(const [k,v]of Object.entries({x:n.x,y:n.y,width:168,height:36,rx:4,fill:'#f5f8f4',stroke:n.decision==='block'?'#ac4e3c':'#5b816b'}))box.setAttribute(k,v);const text=document.createElementNS(ns,'text');text.setAttribute('x',n.x+7);text.setAttribute('y',n.y+23);text.setAttribute('font-size','11');text.textContent=n.label.slice(0,25);s.append(box,text);}host.append(s);}
function render(){const ds=data[$('#dataset').value],rows=ds.rows.filter(r=>r.case_id===$('#case').value),first=rows[0];$('#summary').replaceChildren(table(['组别','攻击危险效果／有效案例','正常工具目标完成','正常阻断／询问','环境拒绝／错误'],Object.entries(ds.summary.arms).map(([name,a])=>[names[name],`${a.attacks.side_effect_success}/${a.attacks.valid_cases}`,`${a.benign.goal_completed}/${a.benign.cases}`,`${a.benign.block_cases}/${a.benign.ask_cases}`,`${a.environment_rejections}/${a.error_cases}`])));$('#case-title').textContent=first.case_id;$('#meta').textContent=`${first.kind} · ${first.tool} · ${first.origin}`;$('#task').textContent=first.task;$('#resource').textContent=first.resource||'无外部材料';$('#cards').replaceChildren();for(const row of rows){const panel=el('section',undefined,'panel arm');panel.append(el('h2',names[row.arm]),el('p',`预定义目标：${row.goal_success?'实际达成':'未达成'}`),el('p',`模型危险提议：${row.dangerous_proposed?'有':'无'} · 材料隔离：${row.content_isolated?'是':'否'}`),el('p',`完成：${row.completed} · 环境拒绝：${row.environment_rejections} · 错误：${row.error||'无'}`));for(const step of row.steps){panel.append(el('h3',`${step.tool} · ${step.decision} · ${step.executed?'已产生工具效果':'未执行'}`,step.decision),el('pre',JSON.stringify(step.args,null,2)),el('p',step.verdict?.explanation||step.environment_error||'由实验执行器完成'),el('pre',step.output.slice(0,600)));}panel.append(el('p',row.answer||'固定重放没有模型回答'));$('#cards').append(panel);}const trace=rows.find(r=>r.arm==='aegis')?.trace;graph(trace?.dag);$('#trace').textContent=JSON.stringify(trace||{},null,2);}
$('#dataset').onchange=loadCases;$('#case').onchange=render;loadCases();
</script></html>'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(template.replace("__DATA__", payload), encoding="utf-8")
