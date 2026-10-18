"""从同一份作品正文构建可编辑 Word；PDF 由该 Word 渲染，避免双稿漂移。"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
FONT = "Songti SC"
BLACK = RGBColor(0, 0, 0)


def diagram(path: Path, evidence: bool = False) -> None:
    """生成代码原生流程图，不复用旧稿中与实验不符的隔离文字。"""
    width, height = (1500, 620) if evidence else (1500, 790)
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    face = "/System/Library/Fonts/STHeiti Medium.ttc"
    font = ImageFont.truetype(face, 30)
    small = ImageFont.truetype(face, 25)
    title = ImageFont.truetype(face, 34)
    ink = "#17231D"
    draw.text((45, 25), "统计分母分别核对" if evidence else "内容判定与实际隔离由不同路径落实", font=title, fill=ink)

    def box(rect, lines, fill="#F3F6F4"):
        draw.rounded_rectangle(rect, 10, fill=fill, outline="#B9C4BD", width=2)
        x0, y0, x1, y1 = rect
        line_h = 43
        for i, line in enumerate(lines):
            draw.text(((x0+x1)/2, (y0+y1)/2+(i-(len(lines)-1)/2)*line_h), line, font=font, fill=ink, anchor="mm")

    def arrow(a, b):
        draw.line((a, b), fill="#496254", width=4)
        x, y = b
        draw.polygon([(x,y),(x-12,y-8),(x-12,y+8)],fill="#496254")

    if evidence:
        cards=[(45,130,485,330),(530,130,970,330),(1015,130,1455,330)]
        for rect,lines in zip(cards,[['10000 个样本','真实模型调用完成'],['5040 条攻击文本','1511 阻断  40 询问'],['20 个工具调用样本','21 次调用  7 次询问']]):box(rect,lines)
        draw.text((60,390), "接口完成率、内容判定率、工具执行结果不能互相替代",font=font,fill=ink)
        draw.text((60,450), "历史万条批次没有无守卫对照或回答级攻击成功标注",font=small,fill="#526159")
        draw.text((60,505), "批次当时原文仍送入模型；当前循环已改为阻断或询问不送原文",font=small,fill="#526159")
    else:
        box((45,140,390,285),['任务与外部材料','内容检查与会话记录'])
        box((540,140,930,285),['当前工具循环','阻断或询问不送原文'])
        box((1080,140,1455,285),['模型提出工具调用','神盾再次判定'])
        arrow((390,212),(540,212));arrow((930,212),(1080,212))
        draw.text((440,170),'记录判定',font=small,fill="#526159",anchor="mm")
        box((45,440,645,595),['SDK 或 MCP 接入路径','宿主消费判定后隔离或转发'])
        box((815,440,1455,595),['实验工具路径','allow 进沙箱   ask 或 block 停止'])
        draw.line([(220,285),(220,440)],fill="#9CA99F",width=3)
        draw.line([(1260,285),(1260,440)],fill="#9CA99F",width=3)
        draw.text((55,650),"检查接口只产生判定；隔离是否落实取决于接入路径",font=font,fill=ink)
        draw.text((55,710),"沙箱不访问真实文件、不联网、不运行命令",font=small,fill="#526159")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path)


def set_font(run, *, size=None, bold=None, mono=False):
    run.font.name = "Courier New" if mono else FONT
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), FONT)
    run.font.color.rgb = BLACK
    if size is not None: run.font.size = Pt(size)
    if bold is not None: run.bold = bold


def data_figures():
    """按冻结数据重画提交版图，避免沿用旧文档中的内嵌图号。"""
    folder=ROOT/'docs/figures'
    face='/System/Library/Fonts/STHeiti Medium.ttc'
    regular=ImageFont.truetype(face,30);small=ImageFont.truetype(face,24);title=ImageFont.truetype(face,36)
    ink='#17231D';red='#B85842';green='#407956';orange='#D59632'
    def base(name,headline,height=540):
        im=Image.new('RGB',(1500,height),'white');d=ImageDraw.Draw(im)
        d.text((50,30),headline,font=title,fill=ink);d.line((50,92,1450,92),fill='#CCD5CE',width=2)
        return im,d,folder/name
    im,d,path=base('submission_data_split.png','本地字符模型使用的合成语料划分',540)
    for index,(name,count,attack,benign) in enumerate([('训练',6960,3600,3360),('验证',1520,720,800),('测试',1520,720,800)]):
        x=50+index*480
        d.text((x+20,130),name,font=regular,fill=ink);d.text((x+20,195),str(count),font=ImageFont.truetype(face,48),fill=ink)
        d.rectangle((x+20,280,x+420,325),fill=green);d.rectangle((x+20,280,x+20+400*attack/count,325),fill=red)
        d.text((x+20,360),f'攻击 {attack}   良性 {benign}',font=small,fill=ink)
    d.text((70,455),'同一 template_id 的全部写法只进入一个划分',font=regular,fill=ink);im.save(path)
    im,d,path=base('submission_family_counts.png','合成文本标签构成',500)
    for y,label,n,color,detail in [(145,'攻击',5040,red,'9类 × 560条'),(290,'良性',4960,green,'8类 × 620条')]:
        d.text((60,y),f'{label} {n}',font=regular,fill=ink);d.text((330,y),detail,font=regular,fill=ink)
        d.rectangle((60,y+55,60+1360*n/10000,y+100),fill=color)
    d.text((60,440),'类别明细见正文表格；总数10000条，四种语言各2500条',font=small,fill=ink);im.save(path)
    card=json.loads((ROOT/'src/aegis/data/injection_model.json').read_text())
    im,d,path=base('submission_character_recall.png','本地字符模型的合成测试集召回率',610)
    for index,(lang,name) in enumerate([('en','英文'),('ja','日文'),('zh','中文'),('ru','俄文')]):
        y=130+index*100;value=card['metrics']['test_by_lang'][lang]['recall']
        d.text((60,y),name,font=regular,fill=ink);d.rectangle((220,y,1200,y+40),fill='#E5EBE6');d.rectangle((220,y,220+980*value,y+40),fill=green)
        d.text((1250,y),f'{value:.4f}',font=regular,fill=ink)
    d.text((60,555),'测试集1520条；阈值0.25；不是MiniMax检测成绩',font=small,fill=ink);im.save(path)
    summary=json.loads((ROOT/'data/corpus/minimax_m3_1_flash_preview_summary.json').read_text())
    im,d,path=base('submission_content_verdicts.png','确定性内容规则三态判定',550)
    for label,y,name,total in [('1',145,'攻击标签',5040),('0',310,'良性标签',4960)]:
        values=summary['content_decisions_by_label'][label]
        d.text((60,y),f'{name} {total}',font=regular,fill=ink);x=60
        for decision,color in [('block',red),('ask',orange),('allow',green)]:
            width=1360*values.get(decision,0)/total
            if width:d.rectangle((x,y+48,x+width,y+90),fill=color)
            x+=width
        d.text((60,y+105),f"阻断 {values.get('block',0)}    询问 {values.get('ask',0)}    放行 {values.get('allow',0)}",font=small,fill=ink)
    d.text((60,490),'本次实验仍向模型送入原文，判定数量不等于上下文隔离次数',font=small,fill=ink);im.save(path)


def text_of(nodes):
    result = []
    for node in nodes:
        kind, content = node["t"], node.get("c")
        if kind == "Str": result.append(content)
        elif kind in {"Space", "SoftBreak", "LineBreak"}: result.append(" ")
        elif kind == "Code": result.append(content[1])
        elif kind in {"Strong", "Emph", "Strikeout", "SmallCaps"}: result.append(text_of(content))
        elif kind == "Link": result.append(text_of(content[1]))
        elif kind == "Quoted": result.append(text_of(content[1]))
    return "".join(result)


def inline(paragraph, nodes, *, size=None, bold=None):
    for node in nodes:
        kind, content = node["t"], node.get("c")
        if kind == "Str": set_font(paragraph.add_run(content),size=size,bold=bold)
        elif kind in {"Space", "SoftBreak"}: set_font(paragraph.add_run(" "),size=size,bold=bold)
        elif kind == "LineBreak": paragraph.add_run().add_break()
        elif kind == "Code": set_font(paragraph.add_run(content[1]),size=(min(size,9) if size else 9),bold=bold,mono=True)
        elif kind in {"Strong", "Emph", "Strikeout", "SmallCaps"}: inline(paragraph,content,size=size,bold=True if kind=="Strong" else bold)
        elif kind in {"Link", "Quoted"}: inline(paragraph,content[1],size=size,bold=bold)


def cell_text(cell):
    return " ".join(text_of(block["c"]) for block in cell[4] if block["t"] in {"Para","Plain"})


def build(source: Path, reference: Path, output: Path, count: int):
    diagram(ROOT/'docs/figures/submission_architecture.png')
    diagram(ROOT/'docs/figures/submission_evidence.png',evidence=True)
    data_figures()
    source_text=source.read_text()
    if '{{PYTEST_COUNT}}' not in source_text and f'{count}项' not in source_text:
        raise ValueError('测试项数与作品正文不一致，请先更新并核对正文')
    markdown = source_text.replace("{{PYTEST_COUNT}}",str(count))
    parsed = subprocess.run(["pandoc","-f","markdown-implicit_figures","-t","json"],input=markdown,text=True,capture_output=True,check=True)
    blocks = json.loads(parsed.stdout)["blocks"]
    doc = Document(reference)
    for child in list(doc._element.body):
        if child.tag != qn("w:sectPr"): doc._element.body.remove(child)
    section=doc.sections[0]
    # Retain the reference A4 page system and its running header/footer.
    section.page_width=Mm(210);section.page_height=Mm(297)
    section.top_margin=Mm(20);section.bottom_margin=Mm(20)
    section.left_margin=Mm(20);section.right_margin=Mm(20)
    section.header_distance=Mm(10);section.footer_distance=Mm(10)
    for name,size in [("Normal",10.5),("Title",23),("Heading 1",17),("Heading 2",12.5),("Heading 3",11),("Caption",9)]:
        if name not in doc.styles:
            doc.styles.add_style(name,WD_STYLE_TYPE.PARAGRAPH)
        style=doc.styles[name];style.font.name=FONT;style.font.size=Pt(size);style.font.color.rgb=BLACK
        style._element.get_or_add_rPr().get_or_add_rFonts().set(qn('w:eastAsia'),FONT)
        fmt=style.paragraph_format;fmt.space_after=Pt(6);fmt.line_spacing=1.28
        if name.startswith('Heading'):
            style.font.bold=True;fmt.space_before=Pt(10);fmt.keep_with_next=True
        if name=='Title':
            style.font.bold=True
            fmt.space_after=Pt(16);fmt.space_before=Pt(10)
            for item in list(style._element):
                if item.tag==qn('w:pPr'):
                    for border in item.findall(qn('w:pBdr')):item.remove(border)
    doc.styles['Normal'].paragraph_format.widow_control=True
    if 'Code Block' not in doc.styles:doc.styles.add_style('Code Block',WD_STYLE_TYPE.PARAGRAPH)
    code=doc.styles['Code Block'];code.font.name='Courier New';code.font.size=Pt(8.5);code.font.color.rgb=BLACK
    code.paragraph_format.line_spacing=1.13;code.paragraph_format.space_after=Pt(5)
    for part in [section.header,section.footer]:
        for paragraph in part.paragraphs:
            for run in paragraph.runs:set_font(run,size=8)
    title_seen=False
    page_break_pending=False
    for block in blocks:
        kind,content=block['t'],block.get('c')
        if kind=='Header':
            level,attrs,nodes=content
            style='Title' if not title_seen else f'Heading {min(level,3)}'
            paragraph=doc.add_paragraph(style=style)
            if page_break_pending:
                paragraph.paragraph_format.page_break_before=True
                page_break_pending=False
            inline(paragraph,nodes)
            title_seen=True
        elif kind in {'Para','Plain'}:
            images=[n for n in content if n['t']=='Image']
            if images:
                for image_node in images:
                    attrs,alt,target=image_node['c'];path=(source.parent/target[0]).resolve()
                    with Image.open(path) as im:w,h=im.size
                    max_w,max_h=170,(85 if path.name=='submission_architecture.png' else 78)
                    scale=min(max_w/w,max_h/h)
                    p=doc.add_paragraph();p.alignment=WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.keep_with_next=True;p.paragraph_format.space_after=Pt(2)
                    picture=p.add_run().add_picture(str(path),width=Mm(w*scale),height=Mm(h*scale))
                    caption=text_of(alt);picture._inline.docPr.set('descr',caption)
                    p=doc.add_paragraph(caption,style='Caption');p.alignment=WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.keep_together=True;p.paragraph_format.space_after=Pt(7)
            else:
                paragraph=doc.add_paragraph();paragraph.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
                inline(paragraph,content)
        elif kind=='RawBlock' and 'pagebreak' in content[1]:
            page_break_pending=True
        elif kind=='CodeBlock':
            paragraph=doc.add_paragraph(style='Code Block');paragraph.paragraph_format.keep_together=True
            set_font(paragraph.add_run(content[1]),size=8.5,mono=True)
        elif kind=='Table':
            _,caption,specs,head,bodies,foot=content
            headers=head[1]
            body_rows=[row for body in bodies for row in body[2]+body[3]]
            all_rows=headers+body_rows+foot[1]
            ncols=len(specs);table=doc.add_table(rows=0,cols=ncols);table.alignment=WD_TABLE_ALIGNMENT.CENTER;table.autofit=False
            proportions=([0.25,0.75] if ncols==2 else [0.27,0.23,0.50] if ncols==3 else [0.25]+[0.75/(ncols-1)]*(ncols-1))
            if ncols==2 and headers and cell_text(headers[0][1][0])=='路径':
                proportions=[0.58,0.42]
            for col,part in zip(table.columns,proportions):col.width=Mm(170*part)
            for index,row in enumerate(all_rows):
                cells=table.add_row().cells
                trpr=table.rows[-1]._tr.get_or_add_trPr();trpr.append(OxmlElement('w:cantSplit'))
                if index<len(headers):trpr.append(OxmlElement('w:tblHeader'))
                for col,(cell,raw_cell,part) in enumerate(zip(cells,row[1],proportions)):
                    cell.width=Mm(170*part);cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
                    p=cell.paragraphs[0];p.paragraph_format.space_after=Pt(0);p.paragraph_format.line_spacing=1.15
                    text=cell_text(raw_cell);p.alignment=WD_ALIGN_PARAGRAPH.LEFT if col==0 or ncols<=3 else WD_ALIGN_PARAGRAPH.CENTER
                    set_font(p.add_run(text),size=9,bold=index<len(headers))
                    tcpr=cell._tc.get_or_add_tcPr()
                    margins=OxmlElement('w:tcMar')
                    for edge in ['top','bottom','left','right']:
                        node=OxmlElement('w:'+edge);node.set(qn('w:w'),'85');node.set(qn('w:type'),'dxa');margins.append(node)
                    tcpr.append(margins)
                    borders=OxmlElement('w:tcBorders')
                    for edge in ['top','bottom','left','right']:
                        node=OxmlElement('w:'+edge);node.set(qn('w:val'),'single');node.set(qn('w:sz'),'4');node.set(qn('w:color'),'D9D9D9');borders.append(node)
                    tcpr.append(borders)
                    if index<len(headers) or index%2==0:
                        shade=OxmlElement('w:shd');shade.set(qn('w:fill'),'E4EBE7' if index<len(headers) else 'F6F7F5');tcpr.append(shade)
            spacer=doc.add_paragraph();spacer.paragraph_format.space_after=Pt(3);spacer.paragraph_format.space_before=Pt(0)
            set_font(spacer.add_run(''),size=1)
        elif kind in {'BulletList','OrderedList'}:
            entries=content if kind=='BulletList' else content[1]
            for entry in entries:
                for item in entry:
                    if item['t'] in {'Para','Plain'}:
                        p=doc.add_paragraph(style='List Bullet');inline(p,item['c'])
        else:
            raise ValueError(f'Unsupported document block: {kind}')
    doc.core_properties.title='神盾 AEGIS 作品文档'
    doc.core_properties.subject='提示注入与工具滥用检测防御 设计 测试 部署与声明'
    doc.core_properties.author='';doc.core_properties.last_modified_by=''
    output.parent.mkdir(parents=True,exist_ok=True);doc.save(output)
    print(json.dumps({'output':str(output),'source':str(source),'pytest_count':count,'tables':len(doc.tables),'figures':len(doc.inline_shapes)},ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'docs/作品提交文档.md')
    parser.add_argument('--reference-docx',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'output/docx/尹纪元+神盾AEGIS+作品文档.docx')
    parser.add_argument('--pytest-count',type=int,required=True)
    args=parser.parse_args();build(args.source,args.reference_docx,args.output,args.pytest_count)
