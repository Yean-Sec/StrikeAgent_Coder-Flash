#!/usr/bin/env python3
"""Render the README architecture diagram (cream / terracotta)."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1400, 1480
SCALE = 2
OUT = Path(__file__).with_name("architecture.png")

BG = (250, 249, 245, 255)
INK = (20, 20, 19, 255)
MUTED = (108, 106, 100, 255)
SOFT = (142, 139, 130, 255)
HAIR = (230, 223, 216, 255)
CARD = (255, 254, 252, 255)
WASH = (247, 244, 240, 255)
PRIMARY = (204, 120, 92, 255)
PRIMARY_DIM = (204, 120, 92, 36)
DARK = (24, 23, 21, 255)

SERIF_B = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc"
SERIF_R = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc"
LATO = "/usr/share/fonts/truetype/lato/Lato-Regular.ttf"
LATO_B = "/usr/share/fonts/truetype/lato/Lato-Bold.ttf"


def font(path: str, size: int, index: int | None = None) -> ImageFont.FreeTypeFont:
    kw = {"index": index} if index is not None else {}
    try:
        return ImageFont.truetype(path, size * SCALE, **kw)
    except OSError:
        return ImageFont.load_default()


def rr(d: ImageDraw.ImageDraw, xy, r, fill=None, outline=None, width=1):
    d.rounded_rectangle(xy, radius=r * SCALE, fill=fill, outline=outline, width=width * SCALE)


def tx(d, xy, text, fnt, fill=INK, anchor="lt"):
    d.text(xy, text, font=fnt, fill=fill, anchor=anchor)


def arrow_down(d, x, y0, y1):
    d.line([(x, y0), (x, y1 - 10 * SCALE)], fill=PRIMARY, width=2 * SCALE)
    d.polygon(
        [(x, y1), (x - 6 * SCALE, y1 - 10 * SCALE), (x + 6 * SCALE, y1 - 10 * SCALE)],
        fill=PRIMARY,
    )


def arrow_right(d, x0, x1, y):
    d.line([(x0, y), (x1 - 10 * SCALE, y)], fill=PRIMARY, width=2 * SCALE)
    d.polygon(
        [(x1, y), (x1 - 10 * SCALE, y - 6 * SCALE), (x1 - 10 * SCALE, y + 6 * SCALE)],
        fill=PRIMARY,
    )


def chip(d, x, y, w, h, label, fnt, fill=PRIMARY_DIM, ink=INK):
    S = SCALE
    rr(d, (x * S, y * S, (x + w) * S, (y + h) * S), 6, fill, None, 0)
    tx(d, ((x + w / 2) * S, (y + h / 2) * S), label, fnt, ink, "mm")


def main() -> None:
    im = Image.new("RGBA", (W * SCALE, H * SCALE), BG)
    d = ImageDraw.Draw(im)
    f_kicker = font(LATO_B, 11)
    f_title = font(SERIF_B, 28)
    f_sub = font(SERIF_R, 13)
    f_h = font(SERIF_B, 15)
    f_en = font(LATO, 10)
    f_body = font(SERIF_R, 12)
    f_small = font(SERIF_R, 11)
    f_num = font(LATO_B, 10)
    f_chip = font(SERIF_R, 11)

    S = SCALE
    tx(d, (W * S / 2, 36 * S), "STRIKEAGENT-CODER-FLASH", f_kicker, PRIMARY, "mt")
    tx(d, (W * S / 2, 68 * S), "架构", f_title, INK, "mt")
    tx(
        d,
        (W * S / 2, 108 * S),
        "源代码走到可复现 POC · 审计关卡压误报 · 组合链在完整靶机上抬危害",
        f_sub,
        MUTED,
        "mt",
    )
    d.line([(480 * S, 128 * S), (920 * S, 128 * S)], fill=HAIR, width=S)

    # 01 console
    rr(d, (40 * S, 148 * S, 1360 * S, 268 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 164 * S), "01  控制台", f_h, INK)
    tx(d, (200 * S, 168 * S), "Vite  React  :5302", f_en, MUTED)
    consoles = [
        (60, 200, "数据大屏"),
        (272, 200, "审计列表"),
        (484, 220, "项目详情 · 流水线"),
        (716, 180, "漏洞库"),
        (908, 190, "监控模式"),
        (1110, 190, "设置"),
    ]
    for x, w, label in consoles:
        chip(d, x, 200, w, 44, label, f_chip)

    arrow_down(d, 700 * S, 268 * S, 292 * S)

    # 02 api
    rr(d, (40 * S, 292 * S, 1360 * S, 412 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 308 * S), "02  API 与编排", f_h, INK)
    tx(d, (230 * S, 312 * S), "Express  WebSocket  SQLite  :8787", f_en, MUTED)
    apis = [
        (60, 250, "REST  项目 / 漏洞 / 报告 / 设置"),
        (330, 250, "WS  审计与验证事件推到详情页"),
        (600, 250, "任务队列  审计槽与验证槽分计"),
        (870, 220, "继续  从最远已完成环节接着跑"),
        (1110, 190, "孤儿任务标暂停并广播"),
    ]
    for x, w, label in apis:
        rr(d, (x * S, 348 * S, (x + w) * S, 388 * S), 6, WASH, HAIR, 1)
        tx(d, ((x + 12) * S, 368 * S), label, f_small, INK, "lm")

    arrow_down(d, 700 * S, 412 * S, 440 * S)

    # 03 audit | 04 verify
    rr(d, (40 * S, 440 * S, 680 * S, 900 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 456 * S), "03  审计流水线", f_h, INK)
    tx(d, (60 * S, 484 * S), "AUDIT   subagent → dedup → codeverify → regrade", f_en, MUTED)
    audit_steps = [
        ("A1", "多智能体审计", "1 路主控只分配方向；按语言并发 4 路专项 Pi，只产出独立漏洞"),
        ("A2", "AI 智能去重", "按文件装箱合并同根发现；同点多面可保留，供后续逐面验证"),
        ("A3", "代码级验证", "沿源码确认可达性与真伪，假阳性在进靶机前裁掉"),
        ("A4", "红队二次评级", "去重 / 验证 / 评级共用工人池：每路 10 条、最多 10 路，超出排队"),
    ]
    yy = 516
    for num, title, body in audit_steps:
        rr(d, (60 * S, yy * S, 660 * S, (yy + 82) * S), 8, WASH, HAIR, 1)
        tx(d, (80 * S, (yy + 18) * S), num, f_num, PRIMARY)
        tx(d, (118 * S, (yy + 16) * S), title, f_h, INK)
        tx(d, (118 * S, (yy + 48) * S), body, f_small, MUTED)
        yy += 92

    rr(d, (720 * S, 440 * S, 1360 * S, 900 * S), 10, CARD, PRIMARY, 2)
    d.rectangle([(720 * S, 896 * S), (1360 * S, 900 * S)], fill=PRIMARY)
    tx(d, (740 * S, 456 * S), "04  验证流水线", f_h, PRIMARY)
    tx(d, (740 * S, 484 * S), "VERIFY   env → remote → chain", f_en, PRIMARY)
    verify_steps = [
        ("V1", "靶机环境", "Compose 拉起完整 HTTP 整站；可与审计并行预搭建，不走最小运行时"),
        ("V2", "远程单洞", "在靶机上逐条打严重 / 高危 / 中危；Pi docker exec 实测，禁止只读源码判成功"),
        ("V3", "组合验证", "复用已确认单洞，构造无权限 / 低权限 → RCE 链；不做管理员起步"),
    ]
    yy = 516
    for num, title, body in verify_steps:
        rr(d, (740 * S, yy * S, 1340 * S, (yy + 108) * S), 8, WASH, HAIR, 1)
        tx(d, (760 * S, (yy + 22) * S), num, f_num, PRIMARY)
        tx(d, (798 * S, (yy + 20) * S), title, f_h, INK)
        # two-line body
        if "；" in body:
            a, b = body.split("；", 1)
            tx(d, (798 * S, (yy + 52) * S), a + "；", f_small, MUTED)
            tx(d, (798 * S, (yy + 76) * S), b, f_small, MUTED)
        else:
            tx(d, (798 * S, (yy + 56) * S), body, f_small, MUTED)
        yy += 120

    arrow_down(d, 700 * S, 900 * S, 928 * S)

    # 05 agents
    rr(d, (40 * S, 928 * S, 1360 * S, 1148 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 944 * S), "05  多智能体调度", f_h, INK)
    tx(d, (250 * S, 948 * S), "每语言 4 路专项 + 1 路主控；后端真正拉 Pi，不是提示词假装并发", f_small, MUTED)
    langs = ["Java", "Go", "Python", "PHP", "JS/TS", "Rust", "Ruby", "C#", "C", "C++", "Solidity"]
    lang_left, lang_right = 60, 1340
    lang_gap = 14
    lang_w = (lang_right - lang_left - lang_gap * (len(langs) - 1)) / len(langs)
    for i, label in enumerate(langs):
        chip(d, lang_left + i * (lang_w + lang_gap), 980, lang_w, 36, label, f_chip)
    notes = [
        (60, 420, "专项方向", "RCE · 注入 · 文件 · 鉴权为主\nCWE 面合并进 4 路，无收口桶"),
        (500, 400, "落盘契约", "每路写入 JSON/<type>.json\n漏跑由编排核对并补派"),
        (920, 380, "主控调度", "只分配方向、等 JSON 汇总\n自己不挖洞；漏跑则补派"),
    ]
    for x, w, title, body in notes:
        rr(d, (x * S, 1032 * S, (x + w) * S, 1124 * S), 8, WASH, HAIR, 1)
        tx(d, ((x + 16) * S, 1048 * S), title, f_h, INK)
        yy = 1078
        for line in body.split("\n"):
            tx(d, ((x + 16) * S, yy * S), line, f_small, MUTED)
            yy += 22

    arrow_down(d, 700 * S, 1148 * S, 1176 * S)

    # 06 infra
    rr(d, (40 * S, 1176 * S, 1360 * S, 1440 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 1192 * S), "06  执行与落盘", f_h, INK)
    tx(d, (220 * S, 1196 * S), "控制台是 Node；Docker 只给远程验证拉靶机", f_small, MUTED)
    blocks = [
        (
            60,
            300,
            "Pi CLI",
            "本机 pi，默认 deepseek-flash\n--mode json · 无会话\n审计 / 验证 / 组合分通道\n密钥不进仓库",
        ),
        (
            380,
            300,
            "Compose 靶机",
            "完整 HTTP 整站，不走 mini\n按当前工作区源码搭建\nhealthy 后才允许远程实测\n失败不阻断审计侧关卡",
        ),
        (
            700,
            300,
            "工作区  SQLite",
            "backend/workspace/<id>\n发现、去重、评级 JSON\n事件流与状态机\n上传与克隆源码只读",
        ),
        (
            1020,
            280,
            "交付",
            "控制台漏洞与验证 Tab\nHTML 安全审计报告\n等级分布与类别条形图\n组合链结论写回项目",
        ),
    ]
    for x, w, title, body in blocks:
        rr(d, (x * S, 1232 * S, (x + w) * S, 1416 * S), 8, WASH, HAIR, 1)
        tx(d, ((x + 16) * S, 1250 * S), title, f_h, INK)
        yy = 1288
        for line in body.split("\n"):
            tx(d, ((x + 16) * S, yy * S), line, f_small, MUTED)
            yy += 28

    im_rgb = Image.new("RGB", im.size, BG[:3])
    im_rgb.paste(im, mask=im.split()[-1])
    im_rgb.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} {im_rgb.size}")


if __name__ == "__main__":
    main()
