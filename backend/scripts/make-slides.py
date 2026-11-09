# Generate CYBERHUNTER AI slide deck as .pptx — modern dark template,
# 16:9, with embedded app screenshots.
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn
import copy

# ---------- palette ----------
BG      = RGBColor(0x0B, 0x0F, 0x14)
PANEL   = RGBColor(0x13, 0x1A, 0x22)
PANEL2  = RGBColor(0x17, 0x20, 0x2B)
LINE    = RGBColor(0x2A, 0x35, 0x44)
ACCENT  = RGBColor(0x58, 0xA6, 0xFF)
ACCENT2 = RGBColor(0x79, 0xC0, 0xFF)
GREEN   = RGBColor(0x3F, 0xB9, 0x50)
AMBER   = RGBColor(0xD2, 0x99, 0x22)
RED     = RGBColor(0xF8, 0x51, 0x49)
TEXT    = RGBColor(0xE6, 0xED, 0xF3)
DIM     = RGBColor(0x8B, 0x98, 0xAB)

ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]

TOTAL = 11


def add_slide():
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = BG
    return s


def rect(slide, l, t, w, h, color, line_color=None):
    sh = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    sh.fill.solid()
    sh.fill.fore_color.rgb = color
    if line_color is None:
        sh.line.fill.background()
    else:
        sh.line.color.rgb = line_color
        sh.line.width = Pt(0.75)
    sh.shadow.inherit = False
    return sh


def rrect(slide, l, t, w, h, fill=PANEL, line=LINE):
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    sh.fill.solid()
    sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = line
    sh.line.width = Pt(1)
    sh.shadow.inherit = False
    try:
        sh.adjustments[0] = 0.06
    except Exception:
        pass
    return sh


def txt(slide, l, t, w, h):
    tb = slide.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    return tf


def run(p, text, size=18, color=TEXT, bold=False, italic=False, font="Segoe UI"):
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.font.bold = bold
    r.font.italic = italic
    r.font.name = font
    return r


def eyebrow(slide, text, n):
    """Small caps label + accent bar + slide number, top of content slides."""
    tf = txt(slide, Inches(0.85), Inches(0.62), Inches(6), Inches(0.35))
    p = tf.paragraphs[0]
    run(p, text.upper(), size=13, color=ACCENT, bold=True)
    # accent underline
    rect(slide, Inches(0.88), Inches(0.72), Inches(0.55), Pt(3), ACCENT)
    # footer
    tf2 = txt(slide, Inches(0.85), Inches(7.05), Inches(8), Inches(0.3))
    p2 = tf2.paragraphs[0]
    run(p2, "CYBERHUNTER AI", size=10, color=DIM, bold=True)
    tf3 = txt(slide, Inches(12.3), Inches(7.05), Inches(0.7), Inches(0.3))
    p3 = tf3.paragraphs[0]
    p3.alignment = PP_ALIGN.RIGHT
    run(p3, f"{n:02d} / {TOTAL:02d}", size=10, color=DIM)
    rect(slide, Inches(0.85), Inches(6.95), Inches(11.63), Pt(0.75), LINE)


def heading(slide, text, top=0.95):
    tf = txt(slide, Inches(0.85), Inches(top), Inches(11.6), Inches(0.9))
    p = tf.paragraphs[0]
    run(p, text, size=34, color=TEXT, bold=True)
    return tf


def bullets(slide, items, top=1.95, left=0.95, width=11.4, size=18, gap=12):
    """items: str or (str, color) or (str, color, bold_prefix)"""
    tf = txt(slide, Inches(left), Inches(top), Inches(width), Inches(6.5))
    first = True
    for it in items:
        if isinstance(it, tuple):
            text, color = it[0], it[1]
        else:
            text, color = it, TEXT
        p = tf.paragraphs[0] if first and not tf.paragraphs[0].runs else tf.add_paragraph()
        p.space_after = Pt(gap)
        # accent marker as separate run
        run(p, "▸  ", size=size, color=GREEN, bold=True)
        run(p, text, size=size, color=color)
        first = False
    return tf


def card(slide, l, t, w, h, heading, body, accent=ACCENT, size=13.5):
    rrect(slide, l, t, w, h, fill=PANEL, line=LINE)
    # left accent strip
    rect(slide, l, t + Inches(0.12), Inches(0.055), h - Inches(0.24), accent)
    tf = txt(slide, Inches(l + Inches(0.28)), Inches(t + Inches(0.16)), Inches(w - Inches(0.45)), Inches(h - Inches(0.25)))
    tf.vertical_anchor = MSO_ANCHOR.TOP
    p = tf.paragraphs[0]
    p.space_after = Pt(5)
    run(p, heading, size=size + 4, color=accent, bold=True)
    p2 = tf.add_paragraph()
    p2.space_before = Pt(2)
    run(p2, body, size=size, color=TEXT)


def pic(slide, path, l, t, w):
    """Place image at width w, height auto."""
    return slide.shapes.add_picture(path, l, t, width=w)


def tag(slide, l, t, text, color=ACCENT):
    """Small pill label."""
    w = Inches(0.28 + 0.115 * len(text))
    rrect(slide, l, t, w, Inches(0.34), fill=PANEL2, line=color)
    tf = txt(slide, l + Inches(0.1), t + Inches(0.015), w, Inches(0.3))
    p = tf.paragraphs[0]
    run(p, text, size=11, color=color, bold=True)


# ================= SLIDE 1 — COVER =================
s = add_slide()
# decorative accent circles
c1 = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(10.6), Inches(-1.6), Inches(4.6), Inches(4.6))
c1.fill.solid(); c1.fill.fore_color.rgb = PANEL2; c1.line.fill.background(); c1.shadow.inherit = False
c2 = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(11.9), Inches(4.4), Inches(2.6), Inches(2.6))
c2.fill.solid(); c2.fill.fore_color.rgb = PANEL; c2.line.fill.background(); c2.shadow.inherit = False
rect(s, Inches(0.85), Inches(1.9), Inches(0.9), Pt(5), ACCENT)
tf = txt(s, Inches(0.85), Inches(2.15), Inches(11), Inches(1.6))
p = tf.paragraphs[0]
run(p, "CYBERHUNTER AI", size=64, color=TEXT, bold=True)
tf2 = txt(s, Inches(0.85), Inches(3.35), Inches(11.5), Inches(1.0))
p2 = tf2.paragraphs[0]
run(p2, "Platform Automated Security Testing & Bug Bounty", size=26, color=ACCENT2)
tf3 = txt(s, Inches(0.85), Inches(4.15), Inches(11.5), Inches(1.2))
p3 = tf3.paragraphs[0]
p3.space_after = Pt(6)
run(p3, "Mendeteksi kerentanan OWASP Top 10 secara aktif & pasif — crawling, injeksi, verifikasi browser", size=17, color=DIM)
tf4 = txt(s, Inches(0.85), Inches(6.3), Inches(11), Inches(0.6))
p4 = tf4.paragraphs[0]
run(p4, "oleh  ", size=16, color=DIM)
run(p4, "Nastain", size=16, color=TEXT, bold=True)
run(p4, "   ·   Ternakheck", size=16, color=DIM)

# ================= SLIDE 2 — MASALAH =================
s = add_slide(); eyebrow(s, "Problem", 2); heading(s, "Masalah")
bullets(s, [
    "Scanner keamanan umumnya mahal, rumit, atau hanya mendeteksi pasif (headers, banner)",
    "Bug bounty butuh active probing: SQLi, XSS, command injection — sulit dilakukan manual pada website besar",
    "Crawler konvensional melewatkan parameter tersembunyi: POST body, JSON API, hidden fields, endpoint tak ter-link",
    "Situs modern memakai anti-bot JS challenge (WAF splash) yang membuat scanner biasa buta total",
    "Hasil scan mentah sulit dibaca — butuh evidence, payload persis, dan laporan siap-kirim",
], size=19)

# ================= SLIDE 3 — SOLUSI =================
s = add_slide(); eyebrow(s, "Solution", 3); heading(s, "Solusi")
cards = [
    ("Crawler Cerdas", "Multi-halaman, subdomain, form, JS bundle — plus parameter mining (±75 nama) & filename mutation untuk endpoint tersembunyi.", ACCENT),
    ("Active + Passive OWASP Top 10", "SQLi (error/blind/UNION extraction), XSS (reflected/stored/DOM via headless browser), cmdi, LFI, SSRF, XXE, CORS, headers.", GREEN),
    ("Anti-Bot Solver", "Challenge JavaScript (WAF splash) diselesaikan otomatis via headless Chromium — clearance cookie dibawa ke request berikutnya.", AMBER),
    ("Report & Evidence", "Payload pemicu, parameter, endpoint, request/response mentah — laporan HTML bilingual (EN/ID) format XRay.", RED),
]
pos = [(0.85, 1.9), (6.85, 1.9), (0.85, 4.15), (6.85, 4.15)]
for (h, b, c), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.6), Inches(2.0), h, b, accent=c)

# ================= SLIDE 4 — CAKUPAN PARAMETER =================
s = add_slide(); eyebrow(s, "Coverage", 4)
heading(s, "Cakupan Parameter", )
tf = txt(s, Inches(0.95), Inches(1.85), Inches(11.4), Inches(5))
rows = [
    ("Query string — semua link crawled", "✓"),
    ("Form GET/POST — input, select, textarea, hidden non-CSRF", "✓"),
    ("JSON & XML body — API endpoints", "✓"),
    ("HTTP headers — UA, Referer, X-Forwarded-*", "✓"),
    ("Cookies", "✓"),
    ("Param tersembunyi di file .js — fetch/axios/route", "✓ JS mining"),
    ("Param nama umum di endpoint tanpa query", "✓ ±75 nama"),
    ("Endpoint tak terduga — cetak/, unduh/, detail.php…", "✓ wordlist + mutation"),
]
first = True
for name, status in rows:
    p = tf.paragraphs[0] if first and not tf.paragraphs[0].runs else tf.add_paragraph()
    p.space_after = Pt(10)
    run(p, "  " + name, size=18, color=TEXT)
    # right-aligned-ish: just append status in green
    run(p, "      " + status, size=16, color=GREEN, bold=True)
    first = False

# ================= SLIDE 5 — DETEKSI =================
s = add_slide(); eyebrow(s, "Detection", 5); heading(s, "Deteksi Vulnerability")
cards = [
    ("SQL Injection", "Error-based multi-DBMS, time-based blind dengan konfirmasi ganda anti-FP, UNION extraction hingga 15 kolom + marker database.", ACCENT),
    ("XSS", "Reflected, stored, dan DOM XSS diverifikasi via browser headless — payload harus benar-benar mengeksekusi.", GREEN),
    ("Command Injection", "Marker aritmatika CYBERHUNTER_$((7*7)) → output CYBERHUNTER_49 — mustahil dari refleksi biasa.", AMBER),
    ("CVE Surface", "Fingerprint versi PHP/CMS → ruleset CVE (php2shell CVE-2026-109618/619, Drupalgeddon2, Joomla, Laravel, WordPress…).", RED),
]
for (h, b, c), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.6), Inches(2.0), h, b, accent=c)

# ================= SLIDE 6 — ARSITEKTUR =================
s = add_slide(); eyebrow(s, "Architecture", 6); heading(s, "Arsitektur")
# three layer blocks
layers = [
    ("FRONTEND", "React + TypeScript + Vite", "Dashboard · Scan · Findings · AI Config · Laporan HTML bilingual", ACCENT),
    ("BACKEND", "Node.js + Express", "crawler · scanner (OWASP Top 10) · cve · domxss · db persistence", GREEN),
    ("AI LAYER", "Multi-Provider", "OpenAI-compatible · Anthropic · Gemini · Ollama · LM Studio · EdgeOne", AMBER),
]
for i, (tag_, sub, body, c) in enumerate(layers):
    t = Inches(1.85 + i * 1.55)
    rrect(s, Inches(0.85), t, Inches(11.6), Inches(1.3), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), t + Inches(0.1), Inches(0.055), Inches(1.1), c)
    tf = txt(s, Inches(1.15), t + Inches(0.12), Inches(11), Inches(1.1))
    p = tf.paragraphs[0]
    run(p, tag_ + "   ", size=14, color=c, bold=True)
    run(p, sub, size=14, color=DIM)
    p2 = tf.add_paragraph()
    p2.space_before = Pt(3)
    run(p2, body, size=15, color=TEXT)

# ================= SLIDE 7 — TEKNOLOGI =================
s = add_slide(); eyebrow(s, "Stack", 7); heading(s, "Teknologi")
cards = [
    ("Frontend", "React 18, TypeScript, Vite, React Router — dark-theme dashboard, live scan log streaming, severity chart interaktif.", ACCENT),
    ("Backend", "Node.js ES modules, Express, fetch manual-redirect, Puppeteer (Chromium) untuk challenge solver & DOM verification.", GREEN),
    ("Deteksi", "±90 payload SQLi/XSS/cmdi/LFI/SSRF/XXE, 75+ parameter mining, 60+ path wordlist + filename mutation, adaptive timeout.", AMBER),
    ("AI Providers", "6 provider model (cloud & lokal) — konfigurasi per-provider, model selector, playground, usage logs terenkripsi.", RED),
]
for (h, b, c), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.6), Inches(2.0), h, b, accent=c, size=12.5)

# ================= SLIDE 8 — TAMPILAN (screenshots) =================
s = add_slide(); eyebrow(s, "Preview", 8)
heading(s, "Tampilan Aplikasi")
# dashboard left, scan right
pic(s, ASSETS + r"\dashboard.png", Inches(0.85), Inches(1.9), Inches(5.7))
pic(s, ASSETS + r"\scan.png", Inches(6.85), Inches(1.9), Inches(5.7))
# small labels under images
tag(s, Inches(0.85), Inches(6.35), "Dashboard", ACCENT)
tag(s, Inches(6.85), Inches(6.35), "Scan Target — live log", GREEN)

# ================= SLIDE 9 — HASIL =================
s = add_slide(); eyebrow(s, "Results", 9)
heading(s, "Hasil & Bukti")
bullets(s, [
    "Scan aplikasi PHP gov (PPID Brebes): 40+ parameter injectable — SQL error \"Illegal mix of collations\" terkonfirmasi manual",
    "Scan situs Joomla ber-WAF (PA Sibolga): anti-bot challenge ter-solve otomatis, crawl menembus splash page",
    "Setiap finding: URL, parameter, lokasi (query/body/header/cookie), payload persis, evidence, request & response mentah",
    "Export laporan HTML bilingual (EN/ID) format XRay — summary + detail Request1/Response1",
    "Findings persisten + dashboard severity chart + filter",
], size=18)
# findings screenshot bottom-right accent
pic(s, ASSETS + r"\findings.png", Inches(8.6), Inches(4.4), Inches(4.0))

# ================= SLIDE 10 — ETIKA =================
s = add_slide(); eyebrow(s, "Ethics", 10); heading(s, "Etika & Keamanan")
bullets(s, [
    "Active probing hanya untuk sistem milik sendiri atau dengan otorisasi tertulis — gating eksplisit di UI",
    "Cookie session di-scope per-origin — tidak pernah bocor ke domain lain",
    "Nilai cookie disensor di log, database, dan laporan export",
    "Payload non-destruktif: marker aritmatika, canary string, error-based — tanpa exploit berbahaya",
    "Deteksi robots.txt 'Disallow: /' → peringatan scope",
    "Rate limiting via request delay yang dapat diatur (0–500ms+)",
], size=19)

# ================= SLIDE 11 — ROADMAP =================
s = add_slide(); eyebrow(s, "Roadmap", 11); heading(s, "Roadmap")
items = [
    ("Jangka Pendek", "Nuclei template integration · authenticated scan wizard · report PDF export", ACCENT),
    ("Menengah", "Distributed scanning queue · authenticated crawling multi-step · GraphQL fuzzing mendalam", GREEN),
    ("Jangka Panjang", "Plugin system check custom · integrasi HackerOne/Bugcrowd scope sync · AI-assisted triage", AMBER),
]
for i, (h, b, c) in enumerate(items):
    t = Inches(1.85 + i * 1.15)
    rrect(s, Inches(0.85), t, Inches(11.6), Inches(0.95), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), t + Inches(0.08), Inches(0.055), Inches(0.79), c)
    tf = txt(s, Inches(1.15), t + Inches(0.1), Inches(11), Inches(0.8))
    p = tf.paragraphs[0]
    run(p, h + "   ", size=15, color=c, bold=True)
    run(p, b, size=15, color=TEXT)
# thanks strip
rrect(s, Inches(0.85), Inches(5.6), Inches(11.6), Inches(1.15), fill=PANEL2, line=ACCENT)
tf = txt(s, Inches(1.3), Inches(5.85), Inches(10.7), Inches(0.8))
p = tf.paragraphs[0]
run(p, "Terima kasih — github.com/nastainannas/cyberhunter-ai", size=22, color=TEXT, bold=True)

out = ASSETS + r"\cyberhunter-slides.pptx"
prs.save(out)
print("saved →", out, "| slides:", len(prs.slides._sldIdLst))
