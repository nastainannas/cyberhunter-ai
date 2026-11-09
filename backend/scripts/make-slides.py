# CYBERHUNTER AI — slide deck v2: modern dark template + framed screenshots.
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# palette
BG      = RGBColor(0x0A, 0x0E, 0x13)
PANEL   = RGBColor(0x12, 0x19, 0x22)
PANEL2  = RGBColor(0x16, 0x1F, 0x2A)
LINE    = RGBColor(0x2A, 0x36, 0x46)
ACCENT  = RGBColor(0x58, 0xA6, 0xFF)
ACCENT2 = RGBColor(0x79, 0xC0, 0xFF)
GREEN   = RGBColor(0x3F, 0xB9, 0x50)
AMBER   = RGBColor(0xD2, 0x99, 0x22)
RED     = RGBColor(0xF8, 0x51, 0x49)
PURPLE  = RGBColor(0xBC, 0x8C, 0xFF)
TEXT    = RGBColor(0xEC, 0xF1, 0xF7)
DIM     = RGBColor(0x8B, 0x98, 0xAB)

ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]
TOTAL = 13


def slide():
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = BG
    return s


def rect(s, l, t, w, h, color):
    sh = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    sh.fill.solid(); sh.fill.fore_color.rgb = color
    sh.line.fill.background(); sh.shadow.inherit = False
    return sh


def rrect(s, l, t, w, h, fill=PANEL, line=LINE):
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    sh.fill.solid(); sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = line; sh.line.width = Pt(1)
    sh.shadow.inherit = False
    try: sh.adjustments[0] = 0.05
    except Exception: pass
    return sh


def tb(s, l, t, w, h):
    b = s.shapes.add_textbox(l, t, w, h)
    b.text_frame.word_wrap = True
    return b.text_frame


def run(p, text, size=18, color=TEXT, bold=False, italic=False):
    r = p.add_run(); r.text = text
    r.font.size = Pt(size); r.font.color.rgb = color
    r.font.bold = bold; r.font.italic = italic; r.font.name = "Segoe UI"
    return r


def chrome(s, n, eyebrow_text):
    """eyebrow + footer on content slides."""
    f = tb(s, Inches(0.85), Inches(0.5), Inches(6), Inches(0.35))
    run(f.paragraphs[0], eyebrow_text.upper(), size=12, color=ACCENT, bold=True)
    rect(s, Inches(0.87), Inches(0.62), Inches(0.6), Pt(3), ACCENT)
    f2 = tb(s, Inches(0.85), Inches(7.08), Inches(9), Inches(0.3))
    run(f2.paragraphs[0], "CYBERHUNTER AI", size=10, color=DIM, bold=True)
    f3 = tb(s, Inches(12.3), Inches(7.08), Inches(0.8), Inches(0.3))
    f3.paragraphs[0].alignment = PP_ALIGN.RIGHT
    run(f3.paragraphs[0], f"{n:02d} / {TOTAL:02d}", size=10, color=DIM)
    rect(s, Inches(0.85), Inches(6.98), Inches(11.63), Pt(0.75), LINE)


def heading(s, text, top=0.85, size=32):
    f = tb(s, Inches(0.85), Inches(top), Inches(11.6), Inches(0.8))
    run(f.paragraphs[0], text, size=size, color=TEXT, bold=True)


def bullets(s, items, top=1.8, size=18, gap=12, left=0.95, width=11.4):
    f = tb(s, Inches(left), Inches(top), Inches(width), Inches(6.2))
    first = True
    for it in items:
        if isinstance(it, tuple): text, color = it
        else: text, color = it, TEXT
        p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
        p.space_after = Pt(gap)
        run(p, "▸  ", size=size, color=GREEN, bold=True)
        run(p, text, size=size, color=color)
        first = False
    return f


def card(s, l, t, w, h, head, body, accent=ACCENT, size=13):
    rrect(s, Inches(l), Inches(t), Inches(w), Inches(h), fill=PANEL, line=LINE)
    rect(s, Inches(l), Inches(t + 0.12), Inches(0.055), Inches(h - 0.24), accent)
    f = tb(s, Inches(l + 0.3), Inches(t + 0.18), Inches(w - 0.5), Inches(h - 0.3))
    f.vertical_anchor = MSO_ANCHOR.TOP
    p = f.paragraphs[0]; p.space_after = Pt(6)
    run(p, head, size=size + 4, color=accent, bold=True)
    p2 = f.add_paragraph()
    run(p2, body, size=size, color=TEXT)
    return f


def framed_pic(s, path, l, t, w, caption=None, cap_color=ACCENT):
    """Image inside a bordered 'device' frame."""
    # measure aspect 1440x900 = 1.6
    h = w / 1.6
    pad = Inches(0.14)
    fl, ft = Inches(l) - pad, Inches(t) - pad
    fw, fh = Inches(w) + pad * 2, Inches(h) + pad * 2 + (Inches(0.42) if caption else Inches(0))
    rrect(s, fl, ft, fw, fh, fill=PANEL2, line=LINE)
    rect(s, fl, ft, fw, Pt(2.5), cap_color)  # top accent strip
    s.shapes.add_picture(path, Inches(l), Inches(t), width=Inches(w))
    if caption:
        f = tb(s, Inches(l), Inches(t + h + Inches(0.12)), Inches(w), Inches(0.35))
        p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        run(p, caption, size=13, color=cap_color, bold=True)


# ================= 1 · COVER =================
s = slide()
rect(s, Inches(0.0), Inches(0.0), prs.slide_width, Inches(0.14), ACCENT)
# glow circles
for (x, y, d, c) in [(10.9, -1.8, 5.2, PANEL2), (12.1, 4.6, 2.8, PANEL), (-1.4, 5.6, 3.4, PANEL2)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    o.fill.solid(); o.fill.fore_color.rgb = c; o.line.fill.background(); o.shadow.inherit = False
rect(s, Inches(0.95), Inches(2.0), Inches(1.0), Pt(5), ACCENT)
f = tb(s, Inches(0.95), Inches(2.3), Inches(11.5), Inches(1.6))
run(f.paragraphs[0], "CYBERHUNTER AI", size=62, color=TEXT, bold=True)
f = tb(s, Inches(0.95), Inches(3.5), Inches(11.5), Inches(0.9))
run(f.paragraphs[0], "Platform Automated Security Testing & Bug Bounty", size=25, color=ACCENT2)
f = tb(s, Inches(0.95), Inches(4.35), Inches(11.5), Inches(1.1))
p = f.paragraphs[0]; p.space_after = Pt(8)
run(p, "Mendeteksi kerentanan OWASP Top 10 secara aktif & pasif — crawling, injeksi, verifikasi browser", size=17, color=DIM)
f = tb(s, Inches(0.95), Inches(6.35), Inches(11), Inches(0.5))
p = f.paragraphs[0]
run(p, "oleh  ", size=15, color=DIM); run(p, "Nastain", size=15, color=TEXT, bold=True); run(p, "   ·   Ternakheck", size=15, color=DIM)

# ================= 2 · MASALAH =================
s = slide(); chrome(s, 2, "Problem")
heading(s, "Masalah")
bullets(s, [
    "Scanner keamanan umumnya mahal, rumit, atau hanya mendeteksi pasif (headers, banner)",
    "Bug bounty butuh active probing: SQLi, XSS, command injection — sulit dilakukan manual pada website besar",
    "Crawler konvensional melewatkan parameter tersembunyi: POST body, JSON API, hidden fields, endpoint tak ter-link",
    "Situs modern memakai anti-bot JS challenge (WAF splash) yang membuat scanner biasa buta total",
    "Hasil scan mentah sulit dibaca — butuh evidence, payload persis, dan laporan siap-kirim",
], size=19)

# ================= 3 · SOLUSI =================
s = slide(); chrome(s, 3, "Solution")
heading(s, "Solusi")
cards = [
    ("Crawler Cerdas", "Multi-halaman, subdomain, form, JS bundle — plus parameter mining (±75 nama) & filename mutation untuk endpoint tersembunyi.", ACCENT),
    ("Active + Passive OWASP Top 10", "SQLi (error/blind/UNION extraction), XSS (reflected/stored/DOM via headless browser), cmdi, LFI, SSRF, XXE, CORS, headers.", GREEN),
    ("Anti-Bot Solver", "Challenge JavaScript (WAF splash) diselesaikan otomatis via headless Chromium — clearance cookie dibawa ke request berikutnya.", AMBER),
    ("Report & Evidence", "Payload pemicu, parameter, endpoint, request/response mentah — laporan HTML bilingual (EN/ID) format XRay.", RED),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.85 + (i // 2) * 2.35
    card(s, l, t, 5.6, 2.05, h, b, accent=c)

# ================= 4 · CAKUPAN =================
s = slide(); chrome(s, 4, "Coverage")
heading(s, "Cakupan Parameter", "Semua sumber input masuk antrian probe — tidak ada yang kelewat")
# two-column checklist cards
cols = [
    ("INPUT LANGSUNG", ["Query string — semua link crawled", "Form GET/POST — input, select, textarea, hidden non-CSRF", "JSON & XML body — API endpoints", "HTTP headers — UA, Referer, X-Forwarded-*", "Cookies"], ACCENT),
    ("DISCOVERY OTOMATIS", ["Param tersembunyi di file .js — fetch/axios/route", "Param nama umum di endpoint tanpa query (±75 nama)", "Endpoint tak terduga — cetak/, unduh/, detail.php…", "Filename mutation — cetakinfo → cetakinfoskpd", "Subdomain enumeration (opsional)"], GREEN),
]
for ci, (h, items, c) in enumerate(cols):
    l = 0.85 + ci * 6.0
    rrect(s, Inches(l), Inches(1.85), Inches(5.6), Inches(4.9), fill=PANEL, line=LINE)
    rect(s, Inches(l), Inches(1.85), Inches(5.6), Inches(0.09), c)
    f = tb(s, Inches(l + 0.3), Inches(2.1), Inches(5.1), Inches(0.5))
    run(f.paragraphs[0], h, size=15, color=c, bold=True)
    f2 = tb(s, Inches(l + 0.3), Inches(2.65), Inches(5.1), Inches(4.0))
    first = True
    for it in items:
        p = f2.paragraphs[0] if first and not f2.paragraphs[0].runs else f2.add_paragraph()
        p.space_after = Pt(10)
        run(p, "✓  ", size=15, color=GREEN, bold=True)
        run(p, it, size=15, color=TEXT)
        first = False

# ================= 5 · DETEKSI =================
s = slide(); chrome(s, 5, "Detection")
heading(s, "Deteksi Vulnerability")
cards = [
    ("SQL Injection", "Error-based multi-DBMS, time-based blind dengan konfirmasi ganda anti-FP, UNION extraction hingga 15 kolom + marker database.", ACCENT),
    ("XSS", "Reflected, stored, dan DOM XSS diverifikasi via browser headless — payload harus benar-benar mengeksekusi.", GREEN),
    ("Command Injection", "Marker aritmatika CYBERHUNTER_$((7*7)) → output CYBERHUNTER_49 — mustahil dari refleksi biasa.", AMBER),
    ("CVE Surface", "Fingerprint versi PHP/CMS → ruleset CVE (php2shell CVE-2026-109618/619, Drupalgeddon2, Joomla, Laravel, WordPress…).", RED),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.85 + (i // 2) * 2.35
    card(s, l, t, 5.6, 2.05, h, b, accent=c)

# ================= 6 · ARSITEKTUR =================
s = slide(); chrome(s, 6, "Architecture")
heading(s, "Arsitektur")
layers = [
    ("FRONTEND", "React + TypeScript + Vite", "Dashboard · Scan · Findings · AI Config · Laporan HTML bilingual", ACCENT),
    ("BACKEND", "Node.js + Express", "crawler.js · scanner.js · cve.js · domxss.js · db.js", GREEN),
    ("AI LAYER", "Multi-Provider", "OpenAI-compatible · Anthropic · Gemini · Ollama · LM Studio · EdgeOne", AMBER),
]
for i, (tag_, sub, body, c) in enumerate(layers):
    t = 1.85 + i * 1.6
    rrect(s, Inches(0.85), Inches(t), Inches(11.6), Inches(1.4), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), Inches(t + 0.1), Inches(0.055), Inches(1.2), c)
    f = tb(s, Inches(1.15), Inches(t + 0.15), Inches(11.0), Inches(1.1))
    p = f.paragraphs[0]
    run(p, tag_ + "   ", size=14, color=c, bold=True)
    run(p, sub, size=14, color=DIM)
    p2 = f.add_paragraph(); p2.space_before = Pt(4)
    run(p2, body, size=15, color=TEXT)
# flow arrows note
f = tb(s, Inches(0.85), Inches(6.7), Inches(11.5), Inches(0.4))
run(f.paragraphs[0], "Frontend → REST API → Scanner Engine → Findings DB → Report Engine → AI Analysis", size=14, color=DIM, italic=True)

# ================= 7 · TEKNOLOGI =================
s = slide(); chrome(s, 7, "Stack")
heading(s, "Teknologi")
cards = [
    ("Frontend", "React 18, TypeScript, Vite, React Router — dark-theme dashboard, live scan log streaming, severity chart interaktif.", ACCENT),
    ("Backend", "Node.js ES modules, Express, fetch manual-redirect, Puppeteer (Chromium) untuk challenge solver & DOM verification.", GREEN),
    ("Deteksi", "±90 payload SQLi/XSS/cmdi/LFI/SSRF/XXE, 75+ parameter mining, 60+ path wordlist + filename mutation, adaptive timeout.", AMBER),
    ("AI Providers", "6 provider model (cloud & lokal) — konfigurasi per-provider, model selector, playground, usage logs terenkripsi.", PURPLE),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.85 + (i // 2) * 2.35
    card(s, l, t, 5.6, 2.05, h, b, accent=c, size=12.5)

# ================= 8 · SCREENSHOT: DASHBOARD =================
s = slide(); chrome(s, 8, "Preview")
heading(s, "Dashboard")
framed_pic(s, ASSETS + r"\dashboard.png", 1.35, 1.7, 10.6, caption="Dashboard — severity chart, statistik scan, navigasi", cap_color=ACCENT)

# ================= 9 · SCREENSHOT: SCAN =================
s = slide(); chrome(s, 9, "Preview")
heading(s, "Scan Target — Live Log")
framed_pic(s, ASSETS + r"\scan.png", 1.35, 1.7, 10.6, caption="Scan console — crawl progress, probe log real-time, temuan masuk live", cap_color=GREEN)

# ================= 10 · SCREENSHOT: FINDINGS + TOOLS =================
s = slide(); chrome(s, 10, "Preview")
heading(s, "Findings & Tools")
framed_pic(s, ASSETS + r"\findings.png", 0.85, 1.7, 5.75, caption="Findings Database — severity, OWASP, evidence", cap_color=RED)
framed_pic(s, ASSETS + r"\ai-config.png", 6.85, 1.7, 5.75, caption="AI Configuration — 6 provider model", cap_color=PURPLE)

# ================= 11 · HASIL =================
s = slide(); chrome(s, 11, "Results")
heading(s, "Hasil & Bukti")
bullets(s, [
    "Scan aplikasi PHP gov (PPID Brebes): 40+ parameter injectable — SQL error \"Illegal mix of collations\" terkonfirmasi manual",
    "Scan situs Joomla ber-WAF (PA Sibolga): anti-bot challenge ter-solve otomatis, crawl menembus splash page",
    "Setiap finding: URL, parameter, lokasi (query/body/header/cookie), payload persis, evidence, request & response mentah",
    "Export laporan HTML bilingual (EN/ID) format XRay — summary + detail Request1/Response1",
    "Findings persisten + dashboard severity chart + filter",
], size=18)

# ================= 12 · ETIKA =================
s = slide(); chrome(s, 12, "Ethics")
heading(s, "Etika & Keamanan")
bullets(s, [
    "Active probing hanya untuk sistem milik sendiri atau dengan otorisasi tertulis — gating eksplisit di UI",
    "Cookie session di-scope per-origin — tidak pernah bocor ke domain lain",
    "Nilai cookie disensor di log, database, dan laporan export",
    "Payload non-destruktif: marker aritmatika, canary string, error-based — tanpa exploit berbahaya",
    "Deteksi robots.txt 'Disallow: /' → peringatan scope",
    "Rate limiting via request delay yang dapat diatur (0–500ms+)",
], size=19)

# ================= 13 · ROADMAP =================
s = slide(); chrome(s, 13, "Roadmap")
heading(s, "Roadmap")
items = [
    ("Jangka Pendek", "Nuclei template integration · authenticated scan wizard · report PDF export", ACCENT),
    ("Menengah", "Distributed scanning queue · authenticated crawling multi-step · GraphQL fuzzing mendalam", GREEN),
    ("Jangka Panjang", "Plugin system check custom · integrasi HackerOne/Bugcrowd scope sync · AI-assisted triage", AMBER),
]
for i, (h, b, c) in enumerate(items):
    t = 1.8 + i * 1.05
    rrect(s, Inches(0.85), Inches(t), Inches(11.6), Inches(0.88), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), Inches(t + 0.08), Inches(0.055), Inches(0.72), c)
    f = tb(s, Inches(1.15), Inches(t + 0.1), Inches(11.0), Inches(0.7))
    p = f.paragraphs[0]
    run(p, h + "   ", size=15, color=c, bold=True)
    run(p, b, size=15, color=TEXT)
# thanks band
rrect(s, Inches(0.85), Inches(5.35), Inches(11.6), Inches(1.35), fill=PANEL2, line=ACCENT)
f = tb(s, Inches(1.3), Inches(5.7), Inches(10.7), Inches(0.8))
p = f.paragraphs[0]
run(p, "Terima kasih", size=30, color=TEXT, bold=True)
p2 = f.add_paragraph(); p2.space_before = Pt(4)
run(p2, "github.com/nastainannas/cyberhunter-ai", size=16, color=ACCENT2)

out = ASSETS + r"\cyberhunter-slides.pptx"
prs.save(out)
print("saved →", out)
print("slides:", len(prs.slides._sldIdLst))
