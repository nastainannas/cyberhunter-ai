# Generate CYBERHUNTER AI slide deck as .pptx (16:9, dark theme).
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

BG = RGBColor(0x0D, 0x11, 0x17)
PANEL = RGBColor(0x16, 0x1B, 0x22)
ACCENT = RGBColor(0x58, 0xA6, 0xFF)
GREEN = RGBColor(0x3F, 0xB9, 0x50)
TEXT = RGBColor(0xE6, 0xED, 0xF3)
DIM = RGBColor(0x8B, 0x98, 0xAB)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]
SW, SH = prs.slide_width, prs.slide_height


def add_slide():
    s = prs.slides.add_slide(BLANK)
    bg = s.background
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG
    return s


def box(slide, l, t, w, h):
    tb = slide.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    return tf


def para(tf, text, size=20, color=TEXT, bold=False, first=False, space_after=6, bullet=False):
    p = tf.paragraphs[0] if first and not tf.paragraphs[0].runs else tf.add_paragraph()
    p.space_after = Pt(space_after)
    if bullet:
        p.text = "▸  " + text
    else:
        p.text = text
    for r in p.runs:
        r.font.size = Pt(size)
        r.font.color.rgb = color
        r.font.bold = bold
        r.font.name = "Segoe UI"
    return p


def title(slide, text, sub=None):
    tf = box(slide, Inches(0.9), Inches(0.55), Inches(11.5), Inches(1.1))
    para(tf, text, size=40, color=ACCENT, bold=True, first=True, space_after=0)
    if sub:
        tf2 = box(slide, Inches(0.9), Inches(1.55), Inches(11.5), Inches(0.6))
        para(tf2, sub, size=18, color=DIM, first=True)


def brand(slide, n):
    tf = box(slide, Inches(0.9), Inches(0.18), Inches(8), Inches(0.4))
    para(tf, "CYBERHUNTER AI", size=13, color=ACCENT, bold=True, first=True)
    tf2 = box(slide, Inches(12.2), Inches(0.18), Inches(1), Inches(0.4))
    p = tf2.paragraphs[0]
    p.text = str(n)
    p.alignment = PP_ALIGN.RIGHT
    for r in p.runs:
        r.font.size = Pt(12)
        r.font.color.rgb = DIM


def bullets(slide, items, top=1.9, size=20, width=11.5):
    tf = box(slide, Inches(0.9), Inches(top), Inches(width), Inches(5))
    first = True
    for it in items:
        if isinstance(it, tuple):
            txt, col = it
        else:
            txt, col = it, TEXT
        para(tf, txt, size=size, color=col, first=first, bullet=True, space_after=10)
        first = False


def card(slide, l, t, w, h, heading, body, size=14):
    from pptx.enum.shapes import MSO_SHAPE
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    sh.fill.solid()
    sh.fill.fore_color.rgb = PANEL
    sh.line.color.rgb = RGBColor(0x30, 0x36, 0x3D)
    sh.line.width = Pt(1)
    tf = sh.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.18)
    tf.margin_right = Inches(0.18)
    tf.margin_top = Inches(0.12)
    p = tf.paragraphs[0]
    p.text = heading
    for r in p.runs:
        r.font.size = Pt(size + 4)
        r.font.bold = True
        r.font.color.rgb = ACCENT
        r.font.name = "Segoe UI"
    p2 = tf.add_paragraph()
    p2.text = body
    p2.space_before = Pt(6)
    for r in p2.runs:
        r.font.size = Pt(size)
        r.font.color.rgb = TEXT
        r.font.name = "Segoe UI"


# ---------- Slide 1: Cover ----------
s = add_slide()
tf = box(s, Inches(1.2), Inches(2.2), Inches(11), Inches(2.6))
para(tf, "CYBERHUNTER AI", size=60, color=ACCENT, bold=True, first=True)
para(tf, "Platform Automated Security Testing & Bug Bounty", size=26, color=TEXT, space_after=18)
para(tf, "Mendeteksi kerentanan OWASP Top 10 secara aktif & pasif — crawling, injeksi, verifikasi browser", size=18, color=DIM, space_after=40)
para(tf, "oleh Nastain  ·  Ternakheck", size=18, color=DIM)

# ---------- Slide 2: Masalah ----------
s = add_slide(); brand(s, 2); title(s, "Masalah")
bullets(s, [
    "Scanner keamanan umumnya mahal, rumit, atau hanya mendeteksi pasif (headers, banner)",
    "Bug bounty butuh active probing: SQLi, XSS, command injection — sulit dilakukan manual pada website besar",
    "Crawler konvensional melewatkan parameter tersembunyi: POST body, JSON API, hidden fields, endpoint tak ter-link",
    "Situs modern memakai anti-bot JS challenge (WAF splash) yang membuat scanner biasa buta total",
    "Hasil scan mentah sulit dibaca — butuh evidence, payload persis, dan laporan siap-kirim",
])

# ---------- Slide 3: Solusi ----------
s = add_slide(); brand(s, 3); title(s, "Solusi", "Satu platform web untuk security testing terotorisasi")
cards = [
    ("Crawler Cerdas", "Multi-halaman, subdomain, form, JS bundle — plus parameter mining (±75 nama) & filename mutation."),
    ("Active + Passive OWASP Top 10", "SQLi (error/blind/UNION extraction), XSS (reflected/stored/DOM via headless browser), cmdi, LFI, SSRF, XXE, CORS, headers."),
    ("Anti-Bot Solver", "Challenge JavaScript (WAF splash) diselesaikan otomatis via headless Chromium — clearance cookie dibawa ke request berikutnya."),
    ("Report & Evidence", "Payload pemicu, parameter, endpoint, request/response mentah, severity, confidence — laporan HTML bilingual (EN/ID) format XRay."),
]
pos = [(0.9, 1.95), (6.9, 1.95), (0.9, 4.15), (6.9, 4.15)]
for (h, b), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.55), Inches(1.95), h, b)

# ---------- Slide 4: Cakupan Parameter ----------
s = add_slide(); brand(s, 4)
title(s, "Cakupan Parameter", "Jangan ada yang kelewat — semua sumber input masuk antrian probe")
tf = box(s, Inches(0.9), Inches(1.85), Inches(11.5), Inches(5))
rows = [
    ("Query string (semua link crawled)", "✓"),
    ("Form GET/POST — input, select, textarea, hidden non-CSRF", "✓"),
    ("JSON & XML body (API endpoints)", "✓"),
    ("HTTP headers (UA, Referer, X-Forwarded-*)", "✓"),
    ("Cookies", "✓"),
    ("Param tersembunyi di file .js (fetch/axios/route)", "✓ JS mining"),
    ("Param nama umum di endpoint tanpa query", "✓ Parameter mining (±75 nama)"),
    ("Endpoint file tak terduga (cetak/, unduh/, detail.php…)", "✓ Wordlist + subdir + filename mutation"),
]
first = True
for name, status in rows:
    para(tf, f"{name}    →    {status}", size=19, color=GREEN if status.startswith("✓") else TEXT, first=first, space_after=12)
    first = False

# ---------- Slide 5: Deteksi ----------
s = add_slide(); brand(s, 5); title(s, "Deteksi Vulnerability")
cards = [
    ("SQL Injection", "Error-based multi-DBMS, time-based blind dengan konfirmasi ganda anti-FP, UNION extraction hingga 15 kolom + marker database."),
    ("XSS", "Reflected, stored, dan DOM XSS diverifikasi via browser headless — payload harus benar-benar mengeksekusi."),
    ("Command Injection", "Marker aritmatika CYBERHUNTER_$((7*7)) → output CYBERHUNTER_49 — mustahil dari refleksi biasa."),
    ("CVE Surface", "Fingerprint versi PHP/CMS → ruleset CVE (php2shell CVE-2026-109618/619, Drupalgeddon2, Joomla, Laravel, WordPress, phpMyAdmin, ThinkPHP…)."),
]
for (h, b), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.55), Inches(1.95), h, b)

# ---------- Slide 6: Arsitektur ----------
s = add_slide(); brand(s, 6); title(s, "Arsitektur")
tf = box(s, Inches(0.9), Inches(1.8), Inches(11.5), Inches(5.2))
para(tf, "Frontend — React + TypeScript + Vite", size=20, color=ACCENT, bold=True, first=True)
para(tf, "Dashboard · Scan · Findings · AI Config · Laporan HTML bilingual", size=16, color=DIM, space_after=14)
para(tf, "Backend — Node.js + Express", size=20, color=ACCENT, bold=True, space_after=6)
para(tf, "├─ crawler.js   : crawl, extract links/forms/params, anti-bot challenge solver (Puppeteer)", size=16, space_after=4)
para(tf, "├─ scanner.js   : probe engine OWASP Top 10, parameter mining, adaptive timeout", size=16, space_after=4)
para(tf, "├─ cve.js       : fingerprint teknologi + ruleset CVE + php2shell probe", size=16, space_after=4)
para(tf, "├─ domxss.js    : verifikasi DOM XSS via Chromium", size=16, space_after=4)
para(tf, "└─ db.js        : persistence JSON (findings, providers, logs)", size=16, space_after=14)
para(tf, "AI Layer — multi-provider (OpenAI-compatible, Anthropic, Gemini, Ollama, LM Studio, EdgeOne)", size=18, color=GREEN, bold=True, space_after=0)

# ---------- Slide 7: Teknologi ----------
s = add_slide(); brand(s, 7); title(s, "Teknologi")
cards = [
    ("Frontend", "React 18, TypeScript, Vite, React Router — dark-theme dashboard, live scan log streaming, severity chart yang bisa diklik."),
    ("Backend", "Node.js ES modules, Express, fetch manual-redirect, Puppeteer (Chromium) untuk challenge solver & DOM verification."),
    ("Deteksi", "~90 payload SQLi/XSS/cmdi/LFI/SSRF/XXE, 75+ nama parameter mining, 60+ path wordlist + filename mutation, adaptive timeout."),
    ("AI Providers", "6 provider model (cloud & lokal) — konfigurasi per-provider, model selector, playground, usage logs terenkripsi."),
]
for (h, b), (l, t) in zip(cards, pos):
    card(s, Inches(l), Inches(t), Inches(5.55), Inches(1.95), h, b, size=13)

# ---------- Slide 8: Hasil ----------
s = add_slide(); brand(s, 8); title(s, "Hasil & Bukti")
bullets(s, [
    "Scan aplikasi PHP gov (PPID Brebes): 40+ parameter injectable — SQL error \"Illegal mix of collations\" terkonfirmasi manual",
    "Scan situs Joomla ber-WAF (PA Sibolga): anti-bot challenge ter-solve otomatis, crawl menembus splash page",
    "Setiap finding: URL, parameter, lokasi (query/body/header/cookie), payload persis, evidence, request & response mentah",
    "Export laporan HTML bilingual (EN/ID) format XRay — summary + detail Request1/Response1",
    "Findings persisten + dashboard severity chart + filter",
], size=19)

# ---------- Slide 9: Etika ----------
s = add_slide(); brand(s, 9); title(s, "Etika & Keamanan")
bullets(s, [
    "Active probing hanya untuk sistem milik sendiri atau dengan otorisasi tertulis — gating eksplisit di UI",
    "Cookie session di-scope per-origin — tidak pernah bocor ke domain lain",
    "Nilai cookie disensor di log, database, dan laporan export",
    "Payload non-destruktif: marker aritmatika, canary string, error-based — tanpa exploit berbahaya",
    "Deteksi robots.txt 'Disallow: /' → peringatan scope",
    "Rate limiting via request delay yang dapat diatur (0–500ms+)",
], size=20)

# ---------- Slide 10: Roadmap ----------
s = add_slide(); brand(s, 10); title(s, "Roadmap")
bullets(s, [
    "Jangka pendek: Nuclei template integration, authenticated scan wizard, report PDF export",
    "Menengah: distributed scanning queue, authenticated crawling multi-step, GraphQL fuzzing mendalam",
    "Jangka panjang: plugin system check custom, integrasi HackerOne/Bugcrowd scope sync, AI-assisted triage",
], size=19)
tf = box(s, Inches(0.9), Inches(5.4), Inches(11.5), Inches(1.4))
para(tf, "Terima kasih", size=30, color=ACCENT, bold=True, first=True, space_after=4)
para(tf, "github.com/nastainannas/cyberhunter-ai", size=18, color=DIM)

out = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets\cyberhunter-slides.pptx"
prs.save(out)
print("saved →", out, "| slides:", len(prs.slides.__iter__.__self__._sldIdLst))
