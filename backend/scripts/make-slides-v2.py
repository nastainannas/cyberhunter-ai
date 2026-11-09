# CYBERHUNTER AI — fresh deck, blue/white/red, Indonesian, modern.
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"
OUT = ASSETS + r"\cyberhunter-slides-new.pptx"

# palette: white / blue / red
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
BG     = RGBColor(0xF6, 0xF9, 0xFD)
PANEL  = RGBColor(0xFF, 0xFF, 0xFF)
PANEL2 = RGBColor(0xEC, 0xF2, 0xFA)
LINE   = RGBColor(0xD5, 0xE0, 0xEC)
BLUE   = RGBColor(0x14, 0x4A, 0x8F)   # primary
BLUE2  = RGBColor(0x1E, 0x6F, 0xD9)   # bright blue
RED    = RGBColor(0xD9, 0x34, 0x2C)   # accent red
INK    = RGBColor(0x16, 0x22, 0x33)
DIM    = RGBColor(0x5B, 0x6B, 0x80)
SOFT   = RGBColor(0xE8, 0xF0, 0xFA)

FH = "Montserrat"     # headings
FB = "Segoe UI"       # body

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]
TOTAL = 15


def slide(white=True):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = WHITE if white else BG
    return s


def rect(s, l, t, w, h, color):
    sh = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    sh.fill.solid(); sh.fill.fore_color.rgb = color
    sh.line.fill.background(); sh.shadow.inherit = False
    return sh


def rrect(s, l, t, w, h, fill=PANEL, line=LINE, radius=0.06):
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    sh.fill.solid(); sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = line; sh.line.width = Pt(1)
    sh.shadow.inherit = False
    try: sh.adjustments[0] = radius
    except Exception: pass
    return sh


def tb(s, l, t, w, h):
    b = s.shapes.add_textbox(l, t, w, h)
    b.text_frame.word_wrap = True
    return b.text_frame


def run(p, text, size=16, color=INK, bold=False, font=FB):
    r = p.add_run(); r.text = text
    r.font.size = Pt(size); r.font.color.rgb = color
    r.font.bold = bold; r.font.name = font
    return r


def chrome(s, n, kicker, title):
    """standard content-slide header: kicker + title + red accent"""
    rect(s, Inches(0.7), Inches(0.42), Inches(0.55), Pt(4), RED)
    f = tb(s, Inches(0.7), Inches(0.55), Inches(10), Inches(0.3))
    run(f.paragraphs[0], kicker.upper(), size=11, color=RED, bold=True, font=FH)
    f2 = tb(s, Inches(0.7), Inches(0.82), Inches(11.9), Inches(0.7))
    run(f2.paragraphs[0], title, size=30, color=INK, bold=True, font=FH)
    # footer
    rect(s, Inches(0.7), Inches(7.02), Inches(11.93), Pt(1), LINE)
    f3 = tb(s, Inches(0.7), Inches(7.1), Inches(8), Inches(0.3))
    run(f3.paragraphs[0], "CYBERHUNTER AI — Automated Security Testing", size=10, color=DIM)
    f4 = tb(s, Inches(11.7), Inches(7.1), Inches(1.3), Inches(0.3))
    f4.paragraphs[0].alignment = PP_ALIGN.RIGHT
    run(f4.paragraphs[0], f"{n:02d} / {TOTAL:02d}", size=10, color=DIM, bold=True)


def bullets(s, items, top=1.7, left=0.85, width=11.6, size=16, gap=10, marker="▪", mcolor=RED):
    f = tb(s, Inches(left), Inches(top), Inches(width), Inches(5.2))
    first = True
    for it in items:
        if isinstance(it, tuple):
            head, body = it
            p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
            p.space_after = Pt(gap)
            run(p, marker + "  ", size=size, color=mcolor, bold=True)
            run(p, head + " — ", size=size, color=BLUE, bold=True)
            run(p, body, size=size, color=INK)
        else:
            p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
            p.space_after = Pt(gap)
            run(p, marker + "  ", size=size, color=mcolor, bold=True)
            run(p, it, size=size, color=INK)
        first = False
    return f


def card(s, l, t, w, h, head, body, accent=BLUE, hsize=15, bsize=12.5):
    rrect(s, Inches(l), Inches(t), Inches(w), Inches(h), fill=PANEL, line=LINE)
    rect(s, Inches(l + 0.28), Inches(t + 0.24), Inches(0.55), Pt(3.5), accent)
    f = tb(s, Inches(l + 0.28), Inches(t + 0.42), Inches(w - 0.55), Inches(h - 0.55))
    f.vertical_anchor = MSO_ANCHOR.TOP
    p = f.paragraphs[0]; p.space_after = Pt(6)
    run(p, head, size=hsize, color=accent, bold=True, font=FH)
    p2 = f.add_paragraph()
    run(p2, body, size=bsize, color=INK)


def shot(s, path, l, t, w, caption=None):
    """screenshot inside a clean white frame with blue top bar + caption"""
    from PIL import Image
    iw, ih = Image.open(path).size
    aspect = iw / ih
    h = w / aspect
    pad = Inches(0.12)
    bar = Inches(0.34)
    cap_h = Inches(0.4) if caption else Inches(0)
    # frame
    rrect(s, Inches(l) - pad, Inches(t) - pad - bar, Inches(w) + pad * 2,
          Inches(h) + pad * 2 + bar + cap_h, fill=PANEL, line=LINE, radius=0.03)
    rect(s, Inches(l) - pad, Inches(t) - pad - bar, Inches(w) + pad * 2, bar, BLUE)
    # window dots
    for i, c in enumerate([RED, RGBColor(0xF0,0xB4,0x29), RGBColor(0x3F,0xB9,0x50)]):
        d = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(l) - pad + Inches(0.14 + i * 0.24),
                               Inches(t) - pad - bar + Inches(0.11), Inches(0.12), Inches(0.12))
        d.fill.solid(); d.fill.fore_color.rgb = c; d.line.fill.background(); d.shadow.inherit = False
    s.shapes.add_picture(path, Inches(l), Inches(t), width=Inches(w))
    if caption:
        f = tb(s, Inches(l), Inches(t + Inches(h) + Inches(0.1)), Inches(w), Inches(0.35))
        p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        run(p, caption, size=12.5, color=BLUE, bold=True)


# ================= 1 · COVER =================
s = slide(white=False)
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(7.5), BLUE)
rect(s, Inches(0), Inches(4.9), prs.slide_width, Inches(2.6), RGBColor(0x10, 0x3A, 0x78))
rect(s, Inches(0.9), Inches(2.15), Inches(1.0), Pt(6), RED)
f = tb(s, Inches(0.9), Inches(2.5), Inches(11.5), Inches(1.6))
run(f.paragraphs[0], "CYBERHUNTER AI", size=54, color=WHITE, bold=True, font=FH)
f = tb(s, Inches(0.9), Inches(3.6), Inches(11.5), Inches(0.8))
run(f.paragraphs[0], "Platform Automated Security Testing & Bug Bounty", size=24, color=RGBColor(0x9D,0xC3,0xFF), font=FH)
f = tb(s, Inches(0.9), Inches(5.7), Inches(11), Inches(0.6))
p = f.paragraphs[0]
run(p, "Oleh  ", size=15, color=RGBColor(0xC9,0xD9,0xEE))
run(p, "Nastain", size=15, color=WHITE, bold=True)
run(p, "    ·    Ternakheck 2025", size=15, color=RGBColor(0xC9,0xD9,0xEE))
# deco circles
for (x, y, d, c) in [(10.6,-1.5,5.0,PANEL2),(11.8,5.4,2.6,PANEL2),(-1.2,5.9,3.2,PANEL2)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    o.fill.solid(); o.fill.fore_color.rgb = c; o.line.fill.background(); o.shadow.inherit = False

# ================= 2 · LATAR BELAKANG =================
s = slide(); chrome(s, 2, "Latar Belakang", "Masalah")
bullets(s, [
    ("Testing manual lambat & tidak skalabel", "Website modern punya ratusan input tersembunyi — mustahil dicek satu per satu dengan tangan."),
    ("Scanner konvensional pasif", "Kebanyakan tools hanya cek header/banner — tidak melakukan active probing yang dibutuhkan bug bounty."),
    ("Parameter mudah terlewat", "Input di POST body, JSON API, hidden fields, cookie, header, dan file JavaScript sering diabaikan crawler biasa."),
    ("Anti-bot menghalangi scan", "WAF modern memakai JavaScript challenge — scanner biasa langsung buta di splash page."),
    ("Hasil mentah sulit dipakai", "Temuan tanpa payload persis, evidence, dan request/response lengkap tidak bisa langsung disubmit."),
], size=16)

# ================= 3 · SOLUSI =================
s = slide(); chrome(s, 3, "Solusi", "CYBERHUNTER AI")
f = tb(s, Inches(0.85), Inches(1.55), Inches(11.6), Inches(0.9))
p = f.paragraphs[0]
run(p, "Platform security testing otomatis untuk web application — dari reconnaissance sampai laporan bug bounty yang siap submit.", size=17, color=DIM)
cards = [
    ("Cerdas", "Crawler multi-halaman + parameter mining menemukan SEMUA input — query, form, JSON, XML, header, cookie, dan yang tersembunyi di file .js.", BLUE),
    ("Mendalam", "Active OWASP Top 10 probes + CVE fingerprinting — SQLi, XSS, cmdi, LFI, SSRF, XXE, CORS, security headers.", RED),
    ("Terverifikasi", "Setiap temuan punya payload persis, lokasi parameter, request/response mentah, dan evidence konfirmasi.", BLUE2),
    ("Siap Lapangan", "Anti-bot solver menembus WAF challenge, authenticated scanning, dan laporan HTML bilingual (EN/ID) format XRay.", RGBColor(0x2E,0x8B,0x6E)),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.95 + (i // 2) * 2.35
    card(s, l, t, 5.6, 2.1, h, b, accent=c)

# ================= 4 · ALUR KERJA =================
s = slide(); chrome(s, 4, "Cara Kerja", "Alur Scan")
steps = [
    ("01", "Recon", "Crawl halaman, form, JS bundle, subdomain — bangun peta attack surface.", BLUE),
    ("02", "Discover", "Ekstrak semua parameter: query, body, header, cookie + param mining & filename mutation.", RED),
    ("03", "Probe", "Kirim payload OWASP aktif ke setiap input — SQLi, XSS, cmdi, LFI, SSRF, XXE.", BLUE),
    ("04", "Verify", "Konfirmasi temuan: error SQL, eksekusi JS di browser, delay time-based, CVE fingerprint.", RED),
    ("05", "Report", "Simpan evidence lengkap → dashboard, findings DB, laporan HTML bilingual.", BLUE),
]
for i, (num, h, b, c) in enumerate(steps):
    t = 1.7 + i * 0.98
    rrect(s, Inches(0.85), Inches(t), Inches(11.6), Inches(0.82), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), Inches(t + 0.08), Inches(0.06), Inches(0.66), c)
    f = tb(s, Inches(1.15), Inches(t + 0.08), Inches(11.0), Inches(0.68))
    f.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = f.paragraphs[0]
    run(p, num + "   ", size=15, color=c, bold=True, font=FH)
    run(p, h + "   ", size=15, color=INK, bold=True)
    run(p, b, size=13.5, color=DIM)

# ================= 5 · CAKUPAN PARAMETER =================
s = slide(); chrome(s, 5, "Coverage", "Semua Input Diprobe")
cols = [
    ("INPUT LANGSUNG", ["Query string — semua link hasil crawl", "Form GET/POST: input, select, textarea, hidden non-CSRF", "JSON & XML body pada API endpoint", "HTTP headers: UA, Referer, X-Forwarded-*", "Cookies"], BLUE),
    ("DISCOVERY OTOMATIS", ["Parameter di file .js — fetch/axios/route tables", "±75 nama param umum pada endpoint kosong", "Endpoint tak ter-link: cetak/, unduh/, detail.php…", "Filename mutation: cetakinfo → cetakinfoskpd", "Subdomain enumeration (opsional)"], RED),
]
for ci, (h, items, c) in enumerate(cols):
    l = 0.85 + ci * 6.0
    rrect(s, Inches(l), Inches(1.7), Inches(5.6), Inches(4.9), fill=PANEL, line=LINE)
    rect(s, Inches(l), Inches(1.7), Inches(5.6), Inches(0.09), c)
    f = tb(s, Inches(l + 0.3), Inches(1.95), Inches(5.1), Inches(0.5))
    run(f.paragraphs[0], h, size=14, color=c, bold=True, font=FH)
    f2 = tb(s, Inches(l + 0.3), Inches(2.5), Inches(5.1), Inches(4.0))
    first = True
    for it in items:
        p = f2.paragraphs[0] if first and not f2.paragraphs[0].runs else f2.add_paragraph()
        p.space_after = Pt(12)
        run(p, "✓  ", size=14, color=c, bold=True)
        run(p, it, size=14, color=INK)
        first = False

# ================= 6 · DETEKSI =================
s = slide(); chrome(s, 6, "Detection", "Deteksi Vulnerability")
cards = [
    ("SQL Injection", "Error-based multi-DBMS, time-based blind dengan konfirmasi ganda (anti false-positive), UNION extraction hingga 15 kolom + marker database.", BLUE),
    ("XSS", "Reflected, stored, dan DOM XSS — diverifikasi via headless browser; payload harus benar-benar mengeksekusi JavaScript.", RED),
    ("Command Injection", "Marker aritmatika CYBERHUNTER_$((7*7)) → output CYBERHUNTER_49. Refleksi biasa tidak dianggap eksekusi.", RGBColor(0x1E,0x6F,0xD9)),
    ("CVE Surface", "Fingerprint versi PHP/CMS → ruleset CVE: php2shell CVE-2026-109618/619, Drupalgeddon2, Joomla, Laravel, WordPress, phpMyAdmin.", RGBColor(0x2E,0x8B,0x6E)),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.75 + (i // 2) * 2.4
    card(s, l, t, 5.6, 2.15, h, b, accent=c, hsize=16, bsize=12.5)

# ================= 7 · PHP2SHELL =================
s = slide(); chrome(s, 7, "CVE", "PHP2Shell — CVE-2026-109618 & 109619")
bullets(s, [
    ("Apa itu", "Sepasang vulnerability kritis di PHP core — memory corruption & use-after-free setelah kondisi out-of-memory. Unauthenticated, ~1 request untuk mod_php."),
    ("Kenapa berbahaya", "Flaw ada di runtime PHP — kode aplikasi yang aman pun tetap rentan. PHP ≤8.1 (EOL) tidak akan pernah dapat patch."),
    ("Cara deteksi", "Version fingerprinting (X-Powered-By, Server, PHPSESSID, phpinfo) + behavioral probe multipart untuk target yang menyembunyikan versi."),
    ("Status patch", "Fixed di PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — versi di bawahnya = vulnerable (severity critical)."),
    ("Hasil", "Versi rentan terbukti → finding CRITICAL. Indikasi behavioral tanpa versi → HIGH (probable, perlu verifikasi manual)."),
], size=15.5)
rrect(s, Inches(0.85), Inches(6.15), Inches(11.6), Inches(0.7), fill=PANEL2, line=LINE)
f = tb(s, Inches(1.15), Inches(6.28), Inches(11.0), Inches(0.5))
f.vertical_anchor = MSO_ANCHOR.MIDDLE
p = f.paragraphs[0]
run(p, "⚠  ", size=14, color=RED, bold=True)
run(p, "Probe behavioral bersifat non-destruktif ringan — hanya aktif di mode Active scan dan pada target yang diotorisasi.", size=12.5, color=INK)

# ================= 8 · SCREENSHOT: DASHBOARD =================
s = slide(); chrome(s, 8, "Demo", "Dashboard")
shot(s, ASSETS + r"\dashboard.png", 2.0, 1.7, 9.3,
     caption="Dashboard — severity chart interaktif, statistik scan & navigasi fitur")

# ================= 9 · SCREENSHOT: SCAN =================
s = slide(); chrome(s, 9, "Demo", "Scan Target — Live Log")
shot(s, ASSETS + r"\scan.png", 2.0, 1.7, 9.3,
     caption="Scan console — crawl progress, probe log real-time, temuan masuk live")
bullets(s, [
    "Mode Passive (recon saja) dan Active (full probing) dengan request delay yang dapat diatur",
    "Scan tetap berjalan saat pindah halaman — state dipulihkan saat kembali",
    "Stop / resume / antrian scan didukung",
], top=6.35, size=13, gap=6)

# ================= 10 · SCREENSHOT: FINDINGS + AI =================
s = slide(); chrome(s, 10, "Demo", "Findings & AI Configuration")
shot(s, ASSETS + r"\findings.png", 0.85, 1.65, 5.75,
     caption="Findings Database — severity, OWASP, evidence")
shot(s, ASSETS + r"\ai-config.png", 6.85, 1.65, 5.75,
     caption="AI Configuration — 6 provider model")

# ================= 11 · HASIL =================
s = slide(); chrome(s, 11, "Hasil", "Bukti di Lapangan")
cards = [
    ("Web PPID Brebes (PHP gov)", "40+ parameter injectable terdeteksi; error \"Illegal mix of collations\" terkonfirmasi — endpoint tak ter-link ditemukan via subdir probing + filename mutation.", RED),
    ("PA Sibolga (Joomla + WAF)", "Anti-bot JavaScript challenge ter-solve otomatis; crawl menembus splash page dengan clearance cookie.", BLUE),
    ("Setiap finding", "URL, parameter, lokasi (query/body/header/cookie), payload persis, evidence, request & response mentah.", BLUE2),
    ("Laporan", "Export HTML bilingual (EN/ID) format XRay — summary + detail Request1/Response1 + rekomendasi remediation.", RGBColor(0x2E,0x8B,0x6E)),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.75 + (i // 2) * 2.4
    card(s, l, t, 5.6, 2.15, h, b, accent=c, hsize=14.5, bsize=12)

# ================= 12 · ETIKA =================
s = slide(); chrome(s, 12, "Keamanan", "Etika & Authorized Testing")
bullets(s, [
    ("Otorisasi wajib", "Active probing hanya untuk sistem milik sendiri atau dengan izin tertulis — gating eksplisit di UI sebelum scan dimulai."),
    ("Cookie aman", "Session cookie di-scope per-origin — tidak pernah bocor ke domain lain; nilai cookie disensor di log, database, dan laporan."),
    ("Payload non-destruktif", "Marker aritmatika, canary string, error-based detection — tanpa exploit yang merusak data."),
    ("Rate limiting", "Request delay yang dapat diatur (0–500ms+) menjaga beban ke target tetap wajar."),
    ("Scope awareness", "robots.txt 'Disallow: /' memicu peringatan — scanner sadar area yang sebaiknya tidak disentuh."),
], size=15.5)

# ================= 13 · TEKNOLOGI =================
s = slide(); chrome(s, 13, "Stack", "Teknologi")
cards = [
    ("Frontend", "React 18 · TypeScript · Vite — dashboard dark-theme, live scan log streaming, severity chart interaktif.", BLUE),
    ("Backend", "Node.js ES modules · Express — crawler, probe engine, adaptive timeout, Puppeteer (Chromium).", RED),
    ("Deteksi", "±90 payload OWASP · 75+ parameter mining · 60+ path wordlist · browser-verified DOM XSS.", RGBColor(0x1E,0x6F,0xD9)),
    ("AI Providers", "6 provider model (cloud & lokal): OpenAI-compatible, Anthropic, Gemini, Ollama, LM Studio, EdgeOne — API key terenkripsi.", RGBColor(0x2E,0x8B,0x6E)),
]
for i, (h, b, c) in enumerate(cards):
    l = 0.85 + (i % 2) * 6.0
    t = 1.75 + (i // 2) * 2.4
    card(s, l, t, 5.6, 2.15, h, b, accent=c, hsize=15, bsize=12)
f = tb(s, Inches(0.85), Inches(6.35), Inches(11.6), Inches(0.5))
p = f.paragraphs[0]
run(p, "Frontend → REST API → Scanner Engine → Findings DB → Report Engine → AI Analysis", size=13, color=DIM, bold=True)

# ================= 14 · ROADMAP =================
s = slide(); chrome(s, 14, "Pengembangan", "Roadmap")
items = [
    ("Jangka Pendek", "Integrasi template Nuclei · wizard authenticated scan · export laporan PDF.", BLUE),
    ("Menengah", "Distributed scan queue · authenticated crawling multi-step · GraphQL fuzzing mendalam.", RED),
    ("Jangka Panjang", "Plugin check custom · sinkronisasi scope HackerOne/Bugcrowd · AI-assisted triage otomatis.", RGBColor(0x1E,0x6F,0xD9)),
]
for i, (h, b, c) in enumerate(items):
    t = 1.7 + i * 1.0
    rrect(s, Inches(0.85), Inches(t), Inches(11.6), Inches(0.85), fill=PANEL, line=LINE)
    rect(s, Inches(0.85), Inches(t + 0.08), Inches(0.06), Inches(0.69), c)
    f = tb(s, Inches(1.15), Inches(t + 0.08), Inches(11.0), Inches(0.7))
    f.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = f.paragraphs[0]
    run(p, h + "   ", size=15, color=c, bold=True, font=FH)
    run(p, b, size=13.5, color=INK)

# ================= 15 · PENUTUP =================
s = slide(white=False)
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(7.5), BLUE)
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(0.16), RED)
for (x, y, d) in [(10.8,-1.6,5.0),(-1.3,5.8,3.2)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    o.fill.solid(); o.fill.fore_color.rgb = PANEL2; o.line.fill.background(); o.shadow.inherit = False
f = tb(s, Inches(0.9), Inches(2.3), Inches(11.5), Inches(0.7))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Terima Kasih", size=48, color=WHITE, bold=True, font=FH)
f = tb(s, Inches(0.9), Inches(3.3), Inches(11.5), Inches(0.6))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "CYBERHUNTER AI — scan lebih dalam, temukan lebih banyak.", size=20, color=RGBColor(0x9D,0xC3,0xFF), font=FH)
f = tb(s, Inches(0.9), Inches(5.7), Inches(11.5), Inches(0.6))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "github.com/nastainannas/cyberhunter-ai", size=16, color=WHITE, bold=True)
p2 = f.add_paragraph(); p2.alignment = PP_ALIGN.CENTER; p2.space_before = Pt(8)
run(p2, "Oleh Nastain · Ternakheck 2025", size=14, color=RGBColor(0xC9,0xD9,0xEE))

prs.save(OUT)
print("saved ->", OUT, "| slides:", len(prs.slides._sldIdLst))
