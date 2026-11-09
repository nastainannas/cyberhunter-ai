# CYBERHUNTER AI — event deck v4: black background, text-left + screenshot-right.
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"
OUT = ASSETS + r"\cyberhunter-ai-platform.pptx"
OUT2 = ASSETS + r"\cyberhunter-ai-platform-v4.pptx"

BG     = RGBColor(0x0A, 0x0E, 0x13)   # plain black
PANEL  = RGBColor(0x13, 0x1A, 0x24)
PANEL2 = RGBColor(0x17, 0x22, 0x2E)
LINE   = RGBColor(0x2A, 0x38, 0x4C)
BLUE   = RGBColor(0x3B, 0x82, 0xF6)
BLUE2  = RGBColor(0x60, 0xA5, 0xFA)
RED    = RGBColor(0xEF, 0x44, 0x44)
GREEN  = RGBColor(0x34, 0xD3, 0x99)
WHITE  = RGBColor(0xF1, 0xF5, 0xF9)
DIM    = RGBColor(0x94, 0xA3, 0xB8)

FH = "Montserrat"
FB = "Segoe UI"

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]
TOTAL = 14


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


def rrect(s, l, t, w, h, fill=PANEL, line=LINE, radius=0.07):
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


def run(p, text, size=16, color=WHITE, bold=False, font=FB):
    r = p.add_run(); r.text = text
    r.font.size = Pt(size); r.font.color.rgb = color
    r.font.bold = bold; r.font.name = font
    return r


def chrome(s, n, kicker, title):
    rect(s, Inches(0.7), Inches(0.4), Inches(0.55), Pt(4), RED)
    f = tb(s, Inches(0.7), Inches(0.52), Inches(10), Inches(0.3))
    run(f.paragraphs[0], kicker.upper(), size=11, color=RED, bold=True, font=FH)
    f2 = tb(s, Inches(0.7), Inches(0.78), Inches(11.9), Inches(0.65))
    run(f2.paragraphs[0], title, size=29, color=WHITE, bold=True, font=FH)
    rect(s, Inches(0.7), Inches(7.02), Inches(11.93), Pt(1), LINE)
    f3 = tb(s, Inches(0.7), Inches(7.1), Inches(8), Inches(0.3))
    run(f3.paragraphs[0], "CYBERHUNTER AI — AI-Powered Automated Vulnerability Assessment Platform", size=9.5, color=DIM)
    f4 = tb(s, Inches(11.7), Inches(7.1), Inches(1.3), Inches(0.3))
    f4.paragraphs[0].alignment = PP_ALIGN.RIGHT
    run(f4.paragraphs[0], f"{n:02d} / {TOTAL:02d}", size=10, color=DIM, bold=True)


def bullets(s, items, top=1.65, left=0.85, width=5.3, size=14.5, gap=9):
    f = tb(s, Inches(left), Inches(top), Inches(width), Inches(5.1))
    first = True
    for it in items:
        if isinstance(it, tuple):
            head, body = it
        else:
            head, body = it, ""
        p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
        p.space_after = Pt(gap)
        run(p, "▪  ", size=size, color=RED, bold=True)
        if body:
            run(p, head + " — ", size=size, color=BLUE2, bold=True)
            run(p, body, size=size, color=WHITE)
        else:
            run(p, head, size=size, color=WHITE)
        first = False
    return f


def card(s, l, t, w, h, head, body, accent=BLUE, hsize=14, bsize=11.5):
    rrect(s, Inches(l), Inches(t), Inches(w), Inches(h), fill=PANEL, line=LINE)
    rect(s, Inches(l + 0.24), Inches(t + 0.2), Inches(0.5), Pt(3.5), accent)
    f = tb(s, Inches(l + 0.24), Inches(t + 0.36), Inches(w - 0.45), Inches(h - 0.5))
    f.vertical_anchor = MSO_ANCHOR.TOP
    p = f.paragraphs[0]; p.space_after = Pt(5)
    run(p, head, size=hsize, color=accent, bold=True, font=FH)
    p2 = f.add_paragraph()
    run(p2, body, size=bsize, color=WHITE)


def shot(s, path, l, t, w, caption=None):
    """screenshot right column, aspect-fit, framed"""
    from PIL import Image
    iw, ih = Image.open(path).size
    aspect = iw / ih
    h = w / aspect
    pad = Inches(0.12)
    bar = Inches(0.32)
    cap_h = Inches(0.38) if caption else Inches(0)
    rrect(s, Inches(l) - pad, Inches(t) - pad - bar, Inches(w) + pad * 2,
          Inches(h) + pad * 2 + bar + cap_h, fill=PANEL2, line=LINE, radius=0.03)
    rect(s, Inches(l) - pad, Inches(t) - pad - bar, Inches(w) + pad * 2, bar, BLUE)
    for i, c in enumerate([RED, RGBColor(0xF0,0xB4,0x29), GREEN]):
        d = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(l) - pad + Inches(0.13 + i * 0.22),
                               Inches(t) - pad - bar + Inches(0.1), Inches(0.11), Inches(0.11))
        d.fill.solid(); d.fill.fore_color.rgb = c; d.line.fill.background(); d.shadow.inherit = False
    s.shapes.add_picture(path, Inches(l), Inches(t), width=Inches(w))
    if caption:
        f = tb(s, Inches(l), Inches(t + Inches(h) + Inches(0.08)), Inches(w), Inches(0.32))
        p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        run(p, caption, size=12, color=BLUE2, bold=True)
    return h


def side_slide(s, n, kicker, title, left_fn, img, caption, img_l=6.35, img_t=1.7, img_w=6.35):
    chrome(s, n, kicker, title)
    left_fn()
    shot(s, ASSETS + "\\" + img, Inches(img_l), Inches(img_t), Inches(img_w), caption)


# ================= 1 · COVER =================
s = slide()
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(7.5), RGBColor(0x0D, 0x16, 0x26))
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(0.14), RED)
rect(s, Inches(0.9), Inches(2.1), Inches(1.0), Pt(6), RED)
f = tb(s, Inches(0.9), Inches(2.45), Inches(11.5), Inches(1.6))
run(f.paragraphs[0], "CYBERHUNTER AI", size=56, color=WHITE, bold=True, font=FH)
f = tb(s, Inches(0.9), Inches(3.6), Inches(11.5), Inches(0.9))
run(f.paragraphs[0], "AI-Powered Automated Vulnerability Assessment Platform", size=23, color=BLUE2, font=FH)
f = tb(s, Inches(0.9), Inches(5.75), Inches(11), Inches(0.6))
p = f.paragraphs[0]
run(p, "Oleh  ", size=15, color=DIM)
run(p, "Nastain", size=15, color=WHITE, bold=True)
for (x, y, d, c) in [(10.7,-1.6,5.2,PANEL),(12.0,5.5,2.6,PANEL),(11.9,1.6,1.6,LINE)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    o.fill.solid(); o.fill.fore_color.rgb = c; o.line.fill.background(); o.shadow.inherit = False

# ================= 2 · LATAR BELAKANG =================
s = slide()
def l2():
    bullets(s, [
        ("Testing manual lambat", "Ratusan input tersembunyi di aplikasi web modern mustahil dicek satu per satu dengan tangan."),
        ("Scanner biasa hanya pasif", "Cek header/banner saja — tidak melakukan active probing yang dibutuhkan assessment nyata."),
        ("Parameter sering terlewat", "POST body, JSON API, hidden fields, cookie, header, dan file .js diabaikan crawler konvensional."),
        ("Anti-bot menghalangi", "WAF modern memakai JavaScript challenge — scanner biasa langsung buta."),
        ("Hasil mentah sulit dipakai", "Tanpa payload, evidence, dan request/response lengkap — tidak bisa langsung ditindaklanjuti."),
    ])
side_slide(s, 2, "Latar Belakang", "Masalah", l2, "dashboard.png",
           "Dashboard — overview hasil assessment")

# ================= 3 · DESKRIPSI =================
s = slide()
def l3():
    f = tb(s, Inches(0.85), Inches(1.6), Inches(5.3), Inches(4.9))
    paras = [
        "CYBERHUNTER AI adalah platform pengujian keamanan siber berbasis AI untuk mengidentifikasi, menganalisis, dan mengevaluasi kerentanan aplikasi web secara otomatis.",
        "Menyediakan automated vulnerability assessment pada sistem yang telah berizin diuji — menganalisis konfigurasi tidak tepat, kelemahan validasi input, security headers, dan potensi kerentanan berbasis standar OWASP.",
        "Hasil ditampilkan di dashboard interaktif: jenis kerentanan, tingkat risiko, bukti pengujian, dan rekomendasi perbaikan — dibantu AI untuk analisis dampak & prioritas mitigasi.",
    ]
    first = True
    for txt in paras:
        p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
        p.space_after = Pt(12)
        run(p, "▪  ", size=14, color=RED, bold=True)
        run(p, txt, size=13.5, color=WHITE)
        first = False
    rrect(s, Inches(0.85), Inches(5.95), Inches(5.3), Inches(0.85), fill=PANEL2, line=LINE)
    f2 = tb(s, Inches(1.15), Inches(6.1), Inches(4.9), Inches(0.6))
    f2.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = f2.paragraphs[0]
    run(p, "Tujuan: ", size=13, color=RED, bold=True)
    run(p, "efektivitas pengujian, deteksi dini, terstruktur & bertanggung jawab.", size=13, color=WHITE)
side_slide(s, 3, "Tentang Karya", "Deskripsi", l3, "scan.png",
           "Scan console — assessment berjalan real-time")

# ================= 4 · TUJUAN =================
s = slide()
def l4():
    cards = [
        ("Efektivitas", "Otomasi assessment — cakupan jauh lebih luas dari testing manual.", BLUE),
        ("Deteksi Dini", "Menemukan celah sebelum dieksploitasi pihak tidak bertanggung jawab.", RED),
        ("Terukur", "Setiap temuan: payload, request/response, severity & rekomendasi.", BLUE2),
        ("Bertanggung Jawab", "Hanya untuk sistem berizin — etika & dampak minimal.", GREEN),
    ]
    for i, (h, b, c) in enumerate(cards):
        l = 0.85 + (i % 2) * 2.72
        t = 1.65 + (i // 2) * 2.5
        card(s, l, t, 2.55, 2.3, h, b, accent=c, hsize=13.5, bsize=11)
side_slide(s, 4, "Tujuan", "Pengembangan", l4, "findings.png",
           "Findings — kerentanan, risiko & rekomendasi")

# ================= 5 · FITUR =================
s = slide()
def l5():
    cards = [
        ("Crawler Cerdas", "Multi-halaman, subdomain, form, JS bundle + parameter mining & filename mutation.", BLUE),
        ("OWASP Top 10", "SQLi, XSS, cmdi, LFI, SSRF, XXE, CORS, headers — aktif & pasif.", RED),
        ("Anti-Bot Solver", "JS challenge (WAF splash) di-solve otomatis via headless Chromium.", BLUE2),
        ("AI Analysis", "6 provider model — triage temuan, dampak & prioritas mitigasi.", GREEN),
    ]
    for i, (h, b, c) in enumerate(cards):
        l = 0.85 + (i % 2) * 2.72
        t = 1.65 + (i // 2) * 2.5
        card(s, l, t, 2.55, 2.3, h, b, accent=c, hsize=13.5, bsize=11)
side_slide(s, 5, "Fitur", "Unggulan Platform", l5, "ai-config.png",
           "AI Configuration — 6 provider model")

# ================= 6 · ALUR KERJA =================
s = slide()
def l6():
    steps = [
        ("01", "Recon", "Crawl halaman, form, JS, subdomain.", BLUE),
        ("02", "Discover", "Ekstrak semua parameter & endpoint tersembunyi.", RED),
        ("03", "Probe", "Payload OWASP aktif ke setiap input.", BLUE),
        ("04", "Verify", "Konfirmasi error, eksekusi JS, CVE fingerprint.", RED),
        ("05", "Report", "Evidence lengkap → dashboard + laporan bilingual.", GREEN),
    ]
    for i, (num, h, b, c) in enumerate(steps):
        t = 1.6 + i * 0.96
        rrect(s, Inches(0.85), Inches(t), Inches(5.3), Inches(0.8), fill=PANEL, line=LINE)
        rect(s, Inches(0.85), Inches(t + 0.07), Inches(0.05), Inches(0.66), c)
        f = tb(s, Inches(1.1), Inches(t + 0.06), Inches(5.0), Inches(0.7))
        f.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = f.paragraphs[0]
        run(p, num + "  ", size=14, color=c, bold=True, font=FH)
        run(p, h + "  ", size=14, color=WHITE, bold=True)
        run(p, b, size=12.5, color=DIM)
side_slide(s, 6, "Cara Kerja", "Alur Assessment", l6, "tools.png",
           "Tools — utilitas pendukung assessment")

# ================= 7 · CAKUPAN =================
s = slide()
def l7():
    bullets(s, [
        ("Input langsung", "Query string, form GET/POST (input, select, textarea, hidden), JSON & XML body, headers (UA, Referer, X-Forwarded-*), cookies."),
        ("Discovery otomatis", "Parameter di file .js (fetch/axios/routes), ±75 nama param umum, endpoint tak ter-link (cetak/, unduh/, detail.php), filename mutation, subdomain enum."),
        ("Hasil", "Tidak ada input yang kelewat — semua masuk antrian probe aktif."),
    ], size=14)
side_slide(s, 7, "Coverage", "Semua Input Diuji", l7, "dashboard.png",
           "Dashboard — ringkasan hasil assessment")

# ================= 8 · DETEKSI =================
s = slide()
def l8():
    cards = [
        ("SQL Injection", "Error-based, blind time-based (konfirmasi ganda), UNION extraction 15 kolom.", BLUE),
        ("XSS", "Reflected, stored & DOM — diverifikasi eksekusi JS via headless browser.", RED),
        ("Command Injection", "Marker aritmatika → output CYBERHUNTER_49, bukan refleksi biasa.", BLUE2),
        ("CVE Surface", "Fingerprint PHP/CMS → ruleset CVE (php2shell, Drupalgeddon2, Joomla, Laravel, WordPress).", GREEN),
    ]
    for i, (h, b, c) in enumerate(cards):
        l = 0.85 + (i % 2) * 2.72
        t = 1.6 + (i // 2) * 2.5
        card(s, l, t, 2.55, 2.3, h, b, accent=c, hsize=13, bsize=10.5)
side_slide(s, 8, "Detection", "Deteksi Kerentanan", l8, "scan.png",
           "Live log — payload & evidence per probe")

# ================= 9 · PHP2SHELL =================
s = slide()
def l9():
    bullets(s, [
        ("Apa itu", "CVE-2026-109618 & 109619 — memory corruption & use-after-free di PHP core. Unauthenticated, ~1 request untuk mod_php."),
        ("Kenapa kritis", "Flaw di runtime PHP — aplikasi aman pun rentan. PHP ≤8.1 (EOL) tidak akan dapat patch."),
        ("Deteksi", "Version fingerprinting (header, PHPSESSID, phpinfo) + behavioral probe multipart."),
        ("Hasil", "Versi rentan → CRITICAL. Indikasi behavioral → HIGH (probable). Fixed: 8.2.35/8.3.36/8.4.27/8.5.12."),
    ], size=14)
side_slide(s, 9, "CVE", "PHP2Shell", l9, "findings.png",
           "Finding PHP2Shell — severity & evidence")

# ================= 10 · PELAPORAN =================
s = slide()
def l10():
    cards = [
        ("Jenis Kerentanan", "SQLi, XSS, cmdi, LFI, SSRF, XXE, CORS, headers, CVE — terklasifikasi.", BLUE),
        ("Tingkat Risiko", "Critical/High/Medium/Low/Info — chart interaktif + filter.", RED),
        ("Bukti", "Payload persis, lokasi parameter, request & response mentah.", BLUE2),
        ("Rekomendasi", "Panduan perbaikan + laporan HTML bilingual (EN/ID) format XRay.", GREEN),
    ]
    for i, (h, b, c) in enumerate(cards):
        l = 0.85 + (i % 2) * 2.72
        t = 1.6 + (i // 2) * 2.5
        card(s, l, t, 2.55, 2.3, h, b, accent=c, hsize=12.5, bsize=10.5)
side_slide(s, 10, "Hasil", "Dashboard & Pelaporan", l10, "findings.png",
           "Findings Database — severity & evidence")

# ================= 11 · ETIKA =================
s = slide()
def l11():
    bullets(s, [
        ("Otorisasi wajib", "Active probing hanya untuk sistem milik sendiri / berizin tertulis — gating eksplisit di UI."),
        ("Cookie aman", "Session cookie di-scope per-origin; nilai disensor di log, DB, dan laporan."),
        ("Payload non-destruktif", "Marker aritmatika, canary, error-based — tanpa exploit merusak."),
        ("Rate limiting", "Request delay dapat diatur — beban ke target tetap wajar."),
        ("Scope awareness", "robots.txt Disallow → peringatan; area terlarang tidak disentuh."),
    ], size=14)
side_slide(s, 11, "Keamanan", "Etika & Authorized Testing", l11, "ai-config.png",
           "AI Configuration — provider & API key terenkripsi")

# ================= 12 · TEKNOLOGI =================
s = slide()
def l12():
    cards = [
        ("Frontend", "React 18 · TypeScript · Vite — dashboard, live log, severity chart.", BLUE),
        ("Backend", "Node.js · Express — crawler, probe engine, Puppeteer.", RED),
        ("Deteksi", "±90 payload OWASP · 75+ param mining · DOM XSS verified.", BLUE2),
        ("AI", "6 provider (cloud & lokal) — key terenkripsi, usage logs.", GREEN),
    ]
    for i, (h, b, c) in enumerate(cards):
        l = 0.85 + (i % 2) * 2.72
        t = 1.6 + (i // 2) * 2.5
        card(s, l, t, 2.55, 2.3, h, b, accent=c, hsize=13, bsize=10.5)
side_slide(s, 12, "Stack", "Teknologi", l12, "scan.png",
           "Scan Target — antarmuka assessment")

# ================= 13 · ROADMAP =================
s = slide()
def l13():
    items = [
        ("Jangka Pendek", "Template Nuclei · wizard authenticated scan · export PDF.", BLUE),
        ("Menengah", "Distributed queue · authenticated crawling · GraphQL fuzzing.", RED),
        ("Jangka Panjang", "Plugin custom · sinkronisasi scope bug bounty · AI triage otomatis.", BLUE2),
    ]
    for i, (h, b, c) in enumerate(items):
        t = 1.7 + i * 1.05
        rrect(s, Inches(0.85), Inches(t), Inches(5.3), Inches(0.9), fill=PANEL, line=LINE)
        rect(s, Inches(0.85), Inches(t + 0.08), Inches(0.05), Inches(0.74), c)
        f = tb(s, Inches(1.1), Inches(t + 0.08), Inches(5.0), Inches(0.78))
        f.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = f.paragraphs[0]
        run(p, h + "\n", size=13.5, color=c, bold=True, font=FH)
        run(p, b, size=11.5, color=WHITE)
side_slide(s, 13, "Pengembangan", "Roadmap", l13, "thumbnail.png",
           "CYBERHUNTER AI")

# ================= 14 · PENUTUP =================
s = slide()
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(7.5), RGBColor(0x0D, 0x16, 0x26))
rect(s, Inches(0), Inches(0), prs.slide_width, Inches(0.14), RED)
for (x, y, d) in [(10.8,-1.6,5.0),(-1.3,5.8,3.2)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    o.fill.solid(); o.fill.fore_color.rgb = PANEL; o.line.fill.background(); o.shadow.inherit = False
f = tb(s, Inches(0.9), Inches(2.2), Inches(11.5), Inches(0.7))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Terima Kasih", size=50, color=WHITE, bold=True, font=FH)
f = tb(s, Inches(0.9), Inches(3.25), Inches(11.5), Inches(1.3))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "CYBERHUNTER AI — AI-Powered Automated Vulnerability Assessment Platform", size=19, color=BLUE2, font=FH)
p2 = f.add_paragraph(); p2.alignment = PP_ALIGN.CENTER; p2.space_before = Pt(10)
run(p2, "Scan lebih dalam, temukan lebih banyak, amankan lebih awal.", size=15, color=DIM)
f = tb(s, Inches(0.9), Inches(5.9), Inches(11.5), Inches(0.6))
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "github.com/nastainannas/cyberhunter-ai", size=15, color=WHITE, bold=True)
p3 = f.add_paragraph(); p3.alignment = PP_ALIGN.CENTER; p3.space_before = Pt(8)
run(p3, "Oleh Nastain", size=13, color=DIM)

try:
    prs.save(OUT)
    print("saved ->", OUT)
except PermissionError:
    prs.save(OUT2)
    print("locked, saved ->", OUT2)
print("slides:", len(prs.slides._sldIdLst))
