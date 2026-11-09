# CYBERHUNTER AI — editable PPTX mirroring slides-v4.html exactly.
# All text/shapes native (editable). 1280x720 HTML px -> 13.333x7.5in (9525 EMU/px)
from pptx import Presentation
from pptx.util import Emu, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from PIL import Image

ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"
OUT = ASSETS + r"\cyberhunter-ai-platform-v4.pptx"
OUT2 = ASSETS + r"\cyberhunter-ai-platform-v7.pptx"

E = lambda px: Emu(int(px * 9525))          # html px -> EMU

def C(h): return RGBColor(int(h[1:3],16), int(h[3:5],16), int(h[5:7],16))

BG      = C("#0A0E13"); BG2 = C("#0D1626"); PANEL = C("#131A24")
PANEL2  = C("#17222E"); PANEL3 = C("#0D141D"); LINE = C("#2A384C")
BLUE    = C("#3B82F6"); BLUE2 = C("#60A5FA"); RED = C("#EF4444")
GREEN   = C("#34D399"); AMBER = C("#F0B41D"); WHITE = C("#FFFFFF")
INKW    = C("#F1F5F9"); DIM = C("#94A3B8"); DIM2 = C("#64748B")

FH, FB = "Montserrat", "Segoe UI"
MONO  = "Consolas"

prs = Presentation()
prs.slide_width, prs.slide_height = Emu(12192000), Emu(6858000)
BLANK = prs.slide_layouts[6]
TOTAL = 17


def slide(bg=BG):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid(); s.background.fill.fore_color.rgb = bg
    return s


def rect(s, x, y, w, h, color):
    sh = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, E(x), E(y), E(w), E(h))
    sh.fill.solid(); sh.fill.fore_color.rgb = color
    sh.line.fill.background(); sh.shadow.inherit = False
    return sh


def rrect(s, x, y, w, h, fill, line=LINE, radius=0.08):
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, E(x), E(y), E(w), E(h))
    sh.fill.solid(); sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = line; sh.line.width = Pt(1)
    sh.shadow.inherit = False
    try: sh.adjustments[0] = radius
    except Exception: pass
    return sh


def tb(s, x, y, w, h):
    b = s.shapes.add_textbox(E(x), E(y), E(w), E(h))
    b.text_frame.word_wrap = True
    return b.text_frame


def run(p, text, px=16, color=WHITE, bold=False, font=FB, spacing=None):
    r = p.add_run(); r.text = text
    r.font.size = Pt(px * 0.75)
    r.font.color.rgb = color; r.font.bold = bold; r.font.name = font
    if spacing:
        rPr = r._r.get_or_add_rPr()
        rPr.set('spc', str(int(spacing * 100)))
    return r


def chrome(s, n, kicker, title):
    rect(s, 64, 25, 44, 4, RED)
    f = tb(s, 64, 34, 900, 22)
    run(f.paragraphs[0], kicker.upper(), px=15, color=RED, bold=True, font=FH, spacing=200)
    f2 = tb(s, 64, 56, 1150, 46)
    run(f2.paragraphs[0], title, px=38, color=WHITE, bold=True, font=FH)
    rect(s, 64, 705, 1152, 1, LINE)
    f3 = tb(s, 64, 681, 700, 20)
    run(f3.paragraphs[0], "CYBERHUNTER AI — AI-Powered Automated Vulnerability Assessment Platform", px=12, color=DIM)
    f4 = tb(s, 1050, 681, 166, 20)
    f4.paragraphs[0].alignment = PP_ALIGN.RIGHT
    run(f4.paragraphs[0], f"{n:02d} / {TOTAL:02d}", px=12, color=DIM, bold=True)


# ---------- left-column builders ----------
def li_bullets(s, items, x=64, y=150, w=560, px=19, gap_px=20):
    """items: list of (head_or_None, body) -> '▪ head — body' or '▪ text'"""
    f = tb(s, x, y, w, 500)
    first = True
    for head, body in items:
        p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
        p.space_after = Pt(gap_px * 0.75)
        run(p, "▪  ", px=px, color=RED, bold=True)
        if head:
            run(p, head, px=px, color=BLUE2, bold=True)
            run(p, " — ", px=px, color=WHITE)
        run(p, body, px=px, color=WHITE)
        first = False


def cards(s, items, x=64, y=150, w=560, cw=None, ch=235, gap=18):
    """items: (head, body, color). 2-col grid."""
    cw = cw or (w - gap) / 2
    for i, (h, b, c) in enumerate(items):
        cx = x + (i % 2) * (cw + gap)
        cy = y + (i // 2) * (ch + gap)
        rrect(s, cx, cy, cw, ch, PANEL, LINE, 0.05)
        rect(s, cx + 20, cy + 20, 44, 4, c)
        f = tb(s, cx + 20, cy + 32, cw - 40, ch - 52)
        f.vertical_anchor = MSO_ANCHOR.TOP
        p = f.paragraphs[0]; p.space_after = Pt(8)
        run(p, h, px=19, color=BLUE2, bold=True, font=FH)
        p2 = f.add_paragraph()
        run(p2, b, px=15, color=WHITE)


def steps(s, items, x=64, y=150, w=560):
    """items: (num,color,name,desc)"""
    t = y
    for num, c, nm, ds in items:
        rrect(s, x, t, w, 68, PANEL, LINE, 0.06)
        rect(s, x, t + 8, 4, 52, c)
        f = tb(s, x + 26, t + 8, w - 40, 52)
        f.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = f.paragraphs[0]
        run(p, num + "  ", px=20, color=c, bold=True, font=FH)
        run(p, nm + "  ", px=17, color=WHITE, bold=True)
        run(p, ds, px=14, color=DIM)
        t += 68 + 14


# ---------- right column ----------
def shotwrap(s, img, x=680, y=150, w=536, caption=None, term_lines=None):
    inner_w = w - 28
    if term_lines:
        img_h = 190
    else:
        iw, ih = Image.open(ASSETS + "\\" + img).size
        img_h = inner_w / (iw / ih)
    bar_h = 12
    cap_h = 30 if caption else 0
    total_h = 14 + bar_h + 10 + img_h + 8 + cap_h + 8
    bg = PANEL3 if term_lines else PANEL2
    rrect(s, x, y, w, total_h, bg, LINE, 0.05)
    # dots
    for i, c in enumerate([RED, AMBER, GREEN]):
        d = s.shapes.add_shape(MSO_SHAPE.OVAL, E(x + 14 + i * 16), E(y + 14 + 1), E(10), E(10))
        d.fill.solid(); d.fill.fore_color.rgb = c; d.line.fill.background(); d.shadow.inherit = False
    if term_lines:
        f = tb(s, x + 14, y + 14 + bar_h + 10, inner_w, img_h + 20)
        first = True
        for txt, col in term_lines:
            p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
            p.space_after = Pt(10)
            run(p, "$ ", px=15, color=GREEN, bold=True, font=MONO)
            run(p, txt, px=15, color=WHITE, font=MONO)
            first = False
    else:
        s.shapes.add_picture(ASSETS + "\\" + img, E(x + 14), E(y + 14 + bar_h + 10),
                             width=E(inner_w), height=E(img_h))
    if caption:
        f = tb(s, x + 14, y + 14 + bar_h + 10 + img_h + 8, inner_w, 24)
        p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        run(p, caption, px=14, color=BLUE2, bold=True)


def content_slide(n, kicker, title, left_fn, img=None, caption=None, term=None):
    s = slide()
    chrome(s, n, kicker, title)
    left_fn(s)
    if img:
        shotwrap(s, img, caption=caption)
    elif term:
        shotwrap(s, None, caption=caption, term_lines=term)
    return s


# ================= 1 · COVER =================
s = slide(BG2)
rect(s, 0, 0, 1280, 5, RED)
rect(s, 72, 190, 56, 6, RED)
f = tb(s, 72, 230, 1100, 90)
run(f.paragraphs[0], "CYBERHUNTER AI", px=76, color=WHITE, bold=True, font=FH)
f = tb(s, 72, 340, 1100, 40)
run(f.paragraphs[0], "AI-Powered Automated Vulnerability Assessment Platform", px=28, color=BLUE2, font=FH)
f = tb(s, 72, 586, 600, 30)
p = f.paragraphs[0]
run(p, "Oleh  ", px=19, color=DIM)
run(p, "Nastain", px=19, color=WHITE, bold=True)
run(p, "   ·   Team Ternakheck", px=19, color=BLUE2, bold=True)
for (x, y, d) in [(1070,-160,520),(1180,550,260),(1190,160,160)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, E(x), E(y), E(d), E(d))
    o.fill.solid(); o.fill.fore_color.rgb = PANEL; o.line.fill.background(); o.shadow.inherit = False

# ================= 2 · MASALAH =================
def l2(s):
    li_bullets(s, [
        ("Testing manual lambat", "ratusan input tersembunyi mustahil dicek satu per satu dengan tangan."),
        ("Scanner biasa hanya pasif", "cek header/banner saja, tanpa active probing."),
        ("Parameter sering terlewat", "POST body, JSON API, hidden fields, cookie, header, file .js."),
        ("Anti-bot menghalangi", "WAF modern memakai JavaScript challenge."),
        ("Hasil mentah sulit dipakai", "tanpa payload, evidence & request/response lengkap."),
    ])
content_slide(2, "Latar Belakang", "Masalah", l2, "dashboard.png", "Dashboard — overview hasil assessment")

# ================= 3 · DESKRIPSI =================
def l3(s):
    f = tb(s, 64, 150, 560, 480)
    items = [
        "CYBERHUNTER AI adalah platform pengujian keamanan siber berbasis AI untuk mengidentifikasi, menganalisis, dan mengevaluasi kerentanan aplikasi web secara otomatis.",
        "Menyediakan automated vulnerability assessment pada sistem yang telah berizin diuji — konfigurasi tidak tepat, kelemahan validasi input, security headers, dan kerentanan berbasis standar OWASP.",
        "Hasil di dashboard interaktif: jenis kerentanan, tingkat risiko, bukti pengujian, dan rekomendasi perbaikan — dibantu AI untuk analisis dampak & prioritas mitigasi.",
    ]
    first = True
    for txt in items:
        p = f.paragraphs[0] if first and not f.paragraphs[0].runs else f.add_paragraph()
        p.space_after = Pt(18)
        run(p, "▪  ", px=19, color=RED, bold=True)
        run(p, txt, px=19, color=WHITE)
        first = False
    p = f.add_paragraph(); p.space_before = Pt(10)
    run(p, "▪  ", px=19, color=RED, bold=True)
    run(p, "Tujuan: ", px=19, color=BLUE2, bold=True)
    run(p, "efektivitas pengujian, deteksi dini, terstruktur & bertanggung jawab.", px=19, color=WHITE)
content_slide(3, "Tentang Karya", "Deskripsi", l3, "scan.png", "Scan console — assessment berjalan real-time")

# ================= 4 · TUJUAN =================
def l4(s):
    cards(s, [
        ("Efektivitas", "Otomasi assessment — cakupan jauh lebih luas dari testing manual.", BLUE),
        ("Deteksi Dini", "Menemukan celah sebelum dieksploitasi pihak tidak bertanggung jawab.", RED),
        ("Terukur", "Setiap temuan: payload, request/response, severity & rekomendasi.", BLUE2),
        ("Bertanggung Jawab", "Hanya untuk sistem berizin — etika & dampak minimal.", GREEN),
    ])
content_slide(4, "Tujuan", "Pengembangan", l4, "findings.png", "Findings — kerentanan, risiko & rekomendasi")

# ================= 5 · FITUR =================
def l5(s):
    cards(s, [
        ("Crawler Cerdas", "Multi-halaman, subdomain, form, JS bundle + parameter mining & filename mutation.", BLUE),
        ("OWASP Top 10", "SQLi, XSS, cmdi, LFI, SSRF, XXE, CORS, headers — aktif & pasif.", RED),
        ("Anti-Bot Solver", "JS challenge (WAF splash) di-solve otomatis via headless Chromium.", BLUE2),
        ("AI Analysis", "6 provider model — triage temuan, dampak & prioritas mitigasi.", GREEN),
    ])
content_slide(5, "Fitur", "Unggulan Platform", l5, "ai-config.png", "AI Configuration — 6 provider model")

# ================= 6 · ALUR =================
def l6(s):
    steps(s, [
        ("01", BLUE, "Recon", "Crawl halaman, form, JS, subdomain."),
        ("02", RED, "Discover", "Ekstrak semua parameter & endpoint tersembunyi."),
        ("03", BLUE, "Probe", "Payload OWASP aktif ke setiap input."),
        ("04", RED, "Verify", "Konfirmasi error, eksekusi JS, CVE fingerprint."),
        ("05", GREEN, "Report", "Evidence lengkap → dashboard + laporan bilingual."),
    ])
content_slide(6, "Cara Kerja", "Alur Assessment", l6, "scan.png", "Scan Target — alur assessment real-time")

# ================= 7 · CAKUPAN =================
def l7(s):
    li_bullets(s, [
        ("Input langsung", "query string, form GET/POST (input, select, textarea, hidden), JSON & XML body, headers, cookies."),
        ("Discovery otomatis", "parameter di file .js, ±75 nama param umum, endpoint tak ter-link, filename mutation, subdomain enum."),
        (None, "Hasil — tidak ada input yang kelewat; semua masuk antrian probe aktif."),
    ], px=17, gap_px=16)
content_slide(7, "Coverage", "Semua Input Diuji", l7, "scan.png", "Live log — setiap probe & payload terekam")

# ================= 8 · DETEKSI =================
def l8(s):
    cards(s, [
        ("SQL Injection", "Error-based, blind time-based (konfirmasi ganda), UNION extraction 15 kolom.", BLUE),
        ("XSS", "Reflected, stored & DOM — diverifikasi eksekusi JS via headless browser.", RED),
        ("Command Injection", "Marker aritmatika → output CYBERHUNTER_49, bukan refleksi biasa.", BLUE2),
        ("CVE Surface", "Fingerprint PHP/CMS → ruleset CVE (php2shell, Drupalgeddon2, Joomla, Laravel).", GREEN),
    ])
content_slide(8, "Detection", "Deteksi Kerentanan", l8, "scan.png", "Live log — payload & evidence per probe")

# ================= 9 · PHP2SHELL =================
def l9(s):
    li_bullets(s, [
        ("Apa itu", "memory corruption & use-after-free di PHP core. Unauthenticated, ~1 request untuk mod_php."),
        ("Kenapa kritis", "flaw di runtime PHP; aplikasi aman pun rentan. PHP ≤8.1 (EOL) tidak akan dapat patch."),
        ("Deteksi", "version fingerprinting (header, PHPSESSID, phpinfo) + behavioral probe multipart."),
        ("Hasil", "versi rentan → CRITICAL; indikasi behavioral → HIGH. Fixed: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12."),
    ], px=17, gap_px=16)
content_slide(9, "CVE", "PHP2Shell — CVE-2026-109618 & 109619", l9, "findings.png", "Finding — severity & evidence lengkap")

# ================= 10 · PELAPORAN =================
def l10(s):
    cards(s, [
        ("Jenis Kerentanan", "SQLi, XSS, cmdi, LFI, SSRF, XXE, CORS, headers, CVE — terklasifikasi.", BLUE),
        ("Tingkat Risiko", "Critical/High/Medium/Low/Info — chart interaktif + filter.", RED),
        ("Bukti", "Payload persis, lokasi parameter, request & response mentah.", BLUE2),
        ("Rekomendasi", "Panduan perbaikan + laporan HTML bilingual (EN/ID) format XRay.", GREEN),
    ])
content_slide(10, "Hasil", "Dashboard & Pelaporan", l10, "findings.png", "Findings Database — severity & evidence")

# ================= 11 · ETIKA =================
def l11(s):
    li_bullets(s, [
        ("Otorisasi wajib", "active probing hanya untuk sistem milik sendiri / berizin tertulis."),
        ("Cookie aman", "session cookie di-scope per-origin; nilai disensor di log, DB, laporan."),
        ("Payload non-destruktif", "marker aritmatika, canary, error-based — tanpa exploit merusak."),
        ("Rate limiting", "request delay dapat diatur; beban ke target tetap wajar."),
        ("Scope awareness", "robots.txt Disallow → peringatan; area terlarang tidak disentuh."),
    ], px=17, gap_px=16)
content_slide(11, "Keamanan", "Etika & Authorized Testing", l11, "tools.png", "Tools — utilitas pendukung assessment")

# ================= 12 · TEKNOLOGI =================
def l12(s):
    cards(s, [
        ("Frontend", "React 18 · TypeScript · Vite — dashboard, live log, severity chart.", BLUE),
        ("Backend", "Node.js · Express — crawler, probe engine, Puppeteer.", RED),
        ("Deteksi", "±90 payload OWASP · 75+ param mining · DOM XSS verified.", BLUE2),
        ("AI", "6 provider (cloud & lokal) — key terenkripsi, usage logs.", GREEN),
    ])
content_slide(12, "Stack", "Teknologi", l12, "ai-config.png", "AI Configuration — 6 provider model")

# ================= 13 · ARSITEKTUR =================
s = slide()
chrome(s, 13, "Arsitektur", "System Design")
layers = [
    ("FRONTEND", "React 18 + TypeScript + Vite", "Dashboard · Scan Console · Findings · AI Configuration · Laporan HTML", BLUE),
    ("BACKEND", "Node.js + Express — REST API + SSE live log", "crawler.js · scanner.js · cve.js · domxss.js · challenge.js · db.js", RED),
    ("DATA & AI", "Findings DB (JSON persisten) + 6 AI Provider", "OpenAI-compatible · Anthropic · Gemini · Ollama · LM Studio · EdgeOne", GREEN),
]
ty = 165
for i, (tag_, sub, body, c) in enumerate(layers):
    rrect(s, 100, ty, 1080, 118, PANEL, LINE, 0.06)
    rect(s, 100, ty + 14, 7, 90, c)
    f = tb(s, 140, ty + 14, 1000, 95)
    f.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = f.paragraphs[0]
    run(p, tag_ + "   ", px=22, color=c, bold=True, font=FH)
    run(p, sub, px=17, color=BLUE2, bold=True)
    p2 = f.add_paragraph(); p2.space_before = Pt(4)
    run(p2, body, px=15, color=WHITE)
    if i < 2:
        ar = s.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, E(630), E(ty + 124), E(20), E(24))
        ar.fill.solid(); ar.fill.fore_color.rgb = LINE; ar.line.fill.background(); ar.shadow.inherit = False
    ty += 118 + 32
f = tb(s, 100, 648, 1080, 24)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Frontend → REST API / SSE → Scanner Engine → Findings DB → Report Engine → AI Analysis", px=15, color=DIM, bold=True)

# ================= 14 · CARA DOWNLOAD =================
def l_dl(s):
    li_bullets(s, [
        ("Repository GitHub", "github.com/nastainannas/cyberhunter-ai — public, langsung bisa di-clone."),
        ("Opsi 1 — Git clone", "git clone https://github.com/nastainannas/cyberhunter-ai.git lalu cd cyberhunter-ai."),
        ("Opsi 2 — Download ZIP", "GitHub → Code → Download ZIP → extract ke folder project."),
        ("Prasyarat", "Node.js 18+ dan npm — cek dengan node -v && npm -v di terminal."),
    ], px=17, gap_px=16)
content_slide(14, "Instalasi", "Cara Download", l_dl, term=[
    ("git clone https://github.com/nastainannas/cyberhunter-ai.git", WHITE),
    ("cd cyberhunter-ai", WHITE),
    ("# cek prasyarat", DIM2),
    ("node -v   &&   npm -v", WHITE),
    ("Struktur: backend/ + frontend/", GREEN),
], caption="Terminal — clone repository")

# ================= 15 · CARA INSTAL =================
def l_in(s):
    li_bullets(s, [
        ("Backend dulu", "cd backend → npm install → npm start. API di http://localhost:8787"),
        ("Frontend", "cd frontend → npm install → npm run dev. UI di http://localhost:5173"),
        ("Pertama kali", "npm install mengunduh semua dependency (±1–2 menit)."),
        ("Konfigurasi AI (opsional)", "AI Configuration → pilih provider → isi API key → Test Connection."),
        ("Mulai scan", "Scan Target → masukkan URL → mode Passive/Active → Start Scan."),
    ], px=16, gap_px=14)
content_slide(15, "Instalasi", "Cara Instal & Menjalankan", l_in, term=[
    ("cd backend", WHITE),
    ("npm install", WHITE),
    ("npm start        # API → :8787", WHITE),
    ("cd ../frontend", WHITE),
    ("npm install", WHITE),
    ("npm run dev      # UI → :5173", WHITE),
    ("✓ Backend & frontend berjalan", GREEN),
], caption="Terminal — instalasi & menjalankan")

# ================= 16 · ROADMAP =================
def l13(s):
    steps(s, [
        ("01", BLUE, "Jangka Pendek", "Template Nuclei · wizard authenticated scan · export PDF."),
        ("02", RED, "Menengah", "Distributed queue · authenticated crawling · GraphQL fuzzing."),
        ("03", BLUE2, "Jangka Panjang", "Plugin custom · sinkronisasi scope bug bounty · AI triage otomatis."),
    ], y=200)
content_slide(16, "Pengembangan", "Roadmap", l13, "thumbnail.png", "CYBERHUNTER AI")

# ================= 17 · CLOSING =================
s = slide(BG2)
rect(s, 0, 0, 1280, 5, RED)
for (x, y, d) in [(1080,-160,500),(-130,580,320)]:
    o = s.shapes.add_shape(MSO_SHAPE.OVAL, E(x), E(y), E(d), E(d))
    o.fill.solid(); o.fill.fore_color.rgb = PANEL; o.line.fill.background(); o.shadow.inherit = False
f = tb(s, 0, 200, 1280, 70)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Terima Kasih", px=60, color=WHITE, bold=True, font=FH)
f = tb(s, 0, 300, 1280, 36)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "CYBERHUNTER AI — AI-Powered Automated Vulnerability Assessment Platform", px=24, color=BLUE2, font=FH)
f = tb(s, 0, 360, 1280, 30)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Scan lebih dalam, temukan lebih banyak, amankan lebih awal.", px=18, color=DIM)
f = tb(s, 0, 520, 1280, 30)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "github.com/nastainannas/cyberhunter-ai", px=20, color=WHITE, bold=True)
f = tb(s, 0, 560, 1280, 26)
p = f.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
run(p, "Oleh Nastain  ·  Team Ternakheck", px=16, color=DIM)

try:
    prs.save(OUT)
    print("saved ->", OUT)
except PermissionError:
    prs.save(OUT2)
    print("locked, saved ->", OUT2)
print("slides:", len(prs.slides._sldIdLst))
