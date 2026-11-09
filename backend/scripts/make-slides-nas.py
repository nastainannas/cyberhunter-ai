# Rebuild NAS.pptx content in-place: keep ALL template design/shapes,
# replace text frame contents (preserving run formatting), and swap
# selected picture shapes for app screenshots (aspect-fit, no crop).
import copy
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.oxml.ns import qn

SRC = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\NAS.pptx"
ASSETS = r"C:\Users\ADMPROD-05-PC\Documents\project\hack\submission-assets"
OUT = ASSETS + r"\cyberhunter-slides.pptx"

prs = Presentation(SRC)


def set_text(shape, text):
    """Replace text frame content, keeping first run's rPr + first p's pPr."""
    tf = shape.text_frame
    txBody = tf._txBody
    ps = txBody.findall(qn('a:p'))
    if not ps:
        return
    pPr = ps[0].find(qn('a:pPr'))
    rPr = None
    for r in ps[0].findall(qn('a:r')):
        rp = r.find(qn('a:rPr'))
        if rp is not None:
            rPr = rp
            break
    for p in ps:
        txBody.remove(p)
    for line in text.split('\n'):
        p = txBody.makeelement(qn('a:p'), {})
        if pPr is not None:
            p.append(copy.deepcopy(pPr))
        r = p.makeelement(qn('a:r'), {})
        if rPr is not None:
            r.append(copy.deepcopy(rPr))
        t = r.makeelement(qn('a:t'), {})
        t.text = line
        r.append(t)
        p.append(r)
        txBody.append(p)


# slide_num -> {shape_index: new_text}
REPL = {
    1: {
        3:  "Platform Automated Security Testing & Bug Bounty",
        14: "CYBERHUNTER AI\nSecurity Testing",
        15: "Nastain",
        16: "Ternakheck",
        17: "Authorized Testing\n2025",
    },
    2: {
        13: "Problem", 14: "Discovery", 15: "Detection", 16: "Reporting",
        25: "The Problem\nWhy It Matters",
        26: "Modern web apps hide hundreds of inputs — manual testing can't cover them all.",
        34: "04.",
        36: "Smart crawler + parameter mining finds every query, form, JSON, header & cookie input.",
        37: "Active OWASP probes — SQLi, XSS, cmdi, LFI, SSRF, XXE — each with real evidence.",
        38: "CVE fingerprinting, anti-bot bypass & bilingual reports ready for bug bounty.",
    },
    3: {
        17: "The Platform", 18: "Nastain", 19: "Ternakheck",
        3:  "CYBERHUNTER AI automates authorized security testing — from recon to verified findings.",
        20: "Scan wide.\nScan deep.",
    },
    4: {
        3:  "Dashboard & Findings Overview",
        9:  "Setiap scan menghasilkan findings terstruktur: severity, OWASP category, dan evidence lengkap.",
        12: "Severity Breakdown",
        13: "Critical & High langsung muncul di live feed — medium/low tersimpan di report.",
        16: "Coverage",
        17: "Query, form, JSON, XML, header, cookie, JS-mined & hidden params — tidak ada yang kelewat.",
    },
    5: {
        0:  "Adaptive crawler + probe engine — crawl, discover, probe, verify, report.",
        10: "Scan Engine",
        17: "Recon",      19: "Crawl pages, forms, JS bundles & subdomains",
        20: "Probing",    24: "Active OWASP payloads pada semua input yang ditemukan",
        25: "Verification", 26: "Browser-verified DOM XSS & CVE surface checks",
        27: "Anti-Bot",   29: "JS challenge solver — clearance cookie otomatis",
    },
    6: {
        14: "Deteksi Vulnerability",
        15: "OWASP Top 10 + CVE — SQLi, XSS, command injection, LFI, SSRF, XXE, CORS & security headers.",
        16: "SQL Injection",
        22: "Error-based · time-based blind · UNION extraction · multibyte collation probes.",
    },
    7: {
        17: "Detection", 18: "Nastain", 19: "Ternakheck",
        3:  "Active probing dengan payload presisi — dikonfirmasi ganda untuk menghindari false positive.",
    },
    8: {
        11: "Parameter Coverage — Semua Input Diprobe",
        19: "Forms",    20: "Headers",
        21: "Input POST/GET forms, hidden fields, select & textarea ikut diprobe.",
        22: "Cookie, User-Agent, Referer, X-Forwarded-* headers.",
        23: "Discovery", 24: "Param mining (±75 nama), endpoint wordlist & filename mutation.",
        25: "JavaScript", 26: "Endpoint & params di-mining dari fetch/axios/route di bundle .js.",
    },
    9: {
        9:  "Scan Console — Live Log",
        15: "Real-time probe log: setiap request, payload, status & timing terlihat langsung.",
        20: "Live", 21: "Evidence",
    },
    10: {
        11: "Findings Database",
        19: "Severity", 20: "Evidence",
        21: "Critical/High/Medium/Low/Info — filter & severity chart interaktif.",
        22: "Payload persis, parameter, lokasi, request & response mentah per finding.",
    },
    11: {
        13: "CVE & Tech Fingerprint",
        14: "Technology Detection",
        15: "PHP2Shell & Beyond",
        16: "Versi PHP/CMS dideteksi → dicocokkan ke ruleset CVE (php2shell CVE-2026-109618/619, Drupalgeddon2, Joomla, Laravel, WordPress…).",
        17: "Hasil & Bukti",
    },
    12: {
        17: "Reporting", 18: "Nastain", 19: "Ternakheck",
        3:  "Bukti lengkap untuk setiap temuan — siap submit ke program bug bounty.",
    },
    13: {
        9:  "Evidence-Rich Findings",
        18: "Payload & Context",
        20: "Setiap finding menyimpan URL, parameter, lokasi (query/body/header/cookie), payload pemicu, dan evidence.",
        24: "A01–A10", 25: "CVE rules",
        27: "Zero guessing.\nReal payloads.",
    },
    14: {
        6:  "Export & Reporting",
        11: "Laporan HTML Bilingual (EN/ID)",
        18: "XRay-style",
        20: "Request",   21: "Raw HTTP request yang memicu vulnerability",
        22: "Response",  23: "Response server + evidence konfirmasi",
        24: "Remediation", 25: "Rekomendasi perbaikan per finding",
        26: "EN/ID.\nBug-bounty ready.",
    },
    15: {
        10: "Etika & Keamanan",
        19: "Active probing hanya dengan otorisasi — gating eksplisit, rate limiting & payload non-destruktif.",
        20: "Auth",   21: "Scope",
        22: "Cookie session di-scope per-origin, disensor di log & report.",
        23: "robots.txt Disallow → peringatan scope.",
        24: "Marker aritmatika & canary — tanpa exploit berbahaya.",
    },
    16: {
        17: "AI & Ecosystem", 18: "Nastain", 19: "Ternakheck",
        3:  "Integrasi AI multi-provider untuk analisis & triage temuan.",
    },
    17: {
        10: "AI Configuration — Multi-Provider",
        22: "6+", 23: "Providers",
        26: "Providers", 27: "Features",
        28: "OpenAI-compatible, Anthropic, Gemini, Ollama, LM Studio, EdgeOne.",
        29: "Model selector, playground & usage logs — API key terenkripsi.",
        30: "Analysis", 31: "AI-assisted triage & penjelasan per finding.",
        32: "Encrypted keys.\nFull control.",
    },
    18: {
        8:  "Roadmap",
        12: "Next Steps",
        18: "Nuclei templates · authenticated scan wizard · PDF export → distributed queue · GraphQL fuzzing.",
        20: "Vision", 21: "Bug bounty ready.\nCommunity driven.",
    },
    19: {
        20: "Every input.\nEvery payload.",
        21: "Hidden endpoints via wordlist, subdomain enum & JS mining.",
        22: "Error-based, blind & UNION SQLi — multi-DBMS.",
        23: "Reflected, stored & DOM XSS — browser-verified.",
        24: "±90", 25: "75+", 26: "20+", 27: "6",
        28: "Payloads.\nProviders.",
    },
    20: {
        3:  "github.com/nastainannas/cyberhunter-ai",
        15: "Nastain",
        16: "Try it.\nHack responsibly.",
        17: "Ternakheck",
    },
}

# apply text replacements
for i, s in enumerate(prs.slides, 1):
    rep = REPL.get(i, {})
    shapes = list(s.shapes)
    for idx, new_text in rep.items():
        if idx < len(shapes) and shapes[idx].has_text_frame:
            set_text(shapes[idx], new_text)
        else:
            print(f"WARN slide {i} shape {idx} missing/not-text")

# ---- swap pictures for screenshots (delete pic, add fit-sized pic + frame) ----
from PIL import Image

def fit_box(orig_l, orig_t, orig_w, orig_h, img_path, max_w=None):
    iw, ih = Image.open(img_path).size
    aspect = iw / ih
    w = min(Emu(orig_w), Emu(orig_h) * aspect) if max_w is None else min(Emu(max_w), Emu(orig_h) * aspect)
    h = int(w / aspect)
    l = Emu(orig_l) + (Emu(orig_w) - w) // 2
    t = Emu(orig_t) + (Emu(orig_h) - h) // 2
    return l, t, w, h

PICTURES = [
    # (slide_idx, pic_shape_idx, image, caption)
    (4,  0, ASSETS + r"\dashboard.png", "Dashboard — severity chart & statistik scan"),
    (9,  0, ASSETS + r"\scan.png",      "Scan Target — live probe log real-time"),
    (10, 1, ASSETS + r"\findings.png",  "Findings Database — severity, OWASP & evidence"),
    (17, 0, ASSETS + r"\ai-config.png", "AI Configuration — 6 provider model"),
]

for slide_i, pic_idx, img, caption in PICTURES:
    s = prs.slides[slide_i - 1]
    pics = [sh for sh in s.shapes if sh.shape_type == 13]
    if pic_idx >= len(pics):
        print(f"WARN slide {slide_i}: pic {pic_idx} not found ({len(pics)} pics)")
        continue
    pic = pics[pic_idx]
    l, t, w, h = fit_box(pic.left, pic.top, pic.width, pic.height, img)
    # backing card slightly larger
    pad = Inches(0.12)
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.dml.color import RGBColor
    card = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                              l - pad, t - pad, w + pad * 2, h + pad * 2 + Inches(0.4))
    card.fill.solid(); card.fill.fore_color.rgb = RGBColor(0x13, 0x1B, 0x24)
    card.line.color.rgb = RGBColor(0x8D, 0xF7, 0x03); card.line.width = Pt(1.5)
    card.shadow.inherit = False
    try: card.adjustments[0] = 0.04
    except Exception: pass
    # caption bar under image inside card
    cap = s.shapes.add_textbox(l, t + h + Inches(0.08), w, Inches(0.3))
    tf = cap.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]; p.alignment = 2  # center
    r = p.add_run(); r.text = caption
    r.font.size = Pt(12); r.font.bold = True
    r.font.color.rgb = RGBColor(0x8D, 0xF7, 0x03); r.font.name = "Calibri"
    # remove old pic (it sits under new shapes anyway -> delete for cleanliness)
    pic._element.getparent().remove(pic._element)
    s.shapes.add_picture(img, l, t, width=w, height=h)
    print(f"slide {slide_i}: screenshot {img.split(chr(92))[-1]} -> ({Emu(l).inches:.2f},{Emu(t).inches:.2f}) {Emu(w).inches:.2f}x{Emu(h).inches:.2f}")

prs.save(OUT)
print("saved ->", OUT)
