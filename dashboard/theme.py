"""Visual identity: deep black surfaces, cyan/violet neon accents, controlled glow.

Severity colours stay semantic (red, orange, yellow, green, blue) so risk reads at a glance.
"""
from __future__ import annotations

from .icons import data_uri

STAGES = [
    (1, "Intake", "upload"),
    (2, "Analysis", "radar"),
    (3, "Report", "file"),
    (4, "Remediation", "shield-check"),
    (5, "Export", "package"),
    (6, "Deploy", "rocket"),
    (7, "Rescan", "refresh"),
]

STATE_COLORS = {"active": "#22d3ee", "done": "#34d399", "ready": "#a3aac2", "locked": "#4b5266"}
STATE_LABELS = {"active": "ACTIVE", "done": "DONE", "ready": "READY", "locked": "LOCKED"}

BASE_CSS = """
:root{--bg:#05060a;--cyan:#22d3ee;--violet:#8b5cf6;--green:#34d399;--text:#f4f6ff;--muted:#8b93a7;--line:rgba(139,147,255,.18);--crit:#ff3b6b;--high:#ff8a3d;--med:#ffd23f;--low:#34d399;--info:#5aa9ff;--mono:ui-monospace,'Cascadia Code','SF Mono',Consolas,monospace;}
.stApp{background:radial-gradient(1100px 600px at 6% -10%,rgba(139,92,246,.22),transparent 60%),radial-gradient(900px 500px at 106% 0%,rgba(34,211,238,.15),transparent 55%),radial-gradient(900px 600px at 50% 125%,rgba(244,63,94,.08),transparent 60%),#05060a;color:var(--text);}
.stApp::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(139,147,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(139,147,255,.05) 1px,transparent 1px);background-size:46px 46px;-webkit-mask-image:radial-gradient(ellipse at 50% 0%,#000 15%,transparent 72%);mask-image:radial-gradient(ellipse at 50% 0%,#000 15%,transparent 72%);}
header[data-testid='stHeader']{background:transparent;}
#MainMenu,footer{visibility:hidden;}
.block-container{max-width:1280px;padding-top:1rem;padding-bottom:3rem;position:relative;z-index:1;}
h1,h2,h3,h4{color:var(--text);}
.lx-top{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;}
.lx-brand{display:flex;align-items:center;gap:.9rem;}
.lx-logo{width:48px;height:48px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(34,211,238,.28),rgba(139,92,246,.4));border:1px solid rgba(34,211,238,.6);box-shadow:0 0 24px rgba(34,211,238,.28),inset 0 0 14px rgba(139,92,246,.3);}
.lx-title{font-weight:800;font-size:1.6rem;letter-spacing:.015em;line-height:1.1;background:linear-gradient(90deg,#ffffff 0%,#9eeaff 55%,#c4b5fd 100%);-webkit-background-clip:text;background-clip:text;color:transparent;}
.lx-tag{font-family:var(--mono);font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-top:.15rem;}
.lx-pills{display:flex;gap:.4rem;flex-wrap:wrap;}
.lx-pill{display:inline-flex;align-items:center;gap:.45rem;padding:.3rem .75rem;border-radius:999px;font-size:.72rem;font-family:var(--mono);border:1px solid var(--line);background:rgba(16,20,42,.75);color:var(--text);}
.lx-pill i{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor;}
.lx-pill.ok{border-color:rgba(52,211,153,.55);color:#9df0cf;}
.lx-pill.warn{border-color:rgba(255,210,63,.5);color:#ffe18a;}
.lx-pill.off{color:var(--muted);}
.lx-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.7rem;margin:.9rem 0 1.2rem;}
.lx-kpi{position:relative;padding:.8rem .95rem .8rem 1.1rem;border-radius:14px;border:1px solid var(--line);background:linear-gradient(150deg,rgba(20,25,48,.88),rgba(9,11,20,.92));overflow:hidden;}
.lx-kpi::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent,#22d3ee);box-shadow:0 0 14px var(--accent,#22d3ee);}
.lx-kpi .k{display:flex;align-items:center;gap:.4rem;font-size:.64rem;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);font-family:var(--mono);}
.lx-kpi .v{font-size:1.5rem;font-weight:800;margin-top:.3rem;line-height:1.1;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.lx-kpi .s{font-size:.72rem;color:var(--muted);margin-top:.15rem;}
div[data-testid='stVerticalBlockBorderWrapper']{background:linear-gradient(155deg,rgba(18,22,44,.82),rgba(8,10,18,.93));border:1px solid var(--line) !important;border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.04);}
.lx-hero{display:flex;align-items:center;gap:1rem;margin:.2rem 0 1rem;}
.lx-hero-ic{width:56px;height:56px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(34,211,238,.18),rgba(139,92,246,.22));border:1px solid rgba(34,211,238,.45);box-shadow:0 0 28px rgba(34,211,238,.2);}
.lx-eyebrow{font-family:var(--mono);font-size:.68rem;letter-spacing:.22em;color:var(--cyan);}
.lx-hero-t{font-size:1.7rem;font-weight:800;line-height:1.15;}
.lx-hero-d{color:var(--muted);font-size:.9rem;margin-top:.1rem;max-width:62ch;}
.lx-sec{display:flex;align-items:center;gap:.75rem;margin:.1rem 0 .7rem;}
.lx-sec .ic{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.35);flex:none;}
.lx-sec .t{font-weight:700;font-size:1.02rem;}
.lx-sec .d{color:var(--muted);font-size:.8rem;}
.lx-badge{display:inline-flex;align-items:center;gap:.35rem;padding:.16rem .55rem;border-radius:6px;font-family:var(--mono);font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--line);color:var(--muted);background:rgba(10,13,24,.7);}
.lx-badge.ok{color:#9df0cf;border-color:rgba(52,211,153,.5);background:rgba(52,211,153,.08);}
.lx-badge.warn{color:#ffe18a;border-color:rgba(255,210,63,.5);background:rgba(255,210,63,.08);}
.lx-badge.bad{color:#ff9db3;border-color:rgba(255,59,107,.55);background:rgba(255,59,107,.09);}
.lx-badge.info{color:#9eeaff;border-color:rgba(34,211,238,.5);background:rgba(34,211,238,.08);}
.lx-sev{display:inline-block;padding:.16rem .6rem;border-radius:6px;font-family:var(--mono);font-size:.68rem;font-weight:700;letter-spacing:.1em;color:#05060a;}
.lx-sev.critical{background:var(--crit);box-shadow:0 0 12px rgba(255,59,107,.5);}
.lx-sev.high{background:var(--high);box-shadow:0 0 12px rgba(255,138,61,.4);}
.lx-sev.medium{background:var(--med);}
.lx-sev.low{background:var(--low);}
.lx-sev.info{background:var(--info);}
.lx-find{border:1px solid var(--line);border-left:3px solid var(--c);border-radius:12px;padding:.75rem .95rem;margin:.55rem 0;background:linear-gradient(150deg,rgba(14,18,36,.9),rgba(8,10,18,.95));}
.lx-find-h{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;}
.lx-find-h .t{font-weight:700;}
.lx-find-m{display:flex;gap:1rem;flex-wrap:wrap;margin:.4rem 0;color:var(--muted);font-size:.76rem;font-family:var(--mono);}
.lx-find-m span{display:inline-flex;align-items:center;gap:.3rem;}
.lx-pre{font-family:var(--mono);font-size:.78rem;background:#04050a;border:1px solid var(--line);border-radius:8px;padding:.5rem .65rem;color:#cfe8ff;white-space:pre-wrap;word-break:break-all;margin:.35rem 0;}
.lx-find details{margin-top:.4rem;}
.lx-find summary{cursor:pointer;color:var(--cyan);font-size:.8rem;}
.lx-grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.8rem;margin-top:.5rem;}
.lx-grid3 b{font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-family:var(--mono);}
.lx-grid3 p{margin:.2rem 0 0;font-size:.85rem;line-height:1.45;}
.lx-ai{margin-top:.6rem;padding:.6rem .75rem;border-radius:10px;border:1px dashed rgba(34,211,238,.45);background:rgba(34,211,238,.05);}
.lx-ai-h{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;font-size:.72rem;color:var(--muted);}
.lx-ai-b{margin-top:.35rem;font-size:.85rem;line-height:1.5;}
.lx-ring{position:relative;width:160px;height:160px;margin:0 auto;}
.lx-ring-c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.lx-ring-c .n{font-size:2.3rem;font-weight:800;line-height:1;}
.lx-ring-c .l{font-family:var(--mono);font-size:.68rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-top:.25rem;}
.lx-sevbar{display:flex;height:14px;border-radius:999px;overflow:hidden;background:rgba(139,147,255,.12);gap:2px;}
.lx-sevbar span{display:block;min-width:6px;}
.lx-legend{display:flex;gap:1rem;flex-wrap:wrap;margin-top:.55rem;font-family:var(--mono);font-size:.7rem;color:var(--muted);}
.lx-legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:.35rem;}
.lx-legend b{color:#fff;}
.lx-checks{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.6rem;margin-top:.9rem;}
.lx-check{display:flex;gap:.6rem;align-items:flex-start;padding:.6rem .7rem;border-radius:10px;border:1px solid var(--line);background:rgba(10,13,24,.7);}
.lx-check .n{font-size:.82rem;font-weight:600;}
.lx-check .d{font-size:.72rem;color:var(--muted);margin-top:.1rem;}
.lx-list{display:flex;flex-direction:column;gap:.45rem;}
.lx-li{display:flex;gap:.6rem;align-items:flex-start;font-size:.88rem;line-height:1.4;}
.lx-li svg{flex:none;margin-top:.1rem;}
.lx-empty{text-align:center;padding:2.2rem 1rem;border-radius:16px;border:1px dashed rgba(139,147,255,.3);background:radial-gradient(500px 160px at 50% 0%,rgba(139,92,246,.1),transparent 70%);}
.lx-empty .ic{width:64px;height:64px;margin:0 auto .8rem;border-radius:18px;display:grid;place-items:center;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.35);}
.lx-empty .t{font-weight:700;font-size:1.1rem;}
.lx-empty .d{color:var(--muted);font-size:.88rem;margin-top:.3rem;max-width:56ch;margin-left:auto;margin-right:auto;}
.lx-banner{display:flex;gap:.7rem;align-items:center;padding:.65rem .9rem;border-radius:12px;border:1px solid rgba(255,210,63,.45);background:linear-gradient(90deg,rgba(255,210,63,.1),rgba(255,210,63,.03));color:#ffe9a8;font-size:.85rem;margin:.3rem 0 .8rem;}
.lx-tl{position:relative;margin-left:.4rem;padding-left:1.1rem;border-left:1px solid var(--line);}
.lx-tl-i{position:relative;padding:.1rem 0 .85rem;}
.lx-tl-i .dot{position:absolute;left:-1.5rem;top:.25rem;width:11px;height:11px;border-radius:50%;background:var(--tc,#8b93a7);box-shadow:0 0 10px var(--tc,#8b93a7);}
.lx-tl-i .h{display:flex;justify-content:space-between;gap:.6rem;flex-wrap:wrap;font-size:.86rem;}
.lx-tl-i .h span{font-family:var(--mono);font-size:.68rem;color:var(--muted);}
.lx-tl-i .m{font-size:.78rem;color:var(--muted);}
.lx-flow{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.7rem;margin:.6rem 0 1rem;}
.lx-step{position:relative;padding:.75rem .85rem;border-radius:12px;border:1px solid var(--line);background:rgba(10,13,24,.75);}
.lx-step .n{font-family:var(--mono);font-size:.64rem;letter-spacing:.14em;color:var(--muted);}
.lx-step .t{font-weight:700;font-size:.9rem;margin:.2rem 0 .35rem;}
.lx-step .d{font-size:.72rem;color:var(--muted);margin-top:.4rem;}
.lx-q{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;}
.lx-q .loc{font-family:var(--mono);font-size:.78rem;color:var(--muted);}
.lx-q-d{color:var(--muted);font-size:.84rem;margin:.35rem 0 .1rem;}
.lx-foot{color:var(--muted);font-size:.74rem;margin-top:1.4rem;text-align:center;}
.stButton>button,.stDownloadButton>button{border-radius:10px;border:1px solid rgba(34,211,238,.45);background:linear-gradient(180deg,rgba(34,211,238,.14),rgba(34,211,238,.05));color:#eaffff;font-weight:600;letter-spacing:.02em;transition:all .15s ease;}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:#22d3ee;box-shadow:0 0 18px rgba(34,211,238,.3);color:#fff;}
.stButton>button[kind='primary'],button[data-testid='stBaseButton-primary']{background:linear-gradient(135deg,#0891b2,#7c3aed);border:1px solid rgba(255,255,255,.22);box-shadow:0 0 22px rgba(34,211,238,.32);color:#fff;}
.stButton>button:disabled,.stDownloadButton>button:disabled{opacity:.4;box-shadow:none;}
.stTextInput input,.stTextArea textarea,div[data-baseweb='select']>div{background:#070914 !important;border:1px solid var(--line) !important;color:#fff !important;border-radius:10px !important;}
.stTextInput input:focus{border-color:#22d3ee !important;box-shadow:0 0 0 1px #22d3ee !important;}
[data-testid='stFileUploaderDropzone']{background:radial-gradient(400px 120px at 50% 0%,rgba(34,211,238,.1),transparent 70%),rgba(34,211,238,.03);border:1.5px dashed rgba(34,211,238,.5);border-radius:14px;}
[data-testid='stExpander']{border:1px solid var(--line);border-radius:12px;background:rgba(10,13,24,.7);}
[data-testid='stDataFrame']{border:1px solid var(--line);border-radius:12px;overflow:hidden;}
div[data-testid='stAlert']{border-radius:12px;}
.stProgress>div>div>div>div{background:linear-gradient(90deg,#22d3ee,#8b5cf6);}
[class*='st-key-nav_']{width:100%;}
[class*='st-key-nav_'] button{position:relative;width:100% !important;min-height:94px;padding:36px 12px 10px 14px;display:flex;align-items:flex-end;justify-content:flex-start;text-align:left;border-radius:14px;border:1px solid var(--line) !important;background:linear-gradient(160deg,rgba(18,22,44,.88),rgba(8,10,18,.96)) !important;box-shadow:none;transition:all .18s ease;overflow:hidden;}
[class*='st-key-nav_'] button p{font-weight:700;letter-spacing:.04em;font-size:.95rem;margin:0;text-align:left;color:#fff;}
[class*='st-key-nav_'] button::before{content:'';position:absolute;left:14px;top:12px;width:20px;height:20px;background-size:contain;background-repeat:no-repeat;}
[class*='st-key-nav_'] button::after{position:absolute;right:12px;top:14px;font-family:var(--mono);font-size:.62rem;letter-spacing:.14em;}
[class*='st-key-nav_'] button:hover:not(:disabled){transform:translateY(-2px);border-color:rgba(34,211,238,.65) !important;box-shadow:0 8px 28px rgba(34,211,238,.16);}
[class*='st-key-nav_'] button:disabled{cursor:not-allowed;}
@media (max-width:900px){.lx-title{font-size:1.25rem;}.lx-hero-t{font-size:1.3rem;}[class*='st-key-nav_'] button{min-height:72px;}}
"""


def nav_css(states: dict) -> str:
    """Per-stage navigation styling: icon colour, status label and highlight depend on state."""
    parts = []
    for n, _name, icon_name in STAGES:
        state = states.get(n, "ready")
        color = STATE_COLORS[state]
        label = STATE_LABELS[state]
        sel = f".st-key-nav_{n} button"
        rules = (
            f'{sel}::before{{background-image:url("{data_uri(icon_name, color)}");}}'
            f'{sel}::after{{content:"{n:02d} \u00b7 {label}";color:{color};}}'
        )
        if state == "active":
            rules += (
                f"{sel}{{border-color:{color} !important;"
                "background:linear-gradient(160deg,rgba(34,211,238,.22),rgba(139,92,246,.16)) !important;"
                "box-shadow:0 0 0 1px rgba(34,211,238,.35),0 0 30px rgba(34,211,238,.24) !important;}"
            )
        elif state == "done":
            rules += f"{sel}{{border-color:rgba(52,211,153,.5) !important;}}"
        elif state == "locked":
            rules += f"{sel}{{opacity:.55 !important;}}{sel} p{{color:#6b7389 !important;}}"
        parts.append(rules)
    return "".join(parts)
