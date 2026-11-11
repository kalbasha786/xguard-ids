"""XGuard IDS dashboard and control panel (set-2 extension of the FYP CSP650 prototype).

A monitor and control panel for the XGBoost IDS. It reads the log and result
files in ~/fyp, and it drives the real backend scripts (ids_controller.py,
unblock_ip.py, reset_demo.py) to run detection, release addresses and reset the
demo. It never contains its own copy of the detection, blocking or alerting
logic, so whatever it does is exactly what the terminal would do, and every
result lands in the same log files. Access needs a login, and what each person
can do depends on their role (viewer, analyst, admin).

Start it with   streamlit run app.py
"""

from __future__ import annotations

import html
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import xguard_auth as au
import xguard_data as xd
import xguard_runner as rn

st.set_page_config(
    page_title="XGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

FYP_DIR = xd.default_fyp_dir()

# ---------------------------------------------------------------------------
# Design tokens. Every colour carries a meaning, nothing is decoration.
# ---------------------------------------------------------------------------
INK = "#15232F"      # text and structure
MUTED = "#5B6873"    # secondary text
RULE = "#CBD3DA"     # borders
GRID = "#E1E6EA"     # chart grid
RED = "#B42318"      # blocked, DoS Hulk
AMBER = "#9A5B00"    # PortScan
GREEN = "#1D7A4F"    # normal traffic, alert delivered
BLUE = "#1E5AA6"     # protected address
VIOLET = "#5B3BA8"   # Web Attack
GREY = "#8A96A0"     # idle, released

CLASS_COLOR = {"BENIGN": GREEN, "DoS Hulk": RED, "PortScan": AMBER, "Web Attack": VIOLET}
ACTION_STATE = {
    "BLOCKED": "block",
    "ALREADY_BLOCKED": "repeat",
    "NOT_BLOCKED_NEVER_BLOCK_LIST": "protect",
    "NO_ACTION": "idle",
}
TELEGRAM_STATE = {"sent": "ok", "failed": "block", "not needed": "idle"}
FONT_STACK = "Atkinson Hyperlegible Next, Atkinson Hyperlegible, Segoe UI, Roboto, sans-serif"

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible+Mono:wght@400;600&family=Atkinson+Hyperlegible+Next:wght@400;600;700;800&display=swap');
:root{
--xg-ink:#15232F;--xg-muted:#5B6873;--xg-rule:#CBD3DA;--xg-soft:#E6EBEF;--xg-panel:#FFFFFF;--xg-faint:#F3F5F7;
--xg-red:#B42318;--xg-amber:#9A5B00;--xg-green:#1D7A4F;--xg-blue:#1E5AA6;--xg-violet:#5B3BA8;--xg-grey:#8A96A0;
--xg-sans:'Atkinson Hyperlegible Next','Atkinson Hyperlegible','Segoe UI',Roboto,system-ui,sans-serif;
--xg-mono:'Atkinson Hyperlegible Mono','Cascadia Mono',Consolas,ui-monospace,monospace;
}
[data-testid="stDecoration"]{display:none;}
[data-testid="stMainBlockContainer"],.block-container{padding-top:3.4rem;padding-bottom:3rem;max-width:1440px;}
.xg{font-family:var(--xg-sans);color:var(--xg-ink);line-height:1.4;}
.xg *{box-sizing:border-box;}
.xg .xg-mono{font-family:var(--xg-mono);font-variant-numeric:tabular-nums;letter-spacing:0;}
.xg .xg-ip{font-weight:600;}
.xg-brand{display:flex;align-items:center;gap:.7rem;margin:.1rem 0 1.4rem;}
.xg-brand svg{flex:none;display:block;}
.xg-wordmark{font-weight:800;font-size:1.6rem;letter-spacing:-.025em;line-height:1;}
.xg-wordmark span{font-weight:600;font-size:.95rem;letter-spacing:0;color:var(--xg-muted);margin-left:.3rem;}
.xg-tagline{font-size:.83rem;color:var(--xg-muted);margin-top:.3rem;line-height:1.3;}
.xg-head{display:flex;justify-content:space-between;align-items:flex-end;gap:1.25rem;flex-wrap:wrap;border-bottom:2px solid var(--xg-ink);padding-bottom:.75rem;margin-bottom:1.25rem;}
.xg-h1{font-size:2.1rem;font-weight:800;letter-spacing:-.02em;line-height:1.05;}
.xg-lede{color:var(--xg-muted);font-size:.95rem;line-height:1.45;max-width:72ch;margin-top:.35rem;}
.xg-status{text-align:right;}
.xg-status-line{display:inline-flex;align-items:center;gap:.5rem;font-weight:700;font-size:1rem;}
.xg-status-sub{color:var(--xg-muted);font-size:.85rem;margin-top:.15rem;}
.xg-led{display:inline-block;width:.68rem;height:.68rem;border-radius:50%;background:#C3CBD1;flex:none;vertical-align:middle;}
.xg-led.ok{background:var(--xg-green);box-shadow:0 0 0 3px rgba(29,122,79,.16);}
.xg-led.block{background:var(--xg-red);box-shadow:0 0 0 3px rgba(180,35,24,.16);}
.xg-led.repeat{background:transparent;box-shadow:inset 0 0 0 2.5px var(--xg-red);}
.xg-led.protect{background:var(--xg-blue);box-shadow:0 0 0 3px rgba(30,90,166,.16);}
.xg-led.info{background:var(--xg-ink);}
.xg-led.idle{background:#C3CBD1;}
.xg-led.fail{background:var(--xg-red);box-shadow:0 0 0 3px rgba(180,35,24,.16);animation:xg-blink 1.2s steps(2,jump-none) infinite;}
@keyframes xg-blink{50%{opacity:.15;}}
@media (prefers-reduced-motion:reduce){.xg-led.fail{animation:none;}}
.xg-trace{background:var(--xg-panel);border:1px solid var(--xg-rule);border-top:5px solid var(--xg-green);border-radius:3px;padding:1.05rem 1.3rem 1.1rem;margin-bottom:1.1rem;}
.xg-trace.block{border-top-color:var(--xg-red);}
.xg-trace.protect{border-top-color:var(--xg-blue);}
.xg-trace-top{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;}
.xg-trace-title{font-size:1.2rem;font-weight:700;display:flex;align-items:center;gap:.6rem;}
.xg-new{font-size:.8rem;font-weight:700;color:#fff;background:var(--xg-ink);padding:.12rem .5rem;border-radius:2px;}
.xg-trace-when{color:var(--xg-muted);font-size:.95rem;font-variant-numeric:tabular-nums;}
.xg-stages{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));}
.xg-stage{position:relative;padding:.1rem 1.15rem .1rem 0;min-width:0;}
.xg-stage + .xg-stage{padding-left:1.15rem;border-left:1px solid var(--xg-rule);}
.xg-stage:not(:last-child)::after{content:"";position:absolute;right:-6px;top:.42rem;width:11px;height:11px;background:var(--xg-panel);border-top:1px solid var(--xg-rule);border-right:1px solid var(--xg-rule);transform:rotate(45deg);}
.xg-stage-name{display:flex;align-items:center;gap:.5rem;font-size:.86rem;font-weight:600;color:var(--xg-muted);margin-bottom:.45rem;}
.xg-stage-value{font-size:1.38rem;font-weight:700;line-height:1.15;margin-bottom:.3rem;overflow-wrap:anywhere;}
.xg-stage-value.xg-mono{font-size:1.22rem;}
.xg-stage-note{font-size:.86rem;color:var(--xg-muted);line-height:1.35;}
.xg-trace-summary{margin-top:1.05rem;padding-top:.85rem;border-top:1px solid var(--xg-soft);font-size:1.02rem;line-height:1.5;}
.xg-trace-summary span{display:block;max-width:78ch;}
.xg-band{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));background:var(--xg-panel);border:1px solid var(--xg-rule);border-radius:3px;margin-bottom:1.4rem;}
.xg-band.four{grid-template-columns:repeat(4,minmax(0,1fr));}
.xg-band.three{grid-template-columns:repeat(3,minmax(0,1fr));}
.xg-band-item{padding:.85rem 1.1rem .9rem;min-width:0;}
.xg-band-item + .xg-band-item{border-left:1px solid var(--xg-rule);}
.xg-band-num{font-size:2rem;font-weight:800;letter-spacing:-.02em;line-height:1.05;font-variant-numeric:tabular-nums;}
.xg-band-num small{font-size:1rem;font-weight:700;letter-spacing:0;color:var(--xg-muted);margin-left:.15rem;}
.xg-band-label{font-size:.9rem;color:var(--xg-muted);margin-top:.25rem;display:flex;align-items:center;gap:.45rem;flex-wrap:wrap;}
.xg-band-flag{display:inline-flex;align-items:center;gap:.35rem;color:var(--xg-red);font-weight:700;}
.xg-section{margin:1.5rem 0 .65rem;}
.xg-h2{font-size:1.2rem;font-weight:700;letter-spacing:-.01em;line-height:1.2;}
.xg-section .xg-lede{margin-top:.2rem;font-size:.9rem;}
.xg-list{border:1px solid var(--xg-rule);border-radius:3px;background:var(--xg-panel);}
.xg-list-row{padding:.75rem 1rem;border-left:4px solid var(--xg-red);}
.xg-list-row + .xg-list-row{border-top:1px solid var(--xg-soft);}
.xg-list-main{display:flex;justify-content:space-between;align-items:baseline;gap:.75rem;flex-wrap:wrap;}
.xg-list-main .xg-ip{font-size:1.08rem;}
.xg-list-sub{color:var(--xg-muted);font-size:.86rem;margin-top:.2rem;}
.xg-list-empty{padding:1rem;color:var(--xg-muted);font-size:.92rem;border-left:4px solid var(--xg-green);}
.xg-table-wrap{border:1px solid var(--xg-rule);border-radius:3px;background:var(--xg-panel);overflow-x:auto;}
.xg .xg-table{width:100%;border-collapse:collapse;border:none;margin:0;font-size:.92rem;}
.xg .xg-table th{text-align:left;font-weight:600;font-size:.82rem;color:var(--xg-muted);background:var(--xg-faint);padding:.6rem .7rem;border:none;border-bottom:1px solid var(--xg-rule);white-space:nowrap;}
.xg .xg-table td{padding:.58rem .7rem;border:none;border-bottom:1px solid var(--xg-soft);white-space:nowrap;vertical-align:middle;background:transparent;}
.xg .xg-table tr:last-child td{border-bottom:none;}
.xg .xg-table tr:nth-child(even) td{background:transparent;}
.xg .xg-table .num{text-align:right;font-variant-numeric:tabular-nums;}
.xg .xg-table td.wrap{white-space:normal;min-width:9rem;}
.xg .xg-table .tight{width:1%;white-space:nowrap;}
.xg-cls{display:inline-flex;align-items:center;gap:.42rem;font-weight:700;}
.xg-swatch{display:inline-block;width:.6rem;height:.6rem;border-radius:2px;flex:none;}
.xg-tag{display:inline-flex;align-items:center;gap:.45rem;}
.xg-tag.bad{color:var(--xg-red);font-weight:700;}
.xg-muted{color:var(--xg-muted);}
.xg-small{font-size:.82rem;margin-top:.1rem;}
.xg-empty{background:var(--xg-panel);border:1px dashed var(--xg-rule);border-radius:3px;padding:1.4rem 1.4rem 1.2rem;margin-bottom:.8rem;}
.xg-note{border-left:3px solid var(--xg-ink);padding:.15rem 0 .15rem .9rem;color:var(--xg-ink);font-size:.92rem;line-height:1.5;max-width:80ch;margin:.4rem 0 .6rem;}
.xg-side-note{font-size:.8rem;color:var(--xg-muted);line-height:1.45;margin-top:1rem;}
@media (max-width:1000px){
.xg-stages{grid-template-columns:1fr;}
.xg-stage{padding:0;}
.xg-stage + .xg-stage{border-left:none;border-top:1px solid var(--xg-soft);padding:.75rem 0 0;margin-top:.75rem;}
.xg-stage:not(:last-child)::after{display:none;}
.xg-band,.xg-band.four,.xg-band.three{grid-template-columns:repeat(2,minmax(0,1fr));}
.xg-band-item + .xg-band-item{border-left:none;}
.xg-band-item{border-top:1px solid var(--xg-soft);}
.xg-status{text-align:left;}
}
.xg-login-wrap{max-width:420px;margin:3vh auto 0;}
.xg-login-brand{display:flex;align-items:center;gap:.8rem;justify-content:center;margin-bottom:.4rem;}
.xg-login-brand .xg-wordmark{font-size:1.9rem;}
.xg-login-tag{text-align:center;color:var(--xg-muted);font-size:.9rem;margin-bottom:1.6rem;}
.xg-login-card{background:var(--xg-panel);border:1px solid var(--xg-rule);border-top:5px solid var(--xg-ink);border-radius:3px;padding:1.5rem 1.6rem 1.2rem;}
.xg-login-card h2{font-size:1.2rem;font-weight:700;margin:0 0 1rem;}
.xg-who{display:flex;align-items:center;gap:.6rem;padding:.1rem 0 .2rem;}
.xg-who-name{font-weight:700;font-size:.98rem;line-height:1.1;}
.xg-badge{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.02em;padding:.12rem .5rem;border-radius:2px;color:#fff;background:var(--xg-grey);}
.xg-badge.admin{background:var(--xg-red);}
.xg-badge.analyst{background:var(--xg-blue);}
.xg-badge.viewer{background:var(--xg-grey);}
.xg-cap{background:var(--xg-panel);border:1px solid var(--xg-rule);border-left:4px solid var(--xg-ink);border-radius:3px;padding:.7rem .9rem;font-size:.86rem;color:var(--xg-muted);line-height:1.45;margin-bottom:1rem;}
.xg-cap b{color:var(--xg-ink);}
.xg-step{display:flex;align-items:center;gap:.6rem;font-size:.9rem;color:var(--xg-muted);margin:.1rem 0 1rem;flex-wrap:wrap;}
.xg-step-item{display:inline-flex;align-items:center;gap:.4rem;}
.xg-step-item.on{color:var(--xg-ink);font-weight:700;}
.xg-step-sep{color:var(--xg-rule);}
.xg-result{background:var(--xg-panel);border:1px solid var(--xg-rule);border-radius:3px;padding:.85rem 1.1rem;margin-bottom:1rem;}
.xg-result.block{border-left:4px solid var(--xg-red);}
.xg-result.protect{border-left:4px solid var(--xg-blue);}
.xg-result.ok{border-left:4px solid var(--xg-green);}
.xg-run-head{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;}
.xg-run-when{color:var(--xg-muted);font-size:.85rem;font-variant-numeric:tabular-nums;}
.xg-progress-note{font-size:.88rem;color:var(--xg-muted);margin:.3rem 0 .6rem;}
.xg-outbox{background:#0f1b24;color:#e6ebef;border-radius:3px;padding:.8rem 1rem;font-family:var(--xg-mono);font-size:.82rem;line-height:1.5;white-space:pre-wrap;max-height:320px;overflow:auto;}
.xg-perm{background:#FBF3E6;border:1px solid #E7C9A0;border-left:4px solid var(--xg-amber);border-radius:3px;padding:.9rem 1.1rem;font-size:.9rem;line-height:1.5;margin-bottom:1rem;}
</style>
"""

LOGO = (
    '<svg width="38" height="38" viewBox="0 0 38 38" aria-hidden="true">'
    '<rect x="1" y="5" width="32" height="32" rx="6" fill="#15232F"/>'
    '<path d="M10 14 L24 28 M24 14 L10 28" stroke="#FFFFFF" stroke-width="4" stroke-linecap="round"/>'
    '<circle cx="31" cy="7" r="5" fill="#1D7A4F" stroke="#F6F7F8" stroke-width="2.5"/>'
    "</svg>"
)

PAGES = {
    "overview": ":material/space_dashboard: Overview",
    "run": ":material/play_circle: Run detection",
    "events": ":material/list_alt: Event log",
    "blocked": ":material/block: Blocked IPs",
    "staff": ":material/badge: Staff actions",
    "model": ":material/insights: Model performance",
    "activity": ":material/history: Activity log",
}
# Pages an analyst or admin gets that a viewer does not; viewer sees the rest
RESTRICTED_PAGES = {"run": "run"}

PLOT_CONFIG = {
    "displaylogo": False,
    "modeBarButtonsToRemove": ["select2d", "lasso2d", "autoScale2d", "toggleSpikelines"],
    "toImageButtonOptions": {"format": "png", "scale": 2, "filename": "xguard_chart"},
}


# ---------------------------------------------------------------------------
# Small HTML helpers
# ---------------------------------------------------------------------------
def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def show_html(markup: str) -> None:
    """Render trusted HTML built in this file. Kept on one line so the
    markdown renderer treats it as a single HTML block."""
    st.markdown(" ".join(line.strip() for line in markup.splitlines()), unsafe_allow_html=True)


def led(state: str) -> str:
    return f'<span class="xg-led {state}" aria-hidden="true"></span>'


def cell_class(name: str) -> str:
    color = CLASS_COLOR.get(name, MUTED)
    return (f'<span class="xg-cls" style="color:{color}">'
            f'<span class="xg-swatch" style="background:{color}"></span>{esc(name)}</span>')


def cell_action(action: str) -> str:
    text = xd.ACTION_TEXT.get(action, action.title())
    return f'<span class="xg-tag">{led(ACTION_STATE.get(action, "idle"))}{esc(text)}</span>'


def cell_telegram(status: str) -> str:
    text = xd.TELEGRAM_TEXT.get(status, status.title())
    bad = " bad" if status == "failed" else ""
    return f'<span class="xg-tag{bad}">{led(TELEGRAM_STATE.get(status, "idle"))}{esc(text)}</span>'


def cell_ip(ip: str) -> str:
    return f'<span class="xg-mono xg-ip">{esc(ip)}</span>'


def html_table(headers: list[str], rows: list[list[str]], numeric=(), wrap=(), tight=()) -> None:
    def cls(i):
        names = []
        if i in numeric:
            names.append("num")
        if i in wrap:
            names.append("wrap")
        if i in tight:
            names.append("tight")
        return f' class="{" ".join(names)}"' if names else ""
    head = "".join(f"<th{cls(i)}>{esc(h)}</th>" for i, h in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f"<td{cls(i)}>{cell}</td>" for i, cell in enumerate(row)) + "</tr>"
        for row in rows
    )
    show_html(f'<div class="xg xg-table-wrap"><table class="xg-table"><thead><tr>{head}</tr></thead>'
              f"<tbody>{body}</tbody></table></div>")


def section(title: str, lede: str = "") -> None:
    extra = f'<div class="xg-lede">{esc(lede)}</div>' if lede else ""
    show_html(f'<div class="xg xg-section"><div class="xg-h2">{esc(title)}</div>{extra}</div>')


def note(text: str) -> None:
    show_html(f'<div class="xg xg-note">{esc(text)}</div>')


def band(items: list[tuple], size: str = "") -> None:
    """items are (number, label) or (number, label, flag_html)."""
    cells = []
    for item in items:
        number, label = item[0], item[1]
        flag = item[2] if len(item) > 2 and item[2] else ""
        cells.append(f'<div class="xg-band-item"><div class="xg-band-num">{number}</div>'
                     f'<div class="xg-band-label">{esc(label)}{flag}</div></div>')
    show_html(f'<div class="xg xg-band {size}">{"".join(cells)}</div>')


def show_table(df, height: int | None = None) -> None:
    kwargs = {"hide_index": True}
    if height:
        kwargs["height"] = height
    try:
        st.dataframe(df, width="stretch", **kwargs)
    except Exception:
        st.dataframe(df, use_container_width=True, **kwargs)


def plot(fig: go.Figure, key: str) -> None:
    try:
        st.plotly_chart(fig, key=key, theme=None, config=PLOT_CONFIG, width="stretch")
    except Exception:
        st.plotly_chart(fig, key=f"{key}_fallback", theme=None, config=PLOT_CONFIG,
                        use_container_width=True)


def toast(text: str, icon: str) -> None:
    try:
        st.toast(text, icon=icon)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Reading data (cached until a file changes)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False, max_entries=64)
def cached_csv(path: str, signature: tuple, columns: tuple):
    return xd.read_csv_safe(Path(path), columns)


def read_log(folder: Path, name: str, columns) -> tuple[pd.DataFrame, str | None]:
    path = folder / name
    return cached_csv(str(path), xd.file_signature(path), tuple(columns))


@st.cache_data(show_spinner=False, max_entries=8)
def cached_results(fyp: str, signature: tuple):
    return xd.load_results(Path(fyp))


def read_results() -> dict:
    files = [FYP_DIR / "results" / name for name in (
        "test_metrics.json", "confusion_matrix.csv", "before_after_comparison.csv", "tuning_results.csv")]
    files.append(FYP_DIR / "models" / "model_info.json")
    return cached_results(str(FYP_DIR), tuple(xd.file_signature(p) for p in files))


@dataclass
class Ctx:
    src: xd.LogSource
    now: datetime
    ref_now: datetime
    events: pd.DataFrame
    blocks: pd.DataFrame
    staff: pd.DataFrame
    history: pd.DataFrame
    summary: dict
    never_block: list
    problems: list


def load_context(src: xd.LogSource) -> Ctx:
    ev_raw, p1 = read_log(src.folder, xd.EVENT_FILE, xd.EVENT_COLUMNS)
    bl_raw, p2 = read_log(src.folder, xd.BLOCK_FILE, xd.BLOCK_COLUMNS)
    sa_raw, p3 = read_log(src.folder, xd.STAFF_FILE, xd.STAFF_COLUMNS)
    events = xd.prepare_events(ev_raw)
    blocks = xd.prepare_blocks(bl_raw)
    staff = xd.prepare_staff(sa_raw)
    now = datetime.now()
    if src.live:
        ref_now = now
    else:
        last = events["time"].dropna().max() if len(events) else None
        ref_now = src.saved_at or (last.to_pydatetime() if last is not None and pd.notna(last) else now)
    never_block, p4 = xd.read_never_block(FYP_DIR / "config" / "never_block_list.txt")
    return Ctx(
        src=src, now=now, ref_now=ref_now, events=events, blocks=blocks, staff=staff,
        history=xd.build_block_history(events, blocks, staff, ref_now),
        summary=xd.summarize(events, blocks), never_block=never_block,
        problems=[p for p in (p1, p2, p3, p4) if p],
    )


def announce_new_events(ctx: Ctx) -> None:
    """Pop a toast for each new decision while watching the live logs."""
    if not ctx.src.live:
        return
    count = len(ctx.events)
    seen = st.session_state.get("xg_seen_events")
    st.session_state["xg_seen_events"] = count
    if seen is None or count == seen:
        return
    if count < seen:
        toast("The logs were reset. Showing the new run.", "🧹")
        return
    icons = {"BLOCKED": "🚫", "ALREADY_BLOCKED": "🔁", "NOT_BLOCKED_NEVER_BLOCK_LIST": "🛡️", "NO_ACTION": "✅"}
    for _, e in ctx.events.iloc[seen:].tail(3).iterrows():
        text = f"{e['predicted']} from {e['source_ip']}, {xd.ACTION_TEXT.get(e['action'], e['action']).lower()}"
        if e["telegram"] == "failed":
            text += ", alert failed"
        toast(text, icons.get(e["action"], "🔎"))


# ---------------------------------------------------------------------------
# Shared page parts
# ---------------------------------------------------------------------------
def page_header(title: str, lede: str, ctx: Ctx) -> None:
    last = ctx.summary["last_time"]
    if ctx.src.live:
        line = f"{led('ok')}Live"
        sub = f"Refreshed {ctx.now:%H:%M:%S}"
        if last is not None:
            sub += f", last decision {xd.fmt_ago(last, ctx.now)}"
    else:
        line = f"{led('idle')}Archived run"
        sub = f"Saved {xd.fmt_dt(ctx.src.saved_at)}" if ctx.src.saved_at else "Not live"
    show_html(
        f'<div class="xg xg-head"><div><div class="xg-h1">{esc(title)}</div>'
        f'<div class="xg-lede">{esc(lede)}</div></div>'
        f'<div class="xg-status"><div class="xg-status-line">{line}</div>'
        f'<div class="xg-status-sub">{esc(sub)}</div></div></div>'
    )
    for problem in ctx.problems:
        st.warning(problem)


def empty_events(ctx: Ctx) -> None:
    if ctx.src.live:
        show_html(
            '<div class="xg xg-empty"><div class="xg-h2">No decisions yet</div>'
            '<div class="xg-lede">Start a run from the Run detection page, or run a demo file in Kali. '
            'Decisions appear here within a few seconds.</div></div>'
        )
        st.code("cd ~/fyp\nsudo venv/bin/python ids_controller.py demo/demo_main_1.csv", language="bash")
    else:
        show_html('<div class="xg xg-empty"><div class="xg-h2">This archived run has no decisions</div>'
                  '<div class="xg-lede">Choose another run in the sidebar, or switch back to the live logs.</div></div>')


def decision_trace(e: pd.Series, title: str, ctx: Ctx) -> None:
    """The latest (or chosen) decision drawn as the system's real pipeline,
    in the order the controller runs it. Blocking comes before alerting."""
    stages_html = []
    for s in xd.decision_stages(e):
        color = f' style="color:{CLASS_COLOR[s.color_class]}"' if s.color_class in CLASS_COLOR else ""
        mono = " xg-mono" if s.mono else ""
        stages_html.append(
            f'<div class="xg-stage"><div class="xg-stage-name">{led(s.state)}{esc(s.name)}</div>'
            f'<div class="xg-stage-value{mono}"{color}>{esc(s.value)}</div>'
            f'<div class="xg-stage-note">{esc(s.note)}</div></div>'
        )
    is_new = (ctx.src.live and pd.notna(e["time"])
              and (pd.Timestamp(ctx.now) - e["time"]).total_seconds() < 120)
    new_tag = '<span class="xg-new">New</span>' if is_new else ""
    show_html(
        f'<div class="xg xg-trace {xd.outcome(e)}">'
        f'<div class="xg-trace-top"><div class="xg-trace-title">{esc(title)}{new_tag}</div>'
        f'<div class="xg-trace-when">{esc(xd.fmt_dt(e["time"]))}</div></div>'
        f'<div class="xg-stages">{"".join(stages_html)}</div>'
        f'<div class="xg-trace-summary"><span>{esc(xd.decision_summary(e))}</span></div></div>'
    )


def decisions_table(events: pd.DataFrame) -> None:
    rows = []
    for _, e in events.iloc[::-1].iterrows():
        rows.append([
            f'<span title="{esc(xd.fmt_dt(e["time"]))}">{esc(xd.fmt_short(e["time"]))}</span>',
            esc(e["scenario"]),
            cell_ip(e["source_ip"]),
            cell_class(e["predicted"]),
            esc(xd.fmt_conf(e["confidence"])),
            esc(xd.fmt_ms(e["prediction_ms"])),
            cell_action(e["action"]),
            cell_telegram(e["telegram"]),
        ])
    html_table(["Time", "Scenario", "Source address", "Predicted class", "Confidence",
                "Prediction time", "Firewall", "Telegram"], rows, numeric=(4, 5))


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
def style_figure(fig: go.Figure, height: int, legend: bool = False) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=12, t=40 if legend else 10, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_STACK, size=13, color=INK),
        hoverlabel=dict(bgcolor="#FFFFFF", bordercolor=RULE, font=dict(family=FONT_STACK, size=13, color=INK)),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
                    font=dict(size=12, color=MUTED), bgcolor="rgba(0,0,0,0)"),
    )
    axis = dict(automargin=True, showgrid=True, gridcolor=GRID, zeroline=False, showline=True, linecolor=RULE,
                tickfont=dict(color=MUTED, size=12), title_font=dict(color=MUTED, size=12))
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    return fig


SYMBOLS = {
    "BLOCKED": "x",
    "ALREADY_BLOCKED": "x-open",
    "NOT_BLOCKED_NEVER_BLOCK_LIST": "diamond-open",
    "NO_ACTION": "circle",
}


def chart_activity(events: pd.DataFrame) -> go.Figure:
    data = events.dropna(subset=["time"])
    lanes = list(xd.CLASS_ORDER) + sorted(c for c in data["predicted"].unique() if c not in xd.CLASS_ORDER)
    fig = go.Figure()
    if data.empty:
        return style_figure(fig, 280)
    t_min, t_max = data["time"].min(), data["time"].max()
    pad = max((t_max - t_min) * 0.06, pd.Timedelta(seconds=15))
    # Invisible points so all four class lanes are always drawn
    fig.add_trace(go.Scatter(x=[t_min] * len(lanes), y=lanes, mode="markers",
                             marker=dict(opacity=0), hoverinfo="skip", showlegend=False))
    actions = list(SYMBOLS) + [a for a in data["action"].unique() if a not in SYMBOLS]
    for action in actions:
        part = data[data["action"] == action]
        if part.empty:
            continue
        name = xd.ACTION_TEXT.get(action, action.title())
        colors = [CLASS_COLOR.get(c, GREY) for c in part["predicted"]]
        custom = [[ip, sc, name, xd.TELEGRAM_TEXT.get(tg, tg), xd.fmt_dt(t)]
                  for ip, sc, tg, t in zip(part["source_ip"], part["scenario"], part["telegram"], part["time"])]
        fig.add_trace(go.Scatter(
            x=part["time"], y=part["predicted"], mode="markers", name=name, showlegend=False,
            marker=dict(symbol=SYMBOLS.get(action, "circle"), size=17, color=colors,
                        line=dict(width=2.5, color=colors)),
            customdata=custom,
            hovertemplate=("<b>%{y}</b> from %{customdata[0]}<br>%{customdata[1]}<br>"
                           "Firewall %{customdata[2]}, Telegram %{customdata[3]}<br>%{customdata[4]}<extra></extra>"),
        ))
        # Legend entry in ink, so the legend explains the shape, not the colour
        fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name=name, hoverinfo="skip",
                                 marker=dict(symbol=SYMBOLS.get(action, "circle"), size=12, color=INK,
                                             line=dict(width=2, color=INK))))
    style_figure(fig, 300, legend=True)
    fig.update_yaxes(type="category", categoryorder="array", categoryarray=lanes, showgrid=True)
    fig.update_xaxes(range=[t_min - pad, t_max + pad], showgrid=False)
    return fig


def chart_block_timeline(history: pd.DataFrame, ref_now: datetime, now_label: str = "now") -> go.Figure | None:
    rows = history[history["status"].isin(["Blocked", "Released"])].dropna(subset=["blocked_at"]).copy()
    if rows.empty:
        return None
    ref = pd.Timestamp(ref_now)
    rows["end"] = rows["released_at"].where(rows["status"].eq("Released"), ref)
    rows["end"] = rows["end"].fillna(ref)
    span_ms = max((rows["end"].max() - rows["blocked_at"].min()).total_seconds() * 1000, 60_000)
    duration = ((rows["end"] - rows["blocked_at"]).dt.total_seconds() * 1000).clip(lower=span_ms * 0.006)
    active = rows["status"].eq("Blocked")
    lanes = list(dict.fromkeys(rows["ip"]))
    custom = [[r.attack, xd.fmt_dt(r.blocked_at),
               ("still blocked" if r.status == "Blocked" else f"released {xd.fmt_dt(r.released_at)} by {r.released_by}"),
               xd.fmt_duration(r.seconds)]
              for r in rows.itertuples()]
    positions = ["inside" if d >= span_ms * 0.15 else "outside" for d in duration]
    fig = go.Figure(go.Bar(
        y=rows["ip"], x=duration, base=rows["blocked_at"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        orientation="h", width=0.5,
        marker=dict(color=[RED if a else GREY for a in active], line=dict(width=0)),
        text=rows["attack"], textposition=positions, insidetextanchor="start", textangle=0,
        constraintext="none", insidetextfont=dict(color="#FFFFFF", size=12),
        outsidetextfont=dict(color=INK, size=12), cliponaxis=False,
        customdata=custom,
        hovertemplate="<b>%{y}</b>, %{customdata[0]}<br>Blocked %{customdata[1]}<br>%{customdata[2]}<br>Time blocked %{customdata[3]}<extra></extra>",
    ))
    style_figure(fig, 100 + 52 * len(lanes))
    fig.update_layout(barmode="overlay", bargap=0.35, margin=dict(l=8, r=12, t=30, b=8))
    fig.update_xaxes(type="date", showgrid=True)
    fig.update_yaxes(type="category", categoryorder="array", categoryarray=lanes[::-1],
                     showgrid=False, tickfont=dict(family="Atkinson Hyperlegible Mono, Consolas, monospace", color=INK, size=13))
    fig.add_shape(type="line", x0=ref, x1=ref, y0=0, y1=1, yref="paper", line=dict(color=INK, width=1, dash="dot"))
    fig.add_annotation(x=ref, y=1, yref="paper", text=now_label, showarrow=False,
                       yanchor="bottom", font=dict(size=11, color=MUTED))
    return fig


def chart_confusion(cm: pd.DataFrame) -> go.Figure:
    labels = [c for c in xd.CLASS_ORDER if c in cm.index] + [c for c in cm.index if c not in xd.CLASS_ORDER]
    cm = cm.reindex(index=labels, columns=labels, fill_value=0)
    pct = cm.div(cm.sum(axis=1).replace(0, 1), axis=0) * 100
    fig = go.Figure(go.Heatmap(
        z=pct.values, x=labels, y=labels, zmin=0, zmax=100, showscale=False, xgap=3, ygap=3,
        colorscale=[[0, "#F2F5F8"], [0.001, "#E4EBF2"], [0.15, "#C2D1E0"], [0.6, "#5E7EA1"], [1, "#1E3A5F"]],
        customdata=cm.values,
        hovertemplate="Actual %{y}, predicted %{x}<br>%{customdata:,} records, %{z:.2f}% of the row<extra></extra>",
    ))
    for i, actual in enumerate(labels):
        for j, predicted in enumerate(labels):
            value, share = int(cm.iloc[i, j]), float(pct.iloc[i, j])
            fig.add_annotation(
                x=predicted, y=actual, showarrow=False,
                text=f"<b>{value:,}</b><br>{share:.2f}%",
                font=dict(size=13, color="#FFFFFF" if share >= 55 else INK),
            )
    style_figure(fig, 380)
    fig.update_xaxes(side="top", showgrid=False, showline=False, ticks="", title_text="Predicted class",
                     tickfont=dict(color=INK, size=12))
    fig.update_yaxes(autorange="reversed", showgrid=False, showline=False, ticks="", title_text="Actual class",
                     tickfont=dict(color=INK, size=12))
    fig.update_layout(margin=dict(l=8, r=8, t=30, b=8))
    return fig


PAYLOAD_ORDER = [
    "Web Attack F1", "Web Attack recall", "Web Attack precision",
    "Macro F1", "Macro recall", "Macro precision", "Accuracy",
    "BENIGN F1", "DoS Hulk F1", "PortScan F1",
]


def chart_payload(ba: pd.DataFrame) -> go.Figure | None:
    if not {"Before rule", "After rule"}.issubset(ba.columns):
        return None
    metrics = [m for m in PAYLOAD_ORDER if m in ba.index]
    metrics += [m for m in ba.index if m not in metrics and "records" not in m.lower()]
    if not metrics:
        return None
    before = [float(ba.loc[m, "Before rule"]) for m in metrics]
    after = [float(ba.loc[m, "After rule"]) for m in metrics]
    colors = [VIOLET if m.startswith("Web Attack") else INK for m in metrics]
    places = [4 if min(b, a) >= 0.99 else 3 for b, a in zip(before, after)]
    seg_x, seg_y = [], []
    for m, b, a in zip(metrics, before, after):
        seg_x += [b, a, None]
        seg_y += [m, m, None]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=seg_x, y=seg_y, mode="lines", line=dict(color="#AEB8C1", width=3),
                             hoverinfo="skip", showlegend=False))
    fig.add_trace(go.Scatter(
        x=before, y=metrics, mode="markers+text", name="Before payload rule",
        marker=dict(symbol="circle-open", size=12, color=GREY, line=dict(width=2.5, color=GREY)),
        text=[f"{b:.{d}f}" for b, d in zip(before, places)],
        textposition=["middle left" if b <= a else "middle right" for b, a in zip(before, after)],
        textfont=dict(color=MUTED, size=12),
        hovertemplate="%{y}<br>Before %{x:.4f}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=after, y=metrics, mode="markers+text", name="After payload rule",
        marker=dict(symbol="circle", size=13, color=colors),
        text=[f"{a:.{d}f}" for a, d in zip(after, places)],
        textposition=["middle right" if b <= a else "middle left" for b, a in zip(before, after)],
        textfont=dict(color=INK, size=12),
        hovertemplate="%{y}<br>After %{x:.4f}<extra></extra>",
    ))
    style_figure(fig, 70 + 36 * len(metrics), legend=True)
    fig.update_xaxes(range=[-0.1, 1.14], tickvals=[0, 0.25, 0.5, 0.75, 1.0], showgrid=True)
    fig.update_yaxes(type="category", categoryorder="array", categoryarray=metrics[::-1], showgrid=False,
                     tickfont=dict(color=INK, size=12))
    return fig


def chart_speed(events: pd.DataFrame) -> go.Figure | None:
    data = events.dropna(subset=["prediction_ms"])
    if data.empty:
        return None
    labels = [f"#{n} {s}" for n, s in zip(data["event_no"], data["scenario"])]
    show_text = len(data) <= 30
    fig = go.Figure(go.Bar(
        x=labels, y=data["prediction_ms"],
        marker=dict(color=[CLASS_COLOR.get(c, GREY) for c in data["predicted"]]),
        text=[f"{v:.1f}" for v in data["prediction_ms"]] if show_text else None,
        textposition="outside", cliponaxis=False, textfont=dict(color=MUTED, size=11),
        hovertemplate="%{x}<br>%{y:.2f} ms<extra></extra>",
    ))
    median = float(data["prediction_ms"].median())
    style_figure(fig, 280)
    fig.add_shape(type="line", x0=0, x1=1, xref="paper", y0=median, y1=median,
                  line=dict(color=INK, width=1, dash="dot"))
    fig.add_annotation(x=1, xref="paper", y=1, yref="paper", text=f"Dotted line, median {median:.2f} ms",
                       showarrow=False, xanchor="right", yanchor="bottom", font=dict(size=12, color=MUTED))
    fig.update_xaxes(showgrid=False, type="category")
    fig.update_yaxes(title_text="Prediction time (ms)", rangemode="tozero")
    fig.update_layout(margin=dict(l=8, r=12, t=40, b=8))
    return fig


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_overview(ctx: Ctx) -> None:
    page_header("Overview", "What XGuard decided most recently, and what is blocked right now.", ctx)
    events, s = ctx.events, ctx.summary
    if events.empty:
        empty_events(ctx)
    else:
        decision_trace(events.iloc[-1], "Latest decision", ctx)

    flag = (f'<span class="xg-band-flag">{led("block")}{s["alerts_failed"]} failed</span>'
            if s["alerts_failed"] else "")
    median = f'{s["median_ms"]:.2f}<small>ms</small>' if s["median_ms"] is not None else "n/a"
    blocked_label = "Blocked right now" if ctx.src.live else "Blocked at end of run"
    band([
        (f'{s["records"]:,}', "Records checked"),
        (f'{s["attacks"]:,}', "Attacks detected"),
        (f'{s["blocked_now"]:,}', blocked_label),
        (f'{s["alerts_sent"]:,}', "Alerts sent", flag),
        (median, "Median prediction time"),
    ])
    if events.empty:
        return

    left, right = st.columns([2.1, 1], gap="large")
    with left:
        section("Activity", "Every replayed record, placed on its predicted class. The mark shows what the firewall did.")
        plot(chart_activity(events), "chart_activity")
    with right:
        section(blocked_label, "Addresses held in the FYP_IDS_BLOCK chain until staff review them.")
        current = ctx.history[ctx.history["status"].eq("Blocked")]
        if current.empty:
            show_html('<div class="xg xg-list"><div class="xg-list-empty">No addresses are blocked. '
                      'Every earlier block has been released.</div></div>')
        else:
            items = []
            for r in current.itertuples():
                color = CLASS_COLOR.get(r.attack, MUTED)
                items.append(
                    f'<div class="xg-list-row" style="border-left-color:{color}">'
                    f'<div class="xg-list-main">{cell_ip(r.ip)}{cell_class(r.attack)}</div>'
                    f'<div class="xg-list-sub">Since {esc(xd.fmt_short(r.blocked_at))}, '
                    f'blocked for {esc(xd.fmt_duration(r.seconds))}</div></div>'
                )
            show_html(f'<div class="xg xg-list">{"".join(items)}</div>')

    shown = events.tail(8)
    section("Recent decisions", f"The latest {len(shown)} decisions, newest first. The full list is in the event log.")
    decisions_table(shown)


def page_events(ctx: Ctx) -> None:
    page_header("Event log", "Every record XGuard has checked, newest first. Filter it, export it, "
                             "or open a decision to see each step.", ctx)
    events = ctx.events
    if events.empty:
        empty_events(ctx)
        return

    present = list(dict.fromkeys(events["predicted"]))
    classes = [c for c in xd.CLASS_ORDER if c in present] + [c for c in present if c not in xd.CLASS_ORDER]
    actions = list(dict.fromkeys(events["action"]))
    statuses = list(dict.fromkeys(events["telegram"]))
    addresses = sorted(events["source_ip"].unique())

    c1, c2, c3, c4 = st.columns(4)
    pick_class = c1.multiselect("Predicted class", classes, placeholder="All classes", key="f_class")
    pick_action = c2.multiselect("Firewall action", actions, placeholder="All actions", key="f_action",
                                 format_func=lambda a: xd.ACTION_TEXT.get(a, a.title()))
    pick_tg = c3.multiselect("Telegram alert", statuses, placeholder="All alerts", key="f_tg",
                             format_func=lambda t: xd.TELEGRAM_TEXT.get(t, t.title()))
    pick_ip = c4.selectbox("Source address", ["All addresses"] + addresses, key="f_ip")
    runs = xd.run_order(events)
    pick_run = st.selectbox("Run or demo file", ["__all__"] + runs, key="f_run",
                            format_func=lambda f: "All runs and demo files" if f == "__all__"
                            else f"{xd.run_label(f)}  ({f})" if xd.run_kind(f) else f)

    view = events
    if pick_run != "__all__":
        view = view[view["demo_file"] == pick_run]
    if pick_class:
        view = view[view["predicted"].isin(pick_class)]
    if pick_action:
        view = view[view["action"].isin(pick_action)]
    if pick_tg:
        view = view[view["telegram"].isin(pick_tg)]
    if pick_ip != "All addresses":
        view = view[view["source_ip"] == pick_ip]
    view = view.iloc[::-1]

    info, download, summary = st.columns([2, 1, 1])
    info.caption(f"Showing {len(view)} of {len(events)} decisions")
    export = view.iloc[::-1][list(xd.EVENT_COLUMNS)].copy()
    stem = Path(pick_run).stem if pick_run != "__all__" else "xguard_events"
    download.download_button(
        "Download as CSV", data=export.to_csv(index=False).encode("utf-8"),
        file_name=f"{stem}_decisions.csv", mime="text/csv", key="dl_events",
    )
    if pick_run != "__all__" and len(view):
        summary.download_button(
            "Download run report", data=xd.run_report_text(pick_run, view.iloc[::-1], run_starter(pick_run)),
            file_name=f"{stem}_report.txt", mime="text/plain", key="dl_run_report",
        )

    table = pd.DataFrame({
        "No.": view["event_no"],
        "Time": view["time"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "Scenario": view["scenario"],
        "Source address": view["source_ip"],
        "Actual class": view["actual"],
        "Predicted class": view["predicted"],
        "Confidence": [xd.fmt_conf(c) for c in view["confidence"]],
        "Prediction ms": view["prediction_ms"],
        "Firewall": [xd.ACTION_TEXT.get(a, a.title()) for a in view["action"]],
        "Telegram": [xd.TELEGRAM_TEXT.get(t, t.title()) for t in view["telegram"]],
        "Demo file": view["demo_file"],
        "Test row": view["test_row"],
    })

    def color_class(value):
        return f"color: {CLASS_COLOR.get(value, INK)}; font-weight: 700"

    def color_firewall(value):
        tone = {"Blocked": RED, "Already blocked": RED, "Protected, not blocked": BLUE}.get(value, MUTED)
        return f"color: {tone}"

    def color_telegram(value):
        return {"Failed": f"color: {RED}; font-weight: 700", "Sent": f"color: {GREEN}"}.get(value, f"color: {MUTED}")

    height = min(35 * (len(table) + 1) + 3, 560)
    try:
        styled = (table.style
                  .map(color_class, subset=["Actual class", "Predicted class"])
                  .map(color_firewall, subset=["Firewall"])
                  .map(color_telegram, subset=["Telegram"])
                  .format({"Prediction ms": "{:.2f}"}, na_rep=""))
        show_table(styled, height=height)
    except Exception:
        show_table(table, height=height)

    section("Explain a decision", "Pick any decision to see the steps XGuard took, in the order it took them.")
    labels = {int(r.event_no): xd.event_label(r) for _, r in events.iterrows()}
    options = list(labels)[::-1]
    chosen = st.selectbox("Decision", options, format_func=lambda n: labels.get(n, f"#{n}"),
                          key="f_explain", label_visibility="collapsed")
    if chosen in labels:
        row = events[events["event_no"] == chosen].iloc[0]
        decision_trace(row, f"Decision #{chosen}", ctx)


def page_blocked(ctx: Ctx) -> None:
    page_header("Blocked IPs", "Which addresses are blocked, for how long, who released them, and which "
                               "addresses XGuard will never block. Analysts and admins can release an address below.", ctx)
    hist = ctx.history
    current = hist[hist["status"].eq("Blocked")]
    released = hist[hist["status"].eq("Released")]
    blocked_label = "Blocked right now" if ctx.src.live else "Blocked at end of run"
    band([
        (f"{len(current)}", blocked_label),
        (f"{len(released)}", "Released by staff"),
        (f"{len(hist)}", "Blocks in this log"),
        (f"{len(ctx.never_block)}", "Protected addresses"),
    ], size="four")

    section(blocked_label, "Each address stays blocked until a staff member reviews and releases it. "
                           "There is no automatic unblock.")
    if current.empty:
        show_html('<div class="xg xg-list"><div class="xg-list-empty">No addresses are blocked.</div></div>')
    else:
        by_ip = ctx.blocks.set_index("ip") if not ctx.blocks.empty else None
        fw = firewall_status_now() if ctx.src.live else None
        rows, inactive = [], []
        for r in current.itertuples():
            source = ""
            if by_ip is not None and r.ip in by_ip.index:
                b = by_ip.loc[r.ip]
                b = b.iloc[0] if isinstance(b, pd.DataFrame) else b
                row_no = f", row {int(b['test_row'])}" if pd.notna(b["test_row"]) else ""
                source = f"{b['demo_file']}{row_no}"
            if fw is None:
                state = '<span class="xg-muted">Not checked</span>' if ctx.src.live else '<span class="xg-muted">Archived</span>'
            elif fw.get(r.ip):
                state = f'<span class="xg-tag">{led("block")}Active</span>'
            else:
                state = f'<span class="xg-tag bad">{led("idle")}Not active</span>'
                inactive.append(r.ip)
            rows.append([cell_ip(r.ip), cell_class(r.attack), esc(xd.fmt_dt(r.blocked_at)),
                         esc(xd.fmt_duration(r.seconds)), state, f'<span class="xg-muted">{esc(source)}</span>'])
        html_table(["Address", "Attack", "Blocked at", "Time blocked", "In firewall", "Triggered by"], rows,
                   numeric=(3,))
        if inactive:
            note(f"{len(inactive)} recorded block(s) are not active in iptables, usually because Kali restarted. "
                 "They come back automatically on the next detection run, or an analyst can restore them now "
                 "at the bottom of this page.")

    fig = chart_block_timeline(hist, ctx.ref_now, "now" if ctx.src.live else "run saved")
    if fig is not None:
        section("Block timeline", "Each bar is one block, from the moment it was added until staff released it. "
                                  "Red bars are still active, grey bars were released.")
        plot(fig, "chart_blocks")

    if not hist.empty:
        section("Block history", "Every block in this log, oldest first.")
        rows = []
        status_led = {"Blocked": "block", "Released": "idle", "Cleared": "idle"}
        status_text = {"Blocked": "Still blocked", "Released": "Released", "Cleared": "Cleared without a staff record"}
        for r in hist.itertuples():
            released = ""
            if pd.notna(r.released_at):
                released = esc(xd.fmt_short(r.released_at) + (f" by {r.released_by}" if r.released_by else ""))
                if r.note:
                    released += f'<div class="xg-small xg-muted">Note, {esc(r.note)}</div>'
            rows.append([
                cell_ip(r.ip), cell_class(r.attack), esc(xd.fmt_short(r.blocked_at)),
                f'<span class="xg-tag">{led(status_led.get(r.status, "idle"))}{esc(status_text.get(r.status, r.status))}</span>',
                released, esc(xd.fmt_duration(r.seconds)),
            ])
        html_table(["Address", "Attack", "Blocked at", "Status", "Released", "Time blocked"],
                   rows, numeric=(5,), wrap=(4,))

    section("Never-block list", "XGuard never adds a firewall rule for these addresses, so it cannot cut off "
                                "its own machine or its gateway. Attacks from them still raise an alert.")
    entries = rn.never_block_entries(FYP_DIR)
    if entries:
        rows = []
        for e in entries:
            what = xd.NEVER_BLOCK_ROLES.get(e["ip"]) if e["core"] else None
            kind = (f'<span class="xg-tag">{led("info")}Built in</span>' if e["core"]
                    else f'<span class="xg-tag">{led("protect")}Added by an admin</span>')
            rows.append([cell_ip(e["ip"]), esc(what or e["note"] or "Protected address"), kind])
        html_table(["Address", "What it is", "Type"], rows, wrap=(1,))
    else:
        note("No never-block list was found in config/never_block_list.txt.")

    section("Releasing from the terminal")
    note("Staff can also release an address in Kali with unblock_ip.py, which asks for their name and a "
         "review note and records both in staff_actions.csv, the same as the control below.")
    st.code("cd ~/fyp\nsudo venv/bin/python unblock_ip.py --list\nsudo venv/bin/python unblock_ip.py 192.168.56.150",
            language="bash")


def page_staff(ctx: Ctx) -> None:
    page_header("Staff actions", "Every release is done by a named staff member with a review note, "
                                 "so each unblock can be traced.", ctx)
    staff = ctx.staff
    releases = staff[staff["action"].eq("UNBLOCKED")]
    median = releases["blocked_seconds"].dropna().median() if len(releases) else None
    band([
        (f"{len(releases)}", "Releases"),
        (f"{staff['staff'].replace('', pd.NA).dropna().nunique()}", "Staff members"),
        (esc(xd.fmt_duration(median)) if median is not None and pd.notna(median) else "n/a",
         "Median time blocked before release"),
    ], size="three")

    section("Audit trail", "Newest first, exactly as written by unblock_ip.py.")
    if staff.empty:
        show_html('<div class="xg xg-empty"><div class="xg-h2">No staff actions yet</div>'
                  '<div class="xg-lede">When a staff member releases an address, the action and their review '
                  'note appear here.</div></div>')
    else:
        rows = []
        for r in staff.iloc[::-1].itertuples():
            rows.append([
                esc(xd.fmt_short(r.time)), cell_ip(r.ip), esc(r.action.title()), esc(r.staff),
                esc(r.note), esc(xd.fmt_short(r.blocked_time)), cell_class(r.attack_name),
                esc(xd.fmt_duration(r.blocked_seconds)),
            ])
        html_table(["Released at", "Address", "Action", "Staff", "Review note", "Blocked at",
                    "Attack", "Time blocked"], rows, numeric=(7,), wrap=(4,))

    section("How a release works")
    note("The staff member checks the alert, then releases the address with their name and a short review "
         "note, either from the control on the Blocked IPs page or in the terminal. The rule is removed from "
         "FYP_IDS_BLOCK, the release is written to the audit log, and a Telegram notice tells the team.")
    st.code("cd ~/fyp\nsudo venv/bin/python unblock_ip.py --list\nsudo venv/bin/python unblock_ip.py 192.168.56.1",
            language="bash")


MODEL_SETTINGS = [
    ("Algorithm", "XGBoost, four class classifier"),
    ("Trees", "175, chosen by early stopping on a validation set"),
    ("Maximum depth", "6"),
    ("Learning rate", "0.1"),
    ("Tree method", "hist"),
    ("Class weights", "Not used, balanced weights made Web Attack worse"),
    ("Training records", "1,578,771 (70% stratified split, seed 42)"),
    ("Test records", "676,617 (30%, used once for the final scores)"),
]
FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
    "Packet Length Mean", "Packet Length Std", "Fwd IAT Mean", "Bwd IAT Mean",
]


def page_model(ctx: Ctx) -> None:
    results = read_results()
    m = results["metrics"]
    total = int(m.get("test_records", 0)) if m else 0
    lede = (f"How the final XGBoost model scored on {total:,} test records it never saw during training."
            if total else "Scores of the final XGBoost model on the held out test set.")
    page_header("Model performance", lede, ctx)
    for problem in results["problems"]:
        st.warning(problem)
    if not m:
        note("results/test_metrics.json was not found, so the scores cannot be shown.")
        return

    band([
        (f'{m.get("accuracy", 0) * 100:.2f}<small>%</small>', "Accuracy"),
        (f'{m.get("macro_f1", 0):.4f}', "Macro F1"),
        (f'{m.get("macro_precision", 0):.4f}', "Macro precision"),
        (f'{m.get("macro_recall", 0):.4f}', "Macro recall"),
        (f"{total:,}", "Test records"),
    ])

    cm = results["confusion"]
    extras = xd.confusion_extras(cm) if cm is not None else None
    left, right = st.columns([1.05, 1], gap="large")
    with left:
        section("Results per class", "Precision is how often an alert for the class was right. "
                                     "Recall is how many records of the class were caught.")
        rows = []
        per_class = m.get("per_class", {})
        names = [c for c in xd.CLASS_ORDER if c in per_class] + [c for c in per_class if c not in xd.CLASS_ORDER]
        for cls in names:
            v = per_class[cls]
            wrong = ""
            if extras is not None and xd.norm_label(cls) in extras.index:
                wrong = f'{int(extras.loc[xd.norm_label(cls), "misclassified"]):,}'
            rows.append([cell_class(xd.norm_label(cls)), f'{v.get("precision", 0):.4f}', f'{v.get("recall", 0):.4f}',
                         f'{v.get("f1", 0):.4f}', f'{int(v.get("support", 0)):,}', wrong])
        html_table(["Class", "Precision", "Recall", "F1", "Test records", "Misclassified"], rows,
                   numeric=(1, 2, 3, 4, 5))
        findings = []
        if cm is not None and "Web Attack" in cm.index:
            caught, size = int(cm.loc["Web Attack", "Web Attack"]), int(cm.loc["Web Attack"].sum())
            findings.append(f"Web Attack is the hardest class. {caught} of {size} test records were detected, "
                            f"so each miss moves its recall by about {100 / size:.1f} points.")
        worst = xd.biggest_error(cm) if cm is not None else None
        if worst:
            actual, predicted, count = worst
            share = count / max(int(cm.loc[actual].sum()), 1) * 100
            findings.append(f"The largest error is {count:,} {actual} records predicted as {predicted}, "
                            f"about {share:.2f}% of {actual}. These would appear as false alerts.")
        for text in findings:
            note(text)
    with right:
        section("Confusion matrix", "Rows are the true class and columns are the prediction. "
                                    "Shading shows the share of each row.")
        if cm is not None:
            plot(chart_confusion(cm), "chart_confusion")
        else:
            note("results/confusion_matrix.csv was not found.")

    ba = results["before_after"]
    if ba is not None:
        lede = ("Many Web Attack rows in CICIDS2017 carry no payload, so they look exactly like normal traffic. "
                "Following Engelen, Rimmer and Joosen (2021), those rows were relabelled as BENIGN before training.")
        row = next((i for i in ba.index if "records" in i.lower()), None)
        if row is not None and {"Before rule", "After rule"}.issubset(ba.columns):
            lede += (f" Web Attack test records went from {int(ba.loc[row, 'Before rule']):,} "
                     f"to {int(ba.loc[row, 'After rule']):,}.")
        section("Effect of the payload rule", lede)
        fig = chart_payload(ba)
        if fig is not None:
            plot(fig, "chart_payload")

    section("Prediction speed", "Time for the model to classify a record. Telegram and iptables are not "
                                "included, as defined in the proposal.")
    s = ctx.summary
    live_median = f'{s["median_ms"]:.2f}<small>ms</small>' if s["median_ms"] is not None else "n/a"
    band([
        (f'{m.get("batch_avg_microseconds_per_record", 0):.2f}<small>µs</small>', "Per record, whole test set at once"),
        (f'{m.get("one_by_one_mean_ms", 0):.2f}<small>ms</small>', "Mean, one record at a time"),
        (f'{m.get("one_by_one_median_ms", 0):.2f}<small>ms</small>', "Median, one record at a time"),
        (f'{m.get("one_by_one_max_ms", 0):.2f}<small>ms</small>', "Slowest single record"),
        (live_median, "Median in the logged demo runs"),
    ])
    fig = chart_speed(ctx.events)
    if fig is not None:
        note("Demo timings come from the controller and include some extra Python work, so they sit a little "
             "above the test set figures. The official speed is the test set measurement above.")
        plot(fig, "chart_speed")

    with st.expander("Model settings, features and tuning"):
        html_table(["Setting", "Value"], [[esc(k), esc(v)] for k, v in MODEL_SETTINGS], wrap=(1,))
        section("The 12 flow features", "Source and destination IP addresses are not model inputs.")
        html_table(["No.", "Feature"], [[str(i), esc(f)] for i, f in enumerate(FEATURES, start=1)],
                   numeric=(0,), tight=(0,))
        if results["tuning"] is not None:
            section("Grid search on the validation set", "Four settings were trained and scored on the validation "
                                                         "set. The highest macro F1 was chosen.")
            tuning_table(results["tuning"])
        if results["model_info"] is not None:
            section("Saved model information", "Fields stored in models/model_info.json.")
            info_table(results["model_info"])


TUNING_NAMES = {
    "trees": "Trees", "best_trees": "Trees", "macro_f1": "Macro F1", "val_macro_f1": "Macro F1",
    "benign_f1": "BENIGN F1", "dos_hulk_f1": "DoS Hulk F1", "portscan_f1": "PortScan F1",
    "web_attack_f1": "Web Attack F1", "val_web_attack_f1": "Web Attack F1", "train_seconds": "Time (s)",
}


def fmt_cell(column: str, value) -> str:
    if isinstance(value, str):
        return value
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if pd.isna(number):
        return ""
    name = column.lower()
    if "macro" in name:
        return f"{number:.5f}"  # depth 6 and depth 10 only differ in the fifth decimal
    if any(word in name for word in ("f1", "precision", "recall", "accuracy")):
        return f"{number:.4f}"
    if number.is_integer():
        return f"{int(number)}"
    return f"{number:.1f}" if "second" in name else f"{number:.4f}"


def tuning_table(df: pd.DataFrame) -> None:
    """Grid search results, one row per setting, with the chosen one marked."""
    columns = list(df.columns)
    macro = next((c for c in columns if "macro" in c.lower()), None)
    best = None
    if macro is not None:
        scores = pd.to_numeric(df[macro], errors="coerce")
        if scores.notna().any():
            best = scores.idxmax()
    combine = {"max_depth", "class_weights"}.issubset(columns)
    rest = [c for c in columns if not (combine and c in ("max_depth", "class_weights"))]
    headers = (["Setting"] if combine else []) + [TUNING_NAMES.get(c, c.replace("_", " ").capitalize()) for c in rest]
    offset = 1 if combine else 0
    numeric = tuple(i + offset for i, c in enumerate(rest) if pd.api.types.is_numeric_dtype(df[c]))
    rows = []
    for idx, r in df.iterrows():
        cells = []
        if combine:
            label = f"Depth {fmt_cell('max_depth', r['max_depth'])}, weights {r['class_weights']}"
            mark = led("ok") if idx == best else led("idle")
            chosen = ' <span class="xg-muted">(chosen)</span>' if idx == best else ""
            cells.append(f'<span class="xg-tag">{mark}{esc(label)}</span>{chosen}')
        cells += [esc(fmt_cell(c, r[c])) for c in rest]
        rows.append(cells)
    html_table(headers, rows, numeric=numeric)


def info_table(info) -> None:
    if not isinstance(info, dict):
        st.json(info, expanded=False)
        return
    rows = []
    for key, value in info.items():
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
            text = text if len(text) <= 160 else text[:157] + "..."
        else:
            text = str(value)
        rows.append([f'<span class="xg-mono">{esc(key)}</span>', esc(text)])
    html_table(["Field", "Value"], rows, wrap=(1,), tight=(0,))


PAGE_FUNCS = {
    "overview": page_overview,
    "run": lambda ctx: page_run(ctx),
    "events": page_events,
    "blocked": page_blocked,
    "staff": page_staff,
    "model": page_model,
    "activity": lambda ctx: page_activity(ctx),
}


# ---------------------------------------------------------------------------
# Who is signed in
# ---------------------------------------------------------------------------
def current_user() -> dict | None:
    return st.session_state.get("xg_user")


def role_now() -> str | None:
    """Role read fresh from disk, so an admin change takes effect at once."""
    user = current_user()
    if not user:
        return None
    role = au.current_role(user["username"])
    if role is None:                      # the account was deleted mid-session
        return None
    user["role"] = role
    return role


def allowed(permission: str) -> bool:
    return au.can(role_now(), permission)


def badge(role: str) -> str:
    return f'<span class="xg-badge {role}">{esc(au.ROLE_TEXT.get(role, role))}</span>'


# ---------------------------------------------------------------------------
# Login screen
# ---------------------------------------------------------------------------
def login_screen() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    show_html(f'<div class="xg"><div class="xg-login-wrap"><div class="xg-login-brand">{LOGO}'
              f'<div class="xg-wordmark">XGuard<span>IDS</span></div></div>'
              f'<div class="xg-login-tag">XGBoost intrusion detection and response control panel</div></div></div>')
    left, mid, right = st.columns([1, 2, 1])
    with mid:
        if not au.has_users():
            st.warning("No accounts exist yet. Create the first admin in the Kali terminal, then sign in here.")
            st.code("cd ~/fyp_dashboard\nvenv/bin/python xguard_auth.py create-admin", language="bash")
            return
        notice = st.session_state.get("xg_notice")
        if notice:
            st.info(notice)
        show_html('<div class="xg"><div class="xg-login-card"><h2>Sign in</h2></div></div>')
        with st.form("login_form", border=False):
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pw")
            try:
                submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
            except TypeError:
                submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            name = username.strip().lower() or "unknown"
            wait = au.lock_remaining(name)
            if wait:
                st.error(f"Too many wrong attempts for this account. Try again in {wait} seconds.")
            else:
                user = au.authenticate(username, password)
                if user:
                    au.clear_failures(name)
                    au.audit(user["username"], user["role"], "LOGIN", "signed in")
                    st.session_state["xg_user"] = user
                    st.session_state["xg_seen_events"] = None
                    st.session_state["xg_last_active"] = time.time()
                    st.session_state.pop("xg_notice", None)
                    st.rerun()
                else:
                    au.audit(name, "-", "LOGIN_FAILED", "wrong username or password")
                    if au.record_failure(name):
                        au.audit(name, "-", "LOGIN_LOCKED",
                                 f"locked for {au.LOCK_SECONDS} s after {au.LOCK_AFTER} wrong attempts")
                        st.error(f"Too many wrong attempts. This account is locked for {au.LOCK_SECONDS} seconds.")
                    else:
                        st.error("Wrong username or password.")
        show_html('<div class="xg xg-side-note" style="text-align:center;margin-top:1rem">'
                  'Forgot a password? An admin can reset it in the terminal with '
                  'xguard_auth.py reset-password.</div>')


def password_screen(forced: bool) -> None:
    left, mid, right = st.columns([1, 2, 1])
    with mid:
        title = "Choose your own password" if forced else "Change your password"
        show_html(f'<div class="xg"><div class="xg-login-wrap" style="margin-top:0">'
                  f'<div class="xg-login-brand">{LOGO}<div class="xg-wordmark">XGuard<span>IDS</span></div></div></div>'
                  f'<div class="xg-login-card"><h2>{esc(title)}</h2></div></div>')
        if forced:
            st.info("Your account was set up with a temporary password. Choose your own before you continue.")
        with st.form("pw_form", border=False):
            current = st.text_input("Current password", type="password", key="pw_current")
            new = st.text_input("New password", type="password", key="pw_new")
            repeat = st.text_input("Repeat the new password", type="password", key="pw_repeat")
            st.caption("At least 8 characters, with a letter and a number.")
            try:
                saved = st.form_submit_button("Save new password", type="primary", width="stretch")
            except TypeError:
                saved = st.form_submit_button("Save new password", type="primary")
        if saved:
            user = current_user()
            ok, msg = au.change_own_password(user["username"], current, new, repeat)
            if ok:
                au.audit(user["username"], role_now(), "PASSWORD_CHANGED", "changed own password")
                st.session_state.pop("xg_change_pw", None)
                st.toast("Password changed.", icon="🔑")
                st.rerun()
            else:
                st.error(msg)
        if not forced and st.button("Cancel", key="pw_cancel"):
            st.session_state.pop("xg_change_pw", None)
            st.rerun()


IDLE_MINUTES = max(1, int(os.environ.get("XGUARD_IDLE_MINUTES", "30") or 30))


def idle_expired() -> bool:
    last = st.session_state.get("xg_last_active")
    return bool(last) and time.time() - last > IDLE_MINUTES * 60


def sign_out_idle() -> None:
    user = current_user()
    if user:
        au.audit(user["username"], user.get("role", "-"), "LOGOUT_IDLE",
                 f"signed out after {IDLE_MINUTES} minutes without activity")
    st.session_state.pop("xg_user", None)
    st.session_state.pop("xg_last_active", None)
    st.session_state["xg_notice"] = f"You were signed out after {IDLE_MINUTES} minutes without activity."


def role_capability_note(role: str) -> None:
    extra = {
        "viewer": "You can watch every page. Running detection, releasing addresses and resetting are done by an analyst or admin.",
        "analyst": "You can run detection and release blocked addresses. Resetting the demo and managing accounts are admin only.",
        "admin": "You can do everything, including resetting the demo and managing accounts.",
    }[role]
    show_html(f'<div class="xg xg-cap">Signed in as <b>{esc(au.ROLE_TEXT[role])}</b>. {esc(extra)}</div>')


# ---------------------------------------------------------------------------
# Run detection page (analyst and admin)
# ---------------------------------------------------------------------------
def _features_and_classes():
    return rn.model_info(FYP_DIR)


def ip_choice_widget(key: str, count_hint: int, has_file_ips: bool):
    """Shared source-address chooser. Returns (mode, single, attackers)."""
    options = ["lab", "outside"] + (["file"] if has_file_ips else []) + ["single"]
    labels = {"lab": "Random lab addresses (192.168.56.x)",
              "outside": "Random outside attackers (203.0.113.x)",
              "file": "Use the address column from the file",
              "single": "One address for every record"}
    mode = st.radio("Source address", options, format_func=lambda m: labels[m], key=f"{key}_ipmode")
    single, attackers = "", 5
    if mode == "single":
        single = st.text_input("Address to use", value="203.0.113.50", key=f"{key}_single")
    elif mode in ("lab", "outside"):
        top = max(1, min(count_hint, 20))
        if top > 1:
            attackers = st.slider("How many different attackers", 1, top, min(3, top), key=f"{key}_attackers",
                                  help="Fewer attackers means some send several records, which shows the "
                                       "already blocked and repeat behaviour.")
        else:
            attackers = 1   # one record means one attacker, a slider from 1 to 1 is not allowed
    return mode, single, attackers


def show_ip_notes(ips, never_block):
    seen, notes = set(), []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        notes.extend(rn.ip_notes(ip, never_block))
    for text in dict.fromkeys(notes):
        note(text)


def start_run(plan, ips, kind: str, ctx: Ctx) -> None:
    problems = [rn.ip_problem(ip) for ip in ips]
    bad = [f"Row {i + 1}, {msg}" for i, msg in enumerate(problems) if msg]
    if bad:
        for msg in bad[:8]:
            st.error(msg)
        return
    features, _ = _features_and_classes()
    frame = rn.build_run_frame(plan, ips, features)
    path = rn.write_run_file(frame, kind)
    ok, msg = RUN.start(FYP_DIR, path, len(frame), kind, current_user()["username"])
    if not ok:
        st.error(msg)
        return
    au.audit(current_user()["username"], role_now(), "RUN_START",
             f"{rn.KIND_TEXT.get(kind, kind)}, {len(frame)} records, file {path.name}")
    st.session_state["xg_seen_events"] = None
    st.rerun()


def running_panel(ctx: Ctx) -> None:
    """Shown while a run is going or just after it finishes."""
    info = RUN.status()
    if not info:
        return
    kind_text = rn.KIND_TEXT.get(info["kind"], "Run")
    if info["running"]:
        show_html(f'<div class="xg"><div class="xg-run-head"><div class="xg-h2">Running now</div>'
                  f'<div class="xg-run-when">{esc(kind_text)}, {info["rows"]} records</div></div></div>')
        done = int((ctx.events["demo_file"] == info["name"]).sum()) if len(ctx.events) else 0
        show_html(f'<div class="xg xg-progress-note">{done} of {info["rows"]} records processed. '
                  'This page refreshes on its own.</div>')
        st.progress(min(done / max(info["rows"], 1), 1.0))
        if allowed("run") and st.button("Stop the run", key="stop_run"):
            if RUN.stop():
                au.audit(current_user()["username"], role_now(), "RUN_STOP", f"stopped {info['name']}")
                st.toast("Run stopped.", icon="🛑")
                st.rerun()
        with st.expander("Controller output"):
            show_html(f'<div class="xg xg-outbox">{esc(info["output"] or "Starting...")}</div>')
    else:
        report = RUN.take_report()
        if report:
            outcome = "stopped" if report["stopped"] else ("finished" if report["returncode"] == 0 else "ended with an error")
            au.audit(report["user"], role_now() or "-", "RUN_DONE", f"{report['name']} {outcome}")
            st.rerun()
        processed = int((ctx.events["demo_file"] == info["name"]).sum()) if len(ctx.events) else 0
        if info["stopped"]:
            st.info(f"The run was stopped. {processed} of {info['rows']} records were processed before it stopped.")
        elif info["returncode"] == 0:
            st.success(f"Run finished. {processed} records were processed. The results are on this page and the Event log.")
        else:
            st.error("The run ended with an error. The controller output is below.")
            with st.expander("Controller output", expanded=True):
                show_html(f'<div class="xg xg-outbox">{esc(info["output"])}</div>')


def page_run(ctx: Ctx) -> None:
    page_header("Run detection", "Feed records to the XGBoost IDS and watch it decide. This runs the real "
                                 "controller, so every block, alert and log entry is the same as the terminal.",
                ctx)
    if not allowed("run"):
        st.info("Running detection needs the Analyst or Admin role. You can still watch every page.")
        return
    if not ctx.src.live:
        st.warning("You are viewing an archived run. Switch the log source back to Live logs to run detection.")
        return

    perms = st.session_state.get("xg_perms")
    if perms is None:
        perms = rn.permission_check(FYP_DIR)
        st.session_state["xg_perms"] = perms
    if not perms.get("ids_controller.py", True):
        show_html('<div class="xg xg-perm">XGuard cannot run the controller yet because it needs permission to use '
                  'the firewall. Run the one time setup in Kali, then reload this page.<br><br>'
                  '<b>cd ~/fyp_dashboard && sudo bash setup_permissions.sh</b></div>')
        return

    running_panel(ctx)
    busy = RUN.busy()
    features, class_names = _features_and_classes()

    mode_text = {"upload": "Upload a CSV", "random": "Random test records", "manual": "Type one record"}
    run_mode = st.radio("Records to run", list(mode_text), format_func=lambda m: mode_text[m],
                        horizontal=True, key="run_mode", label_visibility="collapsed")

    # ---- upload
    if run_mode == "upload":
        note("Drop a CSV with the 12 flow features. A Label column is optional. Up to "
             f"{rn.MAX_ROWS} rows are processed in one run.")
        st.download_button("Download a template CSV", data=rn.template_csv(features),
                           file_name="xguard_template.csv", mime="text/csv", key="dl_template")
        upload = st.file_uploader("CSV file", type=["csv"], key="run_upload",
                                  label_visibility="collapsed", disabled=busy)
        if upload is not None:
            plan = rn.read_upload(upload.getvalue(), upload.name, features, class_names)
            for msg in plan.errors:
                st.error(msg)
            for msg in plan.notes:
                st.caption(msg)
            if plan.size:
                st.caption(f"{plan.size} record(s) ready from {esc(upload.name)}.")
                mode, single, attackers = ip_choice_widget("up", plan.size, plan.file_ips is not None)
                ips = rn.assign_ips(plan.size, mode, single=single, attackers=attackers,
                                    file_ips=plan.file_ips, seed=None)
                if ips:
                    show_ip_notes(ips, ctx.never_block)
                if st.button(f"Run detection on {plan.size} record(s)", type="primary",
                             key="run_upload_go", disabled=busy):
                    start_run(plan, ips, "upload", ctx)

    # ---- random
    if run_mode == "random":
        note("Draw random records from the held out test set. Unlike the demo files, these are not "
             "pre-picked, so an occasional misclassification can appear, which is the most honest test.")
        c1, c2 = st.columns(2)
        count = c1.slider("How many records", 1, rn.MAX_ROWS, 20, key="rand_count", disabled=busy)
        mix = c2.radio("Class mix", ["balanced", "natural"], key="rand_mix", disabled=busy,
                       format_func=lambda m: "Even mix of classes" if m == "balanced" else "Natural mix (mostly benign)")
        mode, single, attackers = ip_choice_widget("rand", count, False)
        if st.button(f"Draw and run {count} record(s)", type="primary", key="run_rand_go", disabled=busy):
            try:
                test = rn.load_test_set(FYP_DIR)
            except Exception as exc:
                st.error(f"The test set could not be read ({type(exc).__name__}). "
                         "Check that data/test.csv exists in the main system.")
            else:
                seed = int(time.time())
                sample = rn.sample_test(test, count, mix, seed)
                plan = rn.plan_from_test(sample, features)
                ips = rn.assign_ips(plan.size, mode, single=single, attackers=attackers, seed=seed)
                start_run(plan, ips, "random", ctx)

    # ---- manual
    if run_mode == "manual":
        note("Type the 12 feature values and a source address, then watch the model classify it. "
             "The values below start from a real DoS Hulk record, change any of them.")
        base = rn.MANUAL_START
        values, edited = [], False
        grid = st.columns(3)
        for i, feature in enumerate(features):
            default = float(base["values"][i]) if i < len(base["values"]) else 0.0
            val = grid[i % 3].number_input(feature, value=default, format="%.4f",
                                           key=f"manual_{i}", disabled=busy)
            values.append(val)
            if abs(val - default) > 1e-9:
                edited = True
        ip = st.text_input("Source address", value="203.0.113.60", key="manual_ip", disabled=busy)
        if st.button("Run detection on this record", type="primary", key="run_manual_go", disabled=busy):
            plan = rn.plan_manual(values, base["test_row"], base["Label"], edited, features)
            start_run(plan, [ip], "manual", ctx)

    # ---- results of the latest run
    run_name = (RUN.status() or {}).get("name")
    if run_name and len(ctx.events):
        rows = ctx.events[ctx.events["demo_file"] == run_name]
        if len(rows):
            section("This run", f"{len(rows)} record(s), newest first. The true label is shown next to "
                                "the prediction, so any mistake is visible.")
            run_results_table(rows)
            d1, d2, _ = st.columns([1, 1, 2])
            stem = Path(run_name).stem
            d1.download_button("Download this run as CSV",
                               data=rows[list(xd.EVENT_COLUMNS)].to_csv(index=False).encode("utf-8"),
                               file_name=f"{stem}_decisions.csv", mime="text/csv", key="dl_this_run")
            d2.download_button("Download run report", data=xd.run_report_text(run_name, rows, run_starter(run_name)),
                               file_name=f"{stem}_report.txt", mime="text/plain", key="dl_this_report")
            attacks = rows[rows["is_attack"]]
            if len(attacks):
                blocked = int(attacks["action"].eq("BLOCKED").sum())
                protected = int(attacks["action"].eq("NOT_BLOCKED_NEVER_BLOCK_LIST").sum())
                failed = int(rows["telegram"].eq("failed").sum())
                bits = [f"{len(attacks)} attack(s) detected", f"{blocked} newly blocked"]
                if protected:
                    bits.append(f"{protected} protected and not blocked")
                if failed:
                    bits.append(f"{failed} alert(s) failed, protection was not affected")
                note(", ".join(bits) + ".")


def run_starter(run_name: str) -> str:
    for r in au.read_audit(2000):
        if r.get("action") == "RUN_START" and run_name in r.get("detail", ""):
            return r.get("user", "")
    return ""


def run_results_table(rows: pd.DataFrame) -> None:
    labelled = rows[rows["actual"].isin(xd.CLASS_ORDER)]
    table_rows = []
    for _, e in rows.iloc[::-1].iterrows():
        if e["actual"] in xd.CLASS_ORDER:
            actual_cell = cell_class(e["actual"])
            right = e["actual"] == e["predicted"]
            result = (f'<span class="xg-tag">{led("ok")}Correct</span>' if right
                      else f'<span class="xg-tag bad">{led("block")}Wrong</span>')
        else:
            actual_cell = '<span class="xg-muted">Not labelled</span>'
            result = '<span class="xg-muted">No label</span>'
        table_rows.append([
            esc(xd.fmt_short(e["time"])), cell_ip(e["source_ip"]), actual_cell, cell_class(e["predicted"]),
            result, esc(xd.fmt_conf(e["confidence"])), cell_action(e["action"]), cell_telegram(e["telegram"]),
        ])
    html_table(["Time", "Source address", "True label", "Predicted", "Result", "Confidence", "Firewall",
                "Telegram"], table_rows, numeric=(5,))
    if len(labelled):
        correct = int((labelled["actual"] == labelled["predicted"]).sum())
        text = f"Correct on {correct} of {len(labelled)} labelled record(s)."
        if correct < len(labelled):
            text += (" The wrong ones are real model mistakes on records it never saw in training, "
                     "matching the small error rate in the test results.")
        note(text)


# ---------------------------------------------------------------------------
# Unblock and reset controls (added onto the existing pages)
# ---------------------------------------------------------------------------
def show_result(key: str) -> None:
    """Shows the outcome of the last action in this section, once."""
    result = st.session_state.pop(key, None)
    if not result:
        return
    kind, text, output = (list(result) + [""])[:3]
    {"ok": st.success, "info": st.info}.get(kind, st.error)(text)
    if output:
        with st.expander("Script output"):
            show_html(f'<div class="xg xg-outbox">{esc(output)}</div>')


PERMISSION_TEXT = ("XGuard needs firewall permission for this. In Kali run  "
                   "cd ~/fyp_dashboard && sudo bash setup_permissions.sh  then try again.")


# ---- firewall status and restore
@st.cache_data(ttl=10, show_spinner=False)
def cached_firewall_status(fyp: str, blocklist_sig: tuple):
    return rn.firewall_status(Path(fyp))


def firewall_status_now() -> dict | None:
    sig = xd.file_signature(FYP_DIR / "logs" / xd.BLOCK_FILE)
    return cached_firewall_status(str(FYP_DIR), sig)


def _do_restore() -> None:
    status, output, count = rn.restore_blocks(FYP_DIR)
    cached_firewall_status.clear()
    if status == "ok":
        au.audit(current_user()["username"], role_now(), "RESTORE", f"{count} block(s) put back in the firewall")
        st.session_state["xg_fw_result"] = ("ok", f"{count} block(s) put back in the firewall.", "")
    elif status == "permission":
        st.session_state["xg_fw_result"] = ("error", PERMISSION_TEXT, "")
    else:
        st.session_state["xg_fw_result"] = ("error", "The restore did not complete.", output)


def firewall_control(ctx: Ctx) -> None:
    if not allowed("unblock"):
        return
    result_waiting = "xg_fw_result" in st.session_state
    status = firewall_status_now()
    current = set(ctx.history[ctx.history["status"].eq("Blocked")]["ip"])
    missing = sorted(ip for ip in current if status is not None and not status.get(ip, False))
    if not missing and not result_waiting:
        return
    section("Restore firewall blocks", "Puts recorded blocks back into iptables with the controller's own "
                                       "restore step, the same one that runs at the start of every detection run.")
    show_result("xg_fw_result")
    if missing:
        note(f"{len(missing)} recorded block(s) are not active in the firewall right now, "
             f"{', '.join(missing)}. This usually happens after Kali restarts.")
        st.button("Restore blocks now", type="primary", key="fw_restore", on_click=_do_restore)


# ---- release an address
def _do_release() -> None:
    ip = st.session_state.get("ub_ip")
    staff = st.session_state.get("ub_staff") or current_user().get("name", "")
    note_text = st.session_state.get("ub_note", "")
    status, output = rn.run_unblock(FYP_DIR, ip, staff, note_text)
    st.session_state["ub_confirm"] = False
    if status == "ok":
        au.audit(current_user()["username"], role_now(), "UNBLOCK", f"released {ip}, note: {note_text}")
        st.session_state["xg_seen_events"] = None
        st.session_state["ub_note"] = ""
        cached_firewall_status.clear()
        st.session_state["xg_release_result"] = ("ok", f"{ip} was released. The audit log and Telegram notice "
                                                       "were updated.", "")
    elif status == "permission":
        st.session_state["xg_release_result"] = ("error", PERMISSION_TEXT, "")
    elif status == "not_blocked":
        st.session_state["xg_release_result"] = ("info", f"{ip} is not blocked, nothing to do.", "")
    else:
        st.session_state["xg_release_result"] = ("error", "The release did not complete.", output)


def unblock_control(ctx: Ctx) -> None:
    if not allowed("unblock"):
        return
    current = ctx.history[ctx.history["status"].eq("Blocked")]
    section("Release an address", "This runs the real unblock_ip.py, so the audit log and the Telegram notice "
                                  "are exactly the same as the terminal.")
    show_result("xg_release_result")
    if current.empty:
        note("No addresses are blocked, so there is nothing to release.")
        return
    c1, c2 = st.columns([1, 1])
    ip = c1.selectbox("Address to release", current["ip"].tolist(), key="ub_ip")
    if "ub_staff" not in st.session_state:
        st.session_state["ub_staff"] = current_user().get("name", "")
    c2.text_input("Your name for the record", key="ub_staff")
    note_text = st.text_input("Review note", key="ub_note",
                              placeholder="What you checked, for example Test record, confirmed safe to restore")
    confirmed = st.checkbox(f"I have reviewed the alert for {ip} and it is safe to release", key="ub_confirm")
    ready = confirmed and len(note_text.strip()) >= 5
    st.button(f"Release {ip}", type="primary", key="ub_go", disabled=not ready, on_click=_do_release)
    if not ready:
        st.caption("Write a review note of at least 5 characters and tick the box to enable the release.")


# ---- never-block list
def _do_nb_add() -> None:
    new_ip = st.session_state.get("nb_ip", "").strip()
    reason = st.session_state.get("nb_note", "").strip()
    ok, msg = rn.add_never_block(FYP_DIR, new_ip, reason, current_user().get("name", current_user()["username"]))
    if ok:
        au.audit(current_user()["username"], role_now(), "NEVERBLOCK_ADD",
                 f"protected {new_ip}, {reason or 'no reason given'}")
        st.session_state["nb_ip"] = ""
        st.session_state["nb_note"] = ""
    st.session_state["xg_nb_result"] = ("ok" if ok else "error", msg, "")


def _do_nb_remove() -> None:
    gone = st.session_state.get("nb_remove_ip")
    ok, msg = rn.remove_never_block(FYP_DIR, gone)
    if ok:
        au.audit(current_user()["username"], role_now(), "NEVERBLOCK_REMOVE", f"removed {gone}")
    st.session_state["nb_remove_confirm"] = False
    st.session_state["xg_nb_result"] = ("ok" if ok else "error", msg, "")


def never_block_control(ctx: Ctx) -> None:
    if not allowed("neverblock"):
        return
    section("Edit the never-block list", "Admin only. XGuard will still alert on these addresses but never block "
                                         "them. The change applies from the next detection run.")
    show_result("xg_nb_result")
    c1, c2 = st.columns([1, 2])
    new_ip = c1.text_input("Address to protect", key="nb_ip", placeholder="for example 192.168.56.20")
    c2.text_input("What it is", key="nb_note", placeholder="for example Lab file server")
    blocked_now = set(ctx.blocks["ip"]) if len(ctx.blocks) else set()
    if new_ip.strip() and new_ip.strip() in blocked_now:
        note(f"{new_ip.strip()} is blocked right now. Protecting it stops future blocks, but it stays blocked "
             "until it is released above.")
    st.button("Add to never-block list", type="primary", key="nb_add", disabled=not new_ip.strip(),
              on_click=_do_nb_add)

    removable = [e["ip"] for e in rn.never_block_entries(FYP_DIR) if not e["core"]]
    if removable:
        c3, c4 = st.columns([1, 2])
        gone = c3.selectbox("Address to remove", removable, key="nb_remove_ip")
        c4.caption("Only addresses added by an admin can be removed. The machine's own addresses and its gateway "
                   "are built in and always stay protected.")
        sure = st.checkbox(f"Yes, remove the protection for {gone}, so XGuard can block it again",
                           key="nb_remove_confirm")
        st.button(f"Remove {gone}", key="nb_remove", disabled=not sure, on_click=_do_nb_remove)
    else:
        st.caption("The machine's own addresses and its gateway are built in and always stay protected.")


# ---- reset
def _do_reset() -> None:
    status, output = rn.run_reset(FYP_DIR)
    st.session_state["reset_confirm"] = ""
    cached_firewall_status.clear()
    if status == "ok":
        au.audit(current_user()["username"], role_now(), "RESET", "demo reset, logs archived")
        st.session_state["xg_seen_events"] = None
        st.session_state["xg_reset_result"] = ("ok", "Demo reset. Every block was removed and the logs were "
                                                     "archived. Pick the archived run in Log source to see them.", "")
    elif status == "permission":
        st.session_state["xg_reset_result"] = ("error", PERMISSION_TEXT, "")
    else:
        st.session_state["xg_reset_result"] = ("error", "The reset did not complete.", output)


def reset_control(ctx: Ctx) -> None:
    if not allowed("reset"):
        return
    section("Reset for a clean demo", "Admin only. This runs reset_demo.py, which removes every IDS block and "
                                      "moves the current logs into the archive, so the next demo starts clean.")
    show_result("xg_reset_result")
    note("Type RESET to confirm. The archived logs are kept, so nothing is lost.")
    confirm = st.text_input("Type RESET to confirm", key="reset_confirm", label_visibility="collapsed",
                            placeholder="RESET")
    st.button("Reset now", type="primary", key="reset_go", disabled=confirm.strip().upper() != "RESET",
              on_click=_do_reset)


# ---------------------------------------------------------------------------
# Activity log page (who did what in the dashboard)
# ---------------------------------------------------------------------------
AUDIT_TEXT = {
    "LOGIN": ("ok", "Signed in"), "LOGIN_OK": ("ok", "Signed in"), "LOGOUT": ("idle", "Signed out"),
    "LOGIN_FAILED": ("block", "Failed sign in"), "RUN_START": ("info", "Started a run"),
    "RUN_DONE": ("idle", "Run finished"), "RUN_STOP": ("block", "Stopped a run"),
    "UNBLOCK": ("ok", "Released an address"), "RESET": ("block", "Reset the demo"),
    "USER_ADDED": ("ok", "Added an account"), "USER_REMOVED": ("block", "Removed an account"),
    "ROLE_CHANGED": ("info", "Changed a role"), "PASSWORD_SET": ("info", "Changed a password"),
    "ACCOUNT_CREATED": ("ok", "Created the first admin"), "PASSWORD_RESET": ("info", "Reset a password"),
    "NEVERBLOCK_ADD": ("protect", "Protected an address"), "NEVERBLOCK_REMOVE": ("block", "Unprotected an address"),
    "LOGIN_LOCKED": ("block", "Account locked"), "LOGOUT_IDLE": ("idle", "Signed out when idle"),
    "PASSWORD_CHANGED": ("info", "Changed own password"), "RESTORE": ("protect", "Restored firewall blocks"),
}


def page_activity(ctx: Ctx) -> None:
    page_header("Activity log", "Every sign in and every control action taken in this dashboard, so each change "
                                "can be traced to a person.", ctx)
    if not allowed("view"):
        return
    rows = au.read_audit(300)
    if not rows:
        show_html('<div class="xg xg-empty"><div class="xg-h2">No activity yet</div>'
                  '<div class="xg-lede">Sign ins and control actions will appear here.</div></div>')
    else:
        table_rows = []
        for r in rows:
            state, text = AUDIT_TEXT.get(r.get("action", ""), ("idle", r.get("action", "")))
            role = r.get("role", "")
            role_cell = badge(role) if role in au.ROLES else esc(role or "")
            table_rows.append([
                esc(r.get("timestamp", "")),
                f'<span class="xg-mono">{esc(r.get("user", ""))}</span>',
                role_cell,
                f'<span class="xg-tag">{led(state)}{esc(text)}</span>',
                esc(r.get("detail", "")),
            ])
        html_table(["Time", "User", "Role", "Action", "Detail"], table_rows, wrap=(4,))

    if allowed("users"):
        user_admin(ctx)


def _do_create_account() -> None:
    new_user = st.session_state.get("nu_user", "")
    role = st.session_state.get("nu_role", "viewer")
    ok, msg = au.create_user(new_user, st.session_state.get("nu_name", ""), role,
                             st.session_state.get("nu_pw", ""), must_change=True)
    if ok:
        au.audit(current_user()["username"], role_now(), "USER_ADDED",
                 f"{new_user.strip().lower()} as {au.ROLE_TEXT[role]}")
        for key in ("nu_user", "nu_name", "nu_pw"):
            st.session_state[key] = ""
    st.session_state["xg_user_result"] = ("ok" if ok else "error", msg, "")


def user_admin(ctx: Ctx) -> None:
    section("Accounts", "Admin only. Add accounts for panel members or staff, set their role, or remove them.")
    users = au.load_users()
    rows = []
    for name, u in sorted(users.items()):
        rows.append([f'<span class="xg-mono">{esc(name)}</span>', esc(u.get("name", "")),
                     badge(u.get("role", "viewer")), esc(u.get("last_login") or "never")])
    html_table(["Username", "Name", "Role", "Last sign in"], rows)

    with st.expander("Add an account"):
        c1, c2 = st.columns(2)
        new_user = c1.text_input("Username", key="nu_user")
        new_name = c2.text_input("Display name", key="nu_name")
        c3, c4 = st.columns(2)
        new_role = c3.selectbox("Role", list(au.ROLES), format_func=lambda r: au.ROLE_TEXT[r], key="nu_role")
        new_pw = c4.text_input("Temporary password", type="password", key="nu_pw")
        st.caption("At least 8 characters, with a letter and a number. They choose their own password at "
                   "the first sign in. " + au.ROLE_SUMMARY[new_role])
        show_result("xg_user_result")
        st.button("Create account", type="primary", key="nu_go", on_click=_do_create_account)

    manage = [u for u in sorted(users) if u != current_user()["username"]]
    if manage:
        with st.expander("Change a role or remove an account"):
            who = st.selectbox("Account", manage, key="mu_user")
            c5, c6 = st.columns([2, 1])
            role_pick = c5.selectbox("Role", list(au.ROLES), format_func=lambda r: au.ROLE_TEXT[r],
                                     index=au.ROLES.index(users[who]["role"]), key="mu_role")
            if c6.button("Save role", key="mu_role_go"):
                ok, msg = au.set_role(who, role_pick)
                if ok:
                    au.audit(current_user()["username"], role_now(), "ROLE_CHANGED", f"{who} to {au.ROLE_TEXT[role_pick]}")
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
            new_pw = st.text_input(f"New password for {who}", type="password", key="mu_pw")
            cc1, cc2 = st.columns(2)
            if cc1.button("Set password", key="mu_pw_go"):
                ok, msg = au.set_password(who, new_pw, must_change=True)
                if ok:
                    au.audit(current_user()["username"], role_now(), "PASSWORD_SET", f"for {who}")
                    st.success(msg)
                else:
                    st.error(msg)
            if cc2.button(f"Remove {who}", key="mu_del_go"):
                ok, msg = au.delete_user(who, current_user()["username"])
                if ok:
                    au.audit(current_user()["username"], role_now(), "USER_REMOVED", who)
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
RUN = rn.RunManager()


@st.cache_resource
def get_run_manager() -> rn.RunManager:
    return rn.RunManager()


RUN = get_run_manager()

st.markdown(CSS, unsafe_allow_html=True)

if not FYP_DIR.exists():
    st.error(f"XGuard cannot find the IDS folder at {FYP_DIR}. Check that the main system is in ~/fyp, "
             "or start the dashboard with XGUARD_FYP_DIR set to its folder.")
    st.stop()

if current_user() is None:
    login_screen()
    st.stop()

if role_now() is None:                    # account deleted while signed in
    st.session_state.pop("xg_user", None)
    st.rerun()

if idle_expired():
    sign_out_idle()
    st.rerun()
st.session_state["xg_last_active"] = time.time()   # only real clicks reach this line, not auto refresh

if au.needs_password_change(current_user()["username"]):
    password_screen(forced=True)
    st.stop()
if st.session_state.get("xg_change_pw"):
    password_screen(forced=False)
    st.stop()

sources = xd.list_log_sources(FYP_DIR)
source_map = {s.key: s for s in sources}
role = role_now()
visible_pages = [k for k in PAGES if k not in RESTRICTED_PAGES or au.can(role, RESTRICTED_PAGES[k])]

with st.sidebar:
    show_html(f'<div class="xg xg-brand">{LOGO}<div><div class="xg-wordmark">XGuard<span>IDS</span></div>'
              f'<div class="xg-tagline">XGBoost intrusion detection and response</div></div></div>')
    user = current_user()
    show_html(f'<div class="xg xg-who"><div><div class="xg-who-name">{esc(user.get("name", user["username"]))}</div>'
              f'<div style="margin-top:.2rem">{badge(role)}</div></div></div>')
    b1, b2 = st.columns(2)
    if b1.button("Sign out", key="logout", width="stretch"):
        au.audit(user["username"], role, "LOGOUT", "signed out")
        st.session_state.pop("xg_user", None)
        st.session_state.pop("xg_last_active", None)
        st.rerun()
    if b2.button("Password", key="change_pw", width="stretch", help="Change your password"):
        st.session_state["xg_change_pw"] = True
        st.rerun()
    st.caption(f"Signs out after {IDLE_MINUTES} minutes without activity.")
    st.divider()
    page = st.radio("Page", visible_pages, format_func=lambda k: PAGES[k],
                    label_visibility="collapsed", key="page")
    st.divider()
    source_key = st.selectbox("Log source", list(source_map),
                              format_func=lambda k: source_map[k].label, key="source")
    live_now = source_map.get(source_key, sources[0]).live
    auto = st.toggle("Auto refresh", value=True, key="auto",
                     help="Reloads the log files every few seconds while you watch the live logs.")
    interval = st.select_slider("Refresh every", options=[2, 3, 5, 10], value=3,
                                format_func=lambda v: f"{v} s", disabled=not auto, key="interval")
    show_html(f'<div class="xg xg-side-note">XGuard reads the logs in {esc(FYP_DIR)} and drives the backend '
              'scripts for runs, releases and resets. It has no separate copy of the detection logic.</div>')

src = source_map.get(source_key, sources[0])


def render() -> None:
    if idle_expired():
        st.rerun()
    ctx = load_context(src)
    announce_new_events(ctx)
    PAGE_FUNCS.get(page, page_overview)(ctx)


def render_controls() -> None:
    # Outside the auto refresh, so a half typed note is never interrupted
    ctx = load_context(src)
    firewall_control(ctx)
    unblock_control(ctx)
    never_block_control(ctx)
    reset_control(ctx)


if page in ("run", "activity"):
    # Forms live here, so the page only refreshes on its own while a run is going
    if page == "run" and src.live and RUN.busy():
        st.fragment(run_every=2)(render)()
    else:
        render()
elif auto and src.live:
    st.fragment(run_every=interval)(render)()
else:
    render()

if page == "blocked" and src.live:
    render_controls()
