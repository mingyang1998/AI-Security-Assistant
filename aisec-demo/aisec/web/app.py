"""FastAPI app —— AISOC 单页控制台。

路由：
  GET  /                          首页（概览）
  GET  /agents                    Agent 列表（来自 Registry sqlite）
  GET  /alerts                    告警列表（来自 data/alerts/*.md）
  GET  /events?type=&limit=       事件检索（来自 data/events/<日期>.jsonl）
  GET  /msp                       MSP 报告列表（来自 data/msp/）
  GET  /msp/{ts}                  MSP 报告详情（md 渲染）
  GET  /api/events.json           事件流 JSON 端点（前端轮询用）
  GET  /api/summary.json          首页概览 JSON

技术选型：所有数据访问走同步 sqlite3 / 直接读文件，
          **不**与 soc-agent 共享 asyncio loop（避免 Proactor 兼容问题）。
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..core.config import Settings, get_settings

logger = logging.getLogger(__name__)

# 模板目录
TEMPLATES_DIR = Path(__file__).parent / "templates"


# ---------- Jinja2 过滤器 ----------


def _filter_datetimeformat(ts: int | float | None) -> str:
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return str(ts)


def _filter_truncate(s: str, length: int = 120) -> str:
    s = str(s)
    if len(s) <= length:
        return s
    return s[:length] + "…"


def _register_filters(templates: Jinja2Templates) -> None:
    templates.env.filters["datetimeformat"] = _filter_datetimeformat
    templates.env.filters["truncate"] = _filter_truncate


# ---------- 数据访问（同步） ----------


def _list_agents(settings: Settings) -> list[dict[str, Any]]:
    db_path = settings.abs(settings.audit.db_path)
    if not db_path.exists():
        return []
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute("SELECT * FROM agents ORDER BY registered_at")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def _list_alerts(settings: Settings) -> list[dict[str, Any]]:
    alerts_dir = settings.abs(settings.alerts.dir)
    if not alerts_dir.exists():
        return []
    items: list[dict[str, Any]] = []
    for p in sorted(alerts_dir.glob("*.md"), reverse=True):
        st = p.stat()
        items.append({
            "name": p.name,
            "path": str(p),
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        })
    return items


def _list_msp_reports(settings: Settings) -> list[dict[str, Any]]:
    msp_dir = settings.abs("data/msp")
    if not msp_dir.exists():
        return []
    items: list[dict[str, Any]] = []
    for p in sorted(msp_dir.glob("*.json"), reverse=True):
        st = p.stat()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            overall = data.get("overall_level", "?")
            score = data.get("overall_score", 0)
            model = (data.get("fingerprint") or {}).get("model", "?")
            ts = data.get("started_at", "")
        except Exception:
            overall, score, model, ts = "?", 0, "?", ""
        items.append({
            "name": p.stem,
            "json_path": str(p),
            "md_path": str(p.with_suffix(".md")),
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "overall": overall,
            "score": score,
            "model": model,
            "started_at": ts,
        })
    return items


def _read_msp_report(settings: Settings, name: str) -> dict[str, Any]:
    """读单份 MSP 报告的 json + md。"""
    safe = (name.replace("..", "").replace("/", "").replace("\\", ""))
    json_path = settings.abs("data/msp") / f"{safe}.json"
    md_path = settings.abs("data/msp") / f"{safe}.md"
    if not json_path.exists():
        raise HTTPException(404, f"report not found: {safe}")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    md = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    return {"data": data, "md": md, "json_path": str(json_path), "md_path": str(md_path)}


def _tail_events(
    settings: Settings,
    type_filter: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    events_dir = settings.abs(settings.audit.events_dir)
    if not events_dir.exists():
        return []
    out: list[dict[str, Any]] = []
    # 多日文件合并（按日期倒序）
    for f in sorted(events_dir.glob("*.jsonl"), reverse=True):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if type_filter and ev.get("type") != type_filter:
                continue
            out.append(ev)
            if len(out) >= limit:
                return out
    return out


def _list_event_types(events_dir: Path) -> list[dict[str, Any]]:
    """统计每个 event type 出现次数。"""
    counts: dict[str, int] = {}
    if not events_dir.exists():
        return []
    for f in sorted(events_dir.glob("*.jsonl"), reverse=True):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = ev.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
    return [{"type": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]


def _summary(settings: Settings) -> dict[str, Any]:
    agents = _list_agents(settings)
    online = sum(1 for a in agents if a.get("status") == "online")
    offline = sum(1 for a in agents if a.get("status") == "offline")
    alerts = _list_alerts(settings)
    msp = _list_msp_reports(settings)
    events_dir = settings.abs(settings.audit.events_dir)
    ev_counts = _list_event_types(events_dir)
    return {
        "agents_total": len(agents),
        "agents_online": online,
        "agents_offline": offline,
        "alerts_total": len(alerts),
        "msp_total": len(msp),
        "msp_latest_level": msp[0]["overall"] if msp else "n/a",
        "msp_latest_score": msp[0]["score"] if msp else 0,
        "event_types": ev_counts[:10],
        "as_of": datetime.now().isoformat(timespec="seconds"),
    }


# ---------- FastAPI app ----------


def build_app(settings: Settings | None = None) -> FastAPI:
    s = settings or get_settings()
    app = FastAPI(title="AISOC", version="0.1", docs_url=None, redoc_url=None)
    # 静态资源（CSS 等）
    app.mount("/static", StaticFiles(directory=str(TEMPLATES_DIR.parent / "static")), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    _register_filters(templates)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "summary": _summary(s),
            "page": "home",
        })

    @app.get("/agents", response_class=HTMLResponse)
    def agents(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("agents.html", {
            "request": request,
            "agents": _list_agents(s),
            "page": "agents",
        })

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("alerts.html", {
            "request": request,
            "alerts": _list_alerts(s),
            "page": "alerts",
        })

    @app.get("/events", response_class=HTMLResponse)
    def events(
        request: Request,
        type: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=2000),
    ) -> HTMLResponse:
        evs = _tail_events(s, type, limit)
        ev_counts = _list_event_types(s.abs(s.audit.events_dir))
        return templates.TemplateResponse("events.html", {
            "request": request,
            "events": evs,
            "type_filter": type or "",
            "limit": limit,
            "event_types": ev_counts,
            "page": "events",
        })

    @app.get("/msp", response_class=HTMLResponse)
    def msp(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("msp.html", {
            "request": request,
            "reports": _list_msp_reports(s),
            "page": "msp",
        })

    @app.get("/msp/{name}", response_class=HTMLResponse)
    def msp_detail(request: Request, name: str) -> HTMLResponse:
        report = _read_msp_report(s, name)
        return templates.TemplateResponse("msp_detail.html", {
            "request": request,
            "report": report,
            "page": "msp",
        })

    @app.get("/api/summary.json", response_class=JSONResponse)
    def api_summary() -> JSONResponse:
        return JSONResponse(_summary(s))

    @app.get("/api/events.json", response_class=JSONResponse)
    def api_events(
        type: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=2000),
    ) -> JSONResponse:
        return JSONResponse({"events": _tail_events(s, type, limit)})

    @app.get("/api/agents.json", response_class=JSONResponse)
    def api_agents() -> JSONResponse:
        return JSONResponse({"agents": _list_agents(s)})

    @app.get("/api/alerts.json", response_class=JSONResponse)
    def api_alerts() -> JSONResponse:
        return JSONResponse({"alerts": _list_alerts(s)})

    @app.get("/api/msp.json", response_class=JSONResponse)
    def api_msp() -> JSONResponse:
        return JSONResponse({"reports": _list_msp_reports(s)})

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    return app


# ---------- CLI 入口 ----------


def main(host: str = "127.0.0.1", port: int = 9000) -> int:
    import uvicorn

    app = build_app()
    print(f"[aisoc] starting at http://{host}:{port}")
    print(f"[aisoc] open in browser: http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
