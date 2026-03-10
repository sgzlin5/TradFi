# coding: utf-8
"""
TradFi K 线可视化 Web 服务
运行: python chart_server.py
访问: http://localhost:23333
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import Cookie, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

# ── 常量 ──────────────────────────────────────
HOST            = "https://api.gateio.ws"
KLINE_INTERVALS = ["1m", "5m", "15m", "30m", "1h", "4h", "1d"]
TEMPLATES_DIR   = Path(__file__).parent / "templates"
CONFIG_FILE     = Path(__file__).parent / "config.enc"

# Cookie 签名密钥（每次启动随机，重启需重新登录）
_COOKIE_SECRET = secrets.token_hex(32)
_signer        = TimestampSigner(_COOKIE_SECRET)

# 内存中存放已登录会话 token -> {api_key, api_secret}
_sessions: Dict[str, dict] = {}

# 登录失败计数与锁定（超过3次锁定24h）
_login_failures: int   = 0
_lockout_until:  float = 0.0
MAX_FAILURES = 3
LOCKOUT_SECS = 86400


# ── config.enc 解密 ───────────────────────────
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_config(password: str) -> dict:
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"找不到配置文件: {CONFIG_FILE}")
    with open(CONFIG_FILE, "rb") as f:
        salt           = f.read(16)
        encrypted_data = f.read()
    key   = _derive_key(password, salt)
    fernet = Fernet(key)
    data  = fernet.decrypt(encrypted_data)          # 密码错误时抛 InvalidToken
    return json.loads(data.decode("utf-8"))


# ── 会话工具 ──────────────────────────────────
def _make_token(session_id: str) -> str:
    return _signer.sign(session_id).decode()


def _verify_token(token: str) -> Optional[str]:
    """返回 session_id，验证失败返回 None"""
    try:
        # max_age=86400 = 24h
        return _signer.unsign(token, max_age=86400).decode()
    except (BadSignature, SignatureExpired):
        return None


def _get_creds(request: Request) -> Optional[Tuple[str, str]]:
    """从 cookie 中取出 API_KEY / API_SECRET，未登录返回 None"""
    token = request.cookies.get("session")
    if not token:
        return None
    sid = _verify_token(token)
    if not sid or sid not in _sessions:
        return None
    s = _sessions[sid]
    return s["api_key"], s["api_secret"]


# ── Gate API 工具函数 ──────────────────────────
def gen_sign(api_key: str, api_secret: str,
             method: str, url_path: str,
             query_string: str = "", body: str = "") -> dict:
    ts        = str(int(time.time()))
    body_hash = hashlib.sha512(body.encode("utf-8")).hexdigest()
    sign_raw  = "\n".join([method.upper(), url_path, query_string, body_hash, ts])
    signature = hmac.new(
        api_secret.encode("utf-8"),
        sign_raw.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()
    return {
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "KEY":          api_key,
        "Timestamp":    ts,
        "SIGN":         signature,
    }


def get_klines(api_key: str, api_secret: str,
               symbol: str, kline_type: str, limit: int = 200) -> dict:
    if kline_type not in KLINE_INTERVALS:
        raise ValueError(f"不支持的周期 '{kline_type}'")
    url_path     = f"/api/v4/tradfi/symbols/{symbol}/klines"
    query_string = f"kline_type={kline_type}&limit={limit}"
    headers      = gen_sign(api_key, api_secret, "GET", url_path, query_string)
    params       = dict(p.split("=", 1) for p in query_string.split("&"))
    resp         = requests.get(HOST + url_path, params=params, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_assets_data(api_key: str, api_secret: str) -> dict:
    url_path = "/api/v4/tradfi/users/assets"
    headers  = gen_sign(api_key, api_secret, "GET", url_path, "")
    resp     = requests.get(HOST + url_path, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_mt5_account_data(api_key: str, api_secret: str) -> dict:
    url_path = "/api/v4/tradfi/users/mt5-account"
    headers  = gen_sign(api_key, api_secret, "GET", url_path, "")
    resp     = requests.get(HOST + url_path, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_positions(api_key: str, api_secret: str) -> dict:
    url_path = "/api/v4/tradfi/positions"
    headers  = gen_sign(api_key, api_secret, "GET", url_path, "")
    resp     = requests.get(HOST + url_path, headers=headers)
    resp.raise_for_status()
    return resp.json()


def update_position(api_key: str, api_secret: str,
                    position_id: int, body: dict) -> dict:
    url_path = f"/api/v4/tradfi/positions/{position_id}"
    body_str = json.dumps(body)
    headers  = gen_sign(api_key, api_secret, "PUT", url_path, "", body_str)
    resp     = requests.put(HOST + url_path, headers=headers, data=body_str)
    resp.raise_for_status()
    return resp.json()


def close_position(api_key: str, api_secret: str,
                   position_id: int, body: dict) -> dict:
    url_path = f"/api/v4/tradfi/positions/{position_id}/close"
    body_str = json.dumps(body)
    headers  = gen_sign(api_key, api_secret, "POST", url_path, "", body_str)
    resp     = requests.post(HOST + url_path, headers=headers, data=body_str)
    resp.raise_for_status()
    return resp.json()


def get_position_history(api_key: str, api_secret: str,
                         from_ts: int, to_ts: int) -> list:
    """获取历史成交记录，返回 list"""
    url_path = "/api/v4/tradfi/positions/history"
    qs       = f"from={from_ts}&to={to_ts}"
    headers  = gen_sign(api_key, api_secret, "GET", url_path, qs)
    resp     = requests.get(HOST + url_path, params={"from": from_ts, "to": to_ts},
                            headers=headers)
    resp.raise_for_status()
    return resp.json().get("data", {}).get("list", [])


# ── FastAPI ───────────────────────────────────
app = FastAPI(title="TradFi K线查看器")


# ── 登录页 ────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(
        content=(TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
    )


@app.post("/api/login")
async def api_login(request: Request):
    global _login_failures, _lockout_until

    # 检查是否处于锁定状态
    now = time.time()
    if now < _lockout_until:
        remaining = int(_lockout_until - now)
        h, m = divmod(remaining // 60, 60)
        raise HTTPException(403, detail=f"登录已被锁定，请 {h}h{m}m 后再试")

    try:
        body     = await request.json()
        password = body.get("password", "")
    except Exception:
        raise HTTPException(400, detail="请求格式错误")

    try:
        cfg = load_config(password)
    except FileNotFoundError as e:
        raise HTTPException(404, detail=str(e))
    except InvalidToken:
        _login_failures += 1
        remaining_tries = MAX_FAILURES - _login_failures
        if _login_failures >= MAX_FAILURES:
            _lockout_until = time.time() + LOCKOUT_SECS
            raise HTTPException(403, detail="密码错误次数过多，已锁定 24 小时")
        raise HTTPException(401, detail=f"密码错误，还剩 {remaining_tries} 次机会")
    except Exception as e:
        raise HTTPException(500, detail=f"解密失败: {e}")

    # 登录成功，重置计数
    _login_failures = 0
    _lockout_until  = 0.0

    api_key    = cfg.get("GATE_API_KEY") or cfg.get("API_KEY") or cfg.get("api_key") or cfg.get("key")
    api_secret = cfg.get("GATE_API_SECRET") or cfg.get("API_SECRET") or cfg.get("api_secret") or cfg.get("secret")
    if not api_key or not api_secret:
        raise HTTPException(500, detail="配置文件中未找到 GATE_API_KEY / GATE_API_SECRET")

    sid   = secrets.token_hex(16)
    token = _make_token(sid)
    _sessions[sid] = {"api_key": api_key, "api_secret": api_secret}

    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", token, httponly=True, samesite="lax", max_age=86400)
    return resp


@app.post("/api/logout")
def api_logout(request: Request):
    token = request.cookies.get("session")
    if token:
        sid = _verify_token(token)
        if sid:
            _sessions.pop(sid, None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


# ── 主页（需登录）────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not _get_creds(request):
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(
        content=(TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
    )


# ── K 线接口（需登录）────────────────────────
@app.get("/api/klines")
def api_klines(
    request:  Request,
    symbol:   str = Query(default="XAUUSD"),
    interval: str = Query(default="1m"),
    limit:    int = Query(default=200, ge=1, le=1000),
):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    if interval not in KLINE_INTERVALS:
        raise HTTPException(400, detail=f"不支持的周期 '{interval}'")
    try:
        raw = get_klines(*creds, symbol, interval, limit)
    except Exception as e:
        raise HTTPException(502, detail=str(e))

    bars = raw.get("data", {}).get("list", [])
    candles = sorted(
        [{"time":  int(b["t"]), "open": float(b["o"]),
          "high":  float(b["h"]), "low": float(b["l"]), "close": float(b["c"])}
         for b in bars],
        key=lambda x: x["time"],
    )
    return JSONResponse({"symbol": symbol, "interval": interval, "candles": candles})


# ── 资产接口（需登录）────────────────────────
@app.get("/api/assets")
def api_assets(request: Request):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    try:
        data = get_assets_data(*creds)
    except Exception as e:
        raise HTTPException(502, detail=str(e))
    return JSONResponse(data)


# ── MT5 账户信息（需登录）────────────────────
@app.get("/api/mt5account")
def api_mt5account(request: Request):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    try:
        data = get_mt5_account_data(*creds)
    except Exception as e:
        raise HTTPException(502, detail=str(e))
    return JSONResponse(data)


# ── 头寸接口（需登录）────────────────────────
@app.get("/api/positions")
def api_positions(request: Request):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    try:
        data = get_positions(*creds)
    except Exception as e:
        raise HTTPException(502, detail=str(e))
    return JSONResponse(data)


# ── 更新头寸止盈止损（需登录）──────────────
@app.put("/api/positions/{position_id}")
async def api_update_position(position_id: int, request: Request):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    try:
        body = await request.json()
        data = update_position(*creds, position_id, body)
    except Exception as e:
        raise HTTPException(502, detail=str(e))
    return JSONResponse(data)


# ── 关闭头寸接口（需登录）──────────────
@app.post("/api/positions/{position_id}/close")
async def api_close_position(position_id: int, request: Request):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    try:
        body = await request.json()
        data = close_position(*creds, position_id, body)
    except Exception as e:
        raise HTTPException(502, detail=str(e))
    return JSONResponse(data)


# ── 收益汇总（需登录）──────────────
@app.get("/api/pnl_summary")
def api_pnl_summary(
    request:    Request,
    today_from: int = Query(..., description="今日零点 Unix 时闳戳（秒）"),
):
    creds = _get_creds(request)
    if not creds:
        raise HTTPException(401, detail="未登录")
    now_ts       = int(time.time())
    yesterday_ts = today_from - 86400
    try:
        # 一次请求拉取昇天至现在的全部历史
        records = get_position_history(*creds, yesterday_ts, now_ts)
    except Exception as e:
        raise HTTPException(502, detail=str(e))

    today_pnl     = 0.0
    yesterday_pnl = 0.0
    for r in records:
        t   = int(r.get("time_close") or 0)
        pnl = float(r.get("realized_pnl") or 0)
        if t >= today_from:
            today_pnl += pnl
        elif t >= yesterday_ts:
            yesterday_pnl += pnl

    return JSONResponse({
        "today_pnl":     round(today_pnl,     2),
        "yesterday_pnl": round(yesterday_pnl, 2),
    })


# ── 启动 ──────────────────────────────────────
if __name__ == "__main__":
    print("K线图地址: http://localhost:23333")
    uvicorn.run(app, host="0.0.0.0", port=23333)
