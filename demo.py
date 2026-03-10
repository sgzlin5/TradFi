# coding: utf-8
import hashlib
import hmac
import os
import time

import requests
from dotenv import load_dotenv

# 从 .env 文件加载环境变量（不存在则读取系统环境变量）
load_dotenv()

API_KEY    = os.environ["GATE_API_KEY"]
API_SECRET = os.environ["GATE_API_SECRET"]

HOST   = "https://api.gateio.ws"
PREFIX = "/api/v4"


def gen_sign(method: str, url_path: str, query_string: str = "", body: str = "") -> dict:
    """生成 Gate REST API 认证 Header"""
    ts          = str(int(time.time()))
    body_hash   = hashlib.sha512(body.encode("utf-8")).hexdigest()
    sign_raw    = "\n".join([method.upper(), url_path, query_string, body_hash, ts])
    signature   = hmac.new(
        API_SECRET.encode("utf-8"),
        sign_raw.encode("utf-8"),
        hashlib.sha512
    ).hexdigest()
    return {
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "KEY":          API_KEY,
        "Timestamp":    ts,
        "SIGN":         signature,
    }


# ── K线周期常量 ───────────────────────────────
KLINE_INTERVALS = ["1m", "5m", "15m", "30m", "1h", "4h", "1d"]


def get_klines(symbol: str, kline_type: str, limit: int = 100) -> list:
    """
    查询 TradFi 品种 K 线数据

    :param symbol:     交易对，如 "EURUSD"、"XAUUSD"
    :param kline_type: K 线周期，支持 1m / 5m / 15m / 30m / 1h / 4h / 1d
    :param limit:      返回条数，默认 100
    :return:           K 线列表（每条为一个 dict / list，取决于 API 返回格式）
    :raises ValueError: kline_type 不在支持列表中时抛出
    """
    if kline_type not in KLINE_INTERVALS:
        raise ValueError(f"不支持的 K 线周期 '{kline_type}'，可选值：{KLINE_INTERVALS}")

    url_path     = f"/api/v4/tradfi/symbols/{symbol}/klines"
    query_string = f"kline_type={kline_type}&limit={limit}"

    headers = gen_sign("GET", url_path, query_string)
    params  = dict(p.split("=", 1) for p in query_string.split("&"))
    resp    = requests.get(HOST + url_path, params=params, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_all_klines(symbol: str, limit: int = 100) -> dict:
    """
    一次性获取指定品种所有支持周期的 K 线数据

    :param symbol: 交易对，如 "EURUSD"
    :param limit:  每个周期返回条数，默认 100
    :return:       以周期为 key、K 线列表为 value 的字典
    """
    result = {}
    for interval in KLINE_INTERVALS:
        print(f"  正在获取 {symbol} {interval} K 线...")
        result[interval] = get_klines(symbol, interval, limit)
    return result


def get_assets() -> dict:
    """
    查询当前账户的 TradFi 资产信息

    :return: 账户资产信息字典
    """
    url_path     = "/api/v4/tradfi/users/assets"
    query_string = ""

    headers = gen_sign("GET", url_path, query_string)
    resp    = requests.get(HOST + url_path, headers=headers)
    resp.raise_for_status()
    return resp.json()


# ── 使用示例 ──────────────────────────────────
if __name__ == "__main__":
    SYMBOL = "NAS100"

    # 1) 查询资产信息
    print("=== 账户资产信息 ===")
    assets = get_assets()
    print(assets)

    # 2) 查询单个周期
    print(f"\n=== {SYMBOL} 1m K 线（最新 5 条）===")
    data_1m = get_klines(SYMBOL, "1m", limit=5)
    print(data_1m)

    # 3) 查询所有周期（每个周期取最新 3 条）
    print(f"\n=== {SYMBOL} 全周期 K 线（每周期 3 条）===")
    all_data = get_all_klines(SYMBOL, limit=3)
    for interval, bars in all_data.items():
        print(f"[{interval}] {bars}")
