"""
scanner.py - 从站 ID 扫描引擎

对 Modbus TCP / RTU 从 1 到 247 逐个探询，收集有应答的设备。
- 模拟器模式：内置 5 个虚拟从站（1/3/7/16/42），零硬件即可演示扫描。
- 真机 TCP / 串口模式：并发探询（默认 12 线程），短超时，避免 247 次串行等待。
  只要收到任意非空响应（含异常帧）即判定设备在线——异常帧也是设备应答。
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .client import execute

VIRTUAL_UNITS = [1, 3, 7, 16, 42]
MIN_UNIT, MAX_UNIT = 1, 247


def _probe(protocol: str, mode: str, conn: dict, unit: int, timeout: float) -> dict | None:
    """探询单个从站 ID；在线返回信息字典，离线返回 None。"""
    c = dict(conn or {})
    c["unit"] = unit
    try:
        # independent=True：扫描探询走独立短连接，不复用/不污染TCP会话池。
        # 否则 12 线程共用一个 socket 会被会话锁串行化，且某次超时会关掉
        # 用户已建立的长连接，导致扫描后正常读写全部失效（v1.2 回归缺陷）。
        r = execute(protocol, 3, {"addr": 0, "count": 1}, mode, c, timeout,
                    independent=True)
    except Exception:
        return None
    if not r.response_hex:
        return None
    return {
        "unit": unit,
        "ok": r.ok,
        "sample": r.values[:4],
        "error": r.error if not r.ok else "",
        "elapsedMs": round(r.elapsed_ms, 2),
        "requestHex": r.request_hex,
        "responseHex": r.response_hex,
    }


def scan_units(protocol: str = "modbus_tcp", mode: str = "simulator",
               conn: dict | None = None, timeout: float = 0.3,
               start: int = MIN_UNIT, end: int = MAX_UNIT,
               max_workers: int = 12) -> dict:
    """扫描从站 ID，返回 {found, probed, elapsedMs, protocol, mode, range}。"""
    t0 = time.perf_counter()
    conn = conn or {}
    start = max(MIN_UNIT, min(MAX_UNIT, int(start)))
    end = max(start, min(MAX_UNIT, int(end)))
    if protocol not in ("modbus_tcp", "modbus_rtu"):
        return {"found": [], "probed": 0, "elapsedMs": 0.0, "protocol": protocol,
                "mode": mode, "range": [start, end],
                "error": "从站扫描仅支持 Modbus TCP / RTU（其他协议靠 IP+节点号/槽号定位）"}

    if mode == "simulator":
        candidates = [u for u in VIRTUAL_UNITS if start <= u <= end]
        probe_mode = "simulator"
        workers = 1
    else:
        candidates = list(range(start, end + 1))
        probe_mode = mode
        workers = max(1, min(int(max_workers), 32))

    found: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, protocol, probe_mode, conn, u, timeout): u
                   for u in candidates}
        for fut in as_completed(futures):
            info = fut.result()
            if info:
                found.append(info)
    found.sort(key=lambda x: x["unit"])
    return {
        "found": found,
        "probed": len(candidates),
        "elapsedMs": round((time.perf_counter() - t0) * 1000, 2),
        "protocol": protocol, "mode": mode, "range": [start, end],
    }
