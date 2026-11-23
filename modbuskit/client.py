"""
client.py - 统一客户端：模拟器 / 真机 TCP 双模式

对外只暴露 Client.execute()，内部按协议分派到对应编解码器。
- simulator 模式：调用内存从站的 apply()，生成合规响应报文，零硬件可演示。
- tcp 模式：真实 socket 连接，sendall(request) -> recv(response)，带超时与异常捕获。
"""
from __future__ import annotations

import socket
import time

from . import modbus, mitsubishi, omron, ab, serialport
from .utils import OpResult, hexstr

PROTOCOLS = {
    "modbus_tcp": {
        "name": "Modbus TCP", "vendor": "通用/施耐德/西门子", "defaultPort": 502,
        "transport": "tcp", "module": modbus, "frame": "MBAP + PDU",
        "note": "标准 Modbus TCP，端口 502，功能码 01/02/03/04/05/06/15/16",
    },
    "modbus_rtu": {
        "name": "Modbus RTU", "vendor": "通用/仪表/变频器", "defaultPort": 0,
        "transport": "rtu", "module": modbus, "frame": "地址 + PDU + CRC16",
        "note": "串口 RTU，CRC16 校验；支持 COM 口直连（RS485/RS232）或经 TCP 透传网关",
    },
    "mitsubishi_mc": {
        "name": "三菱 MC 3E", "vendor": "Mitsubishi Q/L/F 系列", "defaultPort": 1031,
        "transport": "mc", "module": mitsubishi, "frame": "Qna 3E 二进制帧",
        "note": "MC 协议 Qna 3E 二进制，字低字节在前，软元件 D/M/X/Y/W/R",
    },
    "omron_fins": {
        "name": "欧姆龙 FINS/TCP", "vendor": "OMRON CJ/CP/NJ 系列", "defaultPort": 9600,
        "transport": "fins", "module": omron, "frame": "FINS/TCP + FINS 头",
        "note": "FINS over TCP，DM/CIO 区，地址用 BCD 编码，端口 9600",
    },
    "ab_eip": {
        "name": "AB Ethernet/IP", "vendor": "Rockwell/Allen-Bradley", "defaultPort": ab.EIP_PORT,
        "transport": "cip", "module": ab, "frame": "EIP 封装 + CPF + CIP",
        "note": "EtherNet/IP 显式报文 UCMM，Get/Set Attribute Single，端口 44818",
    },
}


class DeviceState:
    """每个协议一个持久模拟从站实例，跨请求保持寄存器写入状态。"""

    def __init__(self):
        self._sims: dict[str, object] = {}

    def simulator(self, protocol: str):
        if protocol not in self._sims:
            cls_name = {"modbus_tcp": (modbus, "ModbusSimulator"),
                        "modbus_rtu": (modbus, "ModbusSimulator"),
                        "mitsubishi_mc": (mitsubishi, "MitsubishiSimulator"),
                        "omron_fins": (omron, "OmronSimulator"),
                        "ab_eip": (ab, "ABSimulator")}[protocol]
            self._sims[protocol] = getattr(cls_name[0], cls_name[1])(seed=7)
        return self._sims[protocol]

    def reset(self, protocol: str | None = None):
        if protocol:
            self._sims.pop(protocol, None)
        else:
            self._sims.clear()


STATE = DeviceState()


def _build(protocol: str, function, params: dict, conn: dict) -> bytes:
    info = PROTOCOLS[protocol]
    mod = info["module"]
    t = info["transport"]
    if t == "tcp":
        return mod.build_request(int(function), params, transport="tcp",
                                 unit=int(conn.get("unit", 1)),
                                 transaction=int(conn.get("transaction", 1)))
    if t == "rtu":
        return mod.build_request(int(function), params, transport="rtu",
                                 unit=int(conn.get("unit", 1)))
    if t == "mc":
        return mod.build_request(str(function), params,
                                 network=int(conn.get("network", 0)),
                                 station=int(conn.get("station", 255)),
                                 processor=int(conn.get("processor", 255)))
    if t == "fins":
        return mod.build_request(str(function), params,
                                 dst_node=int(conn.get("dstNode", 1)),
                                 src_node=int(conn.get("srcNode", 0)),
                                 sid=int(conn.get("sid", 0)))
    if t == "cip":
        return mod.build_request(str(function), params,
                                 session=int(conn.get("session", 0)))
    raise ValueError(f"未知传输类型: {t}")


def _parse(protocol: str, request: bytes, response: bytes, function, params: dict) -> dict:
    info = PROTOCOLS[protocol]
    mod = info["module"]
    t = info["transport"]
    if t in ("tcp", "rtu"):
        return mod.parse_response(request, response, int(function), transport=t, params=params)
    return mod.parse_response(request, response, str(function), params=params)


def _simulate(protocol: str, request: bytes, transport: str = "tcp") -> bytes:
    sim = STATE.simulator(protocol)
    if protocol in ("modbus_tcp", "modbus_rtu"):
        return sim.apply(request, transport=transport)
    return sim.apply(request)


def _tcp_exchange(host: str, port: int, request: bytes, timeout: float) -> bytes:
    """真机 TCP 收发一次（短连接），返回原始响应字节。"""
    if not host:
        raise ValueError("真机模式需要填写目标 IP/主机")
    if not (1 <= port <= 65535):
        raise ValueError(f"非法端口: {port}")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks = []
        while True:
            try:
                part = sock.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
            # 响应已收到就尽快返回（工业设备通常单次来回一帧）
            if len(part) < 4096:
                break
        return b"".join(chunks)


def execute(protocol: str, function, params: dict, mode: str = "simulator",
            conn: dict | None = None, timeout: float = 3.0) -> OpResult:
    """执行一次协议操作，返回完整 OpResult。"""
    conn = conn or {}
    result = OpResult(mode=mode)
    if protocol not in PROTOCOLS:
        result.error = f"不支持的协议: {protocol}"
        return result
    info = PROTOCOLS[protocol]
    t0 = time.perf_counter()
    try:
        request = _build(protocol, function, params, conn)
        result.request_hex = hexstr(request)
        if mode == "simulator":
            response = _simulate(protocol, request, info["transport"])
            result.transport = "内存模拟从站"
        elif mode == "serial":
            if protocol != "modbus_rtu":
                raise ValueError("串口直连仅支持 Modbus RTU 协议")
            response = serialport.exchange(conn, request, timeout)
            p = serialport.normalize_params(conn)
            result.transport = f"串口 {p['port']} @ {p['baudrate']}"
        else:
            host = conn.get("host", "127.0.0.1")
            port = int(conn.get("port", PROTOCOLS[protocol]["defaultPort"]))
            response = _tcp_exchange(host, port, request, timeout)
            result.transport = f"TCP {host}:{port}"
        if not response:
            raise ValueError("未收到响应（设备未应答或端口不可达）")
        result.response_hex = hexstr(response)
        parsed = _parse(protocol, request, response, function, params)
        result.parsed = parsed
        result.values = parsed.get("values", [])
        result.ok = parsed.get("ok", False)
        if not result.ok:
            result.error = parsed.get("error") or "设备返回异常"
    except Exception as exc:                      # noqa: BLE001 - 统一转成用户可读错误
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
    result.elapsed_ms = (time.perf_counter() - t0) * 1000
    return result


def snapshot(protocol: str) -> dict:
    if protocol in PROTOCOLS:
        try:
            return STATE.simulator(protocol).snapshot()
        except Exception:
            return {}
    return {}


def reset(protocol: str | None = None):
    STATE.reset(protocol)
