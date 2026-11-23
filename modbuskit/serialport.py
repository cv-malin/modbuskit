"""
serialport.py - 串口直连（RS485 / RS232）

基于 pyserial，供 Modbus RTU 真机模式使用。
- list_ports()：枚举本机 COM 口
- normalize_params()：校验并规范化串口参数
- exchange()：发送一帧并智能读取完整响应（按 Modbus RTU 帧长预读）
- test_port()：开关一次端口做连通性预检
"""
from __future__ import annotations

import time

PARITY_MAP = {"N": "N", "E": "E", "O": "O", "M": "M", "S": "S"}


def list_ports() -> list[dict]:
    """枚举本机串口，无 pyserial / 无硬件时返回空列表。"""
    try:
        from serial.tools import list_ports as lp
        return [{"device": p.device, "name": p.name, "description": p.description or p.device,
                 "hwid": p.hwid or ""} for p in lp.comports()]
    except Exception:
        return []


def normalize_params(conn: dict | None = None) -> dict:
    """校验串口参数，抛 ValueError 给出可读错误。"""
    c = conn or {}
    port = str(c.get("port", "")).strip()
    if not port:
        raise ValueError("串口模式需要选择 COM 口")
    baud = int(c.get("baudrate", 9600))
    if baud not in (300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200):
        raise ValueError(f"非法波特率: {baud}")
    size = int(c.get("bytesize", 8))
    if size not in (7, 8):
        raise ValueError(f"非法数据位: {size}")
    parity = str(c.get("parity", "N")).upper()[:1]
    if parity not in PARITY_MAP:
        raise ValueError(f"非法校验位: {parity}")
    stop = float(c.get("stopbits", 1))
    if stop not in (1, 1.5, 2):
        raise ValueError(f"非法停止位: {stop}")
    return {"port": port, "baudrate": baud, "bytesize": size,
            "parity": parity, "stopbits": stop}


def _serial(params: dict, timeout: float):
    import serial
    return serial.Serial(port=params["port"], baudrate=params["baudrate"],
                         bytesize=params["bytesize"], parity=params["parity"],
                         stopbits=params["stopbits"], timeout=timeout,
                         write_timeout=timeout)


def exchange(conn: dict | None, request: bytes, timeout: float = 1.0) -> bytes:
    """发送一帧，按 Modbus RTU 帧结构读取完整响应。"""
    p = normalize_params(conn)
    if not request:
        raise ValueError("空请求帧")
    with _serial(p, timeout) as ser:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        ser.write(request)
        ser.flush()
        head = ser.read(3)
        if len(head) < 3:
            return head
        func = head[1] & 0x7F
        if head[1] & 0x80:                       # 异常响应：unit + (fc|80) + code + CRC2
            need = 2
        elif func in (1, 2, 3, 4):               # 读响应：unit + fc + byteCount + data + CRC2
            need = head[2] + 2
        else:                                    # 写响应：unit + fc + addr2 + value2 + CRC2
            need = 5
        body = ser.read(need) if need else b""
        return head + body


def test_port(conn: dict | None, timeout: float = 0.5) -> dict:
    """开关一次端口，返回 {ok, message}。"""
    try:
        p = normalize_params(conn)
        with _serial(p, timeout):
            pass
        return {"ok": True,
                "message": f"串口可用 {p['port']} @ {p['baudrate']}-{p['bytesize']}{p['parity']}{p['stopbits']}"}
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}: {e}"}
