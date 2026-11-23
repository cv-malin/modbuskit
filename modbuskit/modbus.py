"""
modbus.py - Modbus TCP / RTU 协议编解码 + 模拟从站

支持功能码：
  0x01 读线圈        0x02 读离散输入
  0x03 读保持寄存器  0x04 读输入寄存器
  0x05 写单线圈      0x06 写单寄存器
  0x0F 写多线圈      0x10 写多寄存器
异常响应：功能码 | 0x80 + 异常码（0x01 非法功能 / 0x02 非法地址 / 0x03 非法数据）
"""
from __future__ import annotations

from .utils import (be16, u16be, crc16_modbus, bits_to_bytes, bytes_to_bits,
                    words_to_bytes, bytes_to_words)

# ---------------------------------------------------------------------------
# 元数据
# ---------------------------------------------------------------------------
FUNCTIONS = [
    {"code": 1,  "name": "读线圈",       "en": "Read Coils",           "access": "read",  "kind": "bits",  "params": ["addr", "count"]},
    {"code": 2,  "name": "读离散输入",   "en": "Read Discrete Inputs",  "access": "read",  "kind": "bits",  "params": ["addr", "count"]},
    {"code": 3,  "name": "读保持寄存器", "en": "Read Holding Registers","access": "read",  "kind": "words", "params": ["addr", "count"]},
    {"code": 4,  "name": "读输入寄存器", "en": "Read Input Registers",  "access": "read",  "kind": "words", "params": ["addr", "count"]},
    {"code": 5,  "name": "写单线圈",     "en": "Write Single Coil",     "access": "write", "kind": "bit",   "params": ["addr", "value"]},
    {"code": 6,  "name": "写单寄存器",   "en": "Write Single Register", "access": "write", "kind": "word",  "params": ["addr", "value"]},
    {"code": 15, "name": "写多线圈",     "en": "Write Multiple Coils",  "access": "write", "kind": "bits",  "params": ["addr", "values"]},
    {"code": 16, "name": "写多寄存器",   "en": "Write Multiple Regs",   "access": "write", "kind": "words", "params": ["addr", "values"]},
]
FUNC_BY_CODE = {f["code"]: f for f in FUNCTIONS}

EXCEPTION_DESC = {
    1: "非法功能码", 2: "非法数据地址", 3: "非法数据值",
    4: "从站设备故障", 5: "确认", 6: "从站忙", 10: "目标路径不可用",
}


# ---------------------------------------------------------------------------
# 请求构造
# ---------------------------------------------------------------------------
def build_pdu(function: int, params: dict) -> bytes:
    """构造 Modbus PDU（功能码 + 数据域）。"""
    fc = int(function)
    addr = int(params.get("addr", 0))
    count = int(params.get("count", 1))
    if fc in (1, 2, 3, 4):
        return bytes([fc]) + be16(addr) + be16(count)
    if fc == 5:
        value = 1 if params.get("value", 0) else 0
        return bytes([fc]) + be16(addr) + bytes([0xFF, 0x00]) if value else bytes([fc]) + be16(addr) + b"\x00\x00"
    if fc == 6:
        return bytes([fc]) + be16(addr) + be16(int(params.get("value", 0)))
    if fc == 15:
        bits = [1 if v else 0 for v in params.get("values", [])]
        data = bits_to_bytes(bits)
        return bytes([fc]) + be16(addr) + be16(len(bits)) + bytes([len(data)]) + data
    if fc == 16:
        words = [int(v) & 0xFFFF for v in params.get("values", [])]
        data = words_to_bytes(words)
        return bytes([fc]) + be16(addr) + be16(len(words)) + bytes([len(data)]) + data
    raise ValueError(f"不支持的功能码: {fc}")


def build_request(function: int, params: dict, transport: str = "tcp",
                  unit: int = 1, transaction: int = 1) -> bytes:
    """构造完整 ADU。transport: 'tcp' -> MBAP+PDU；'rtu' -> 地址+PDU+CRC。"""
    pdu = build_pdu(function, params)
    if transport == "tcp":
        mbap = be16(transaction) + b"\x00\x00" + be16(len(pdu) + 1) + bytes([unit & 0xFF])
        return mbap + pdu
    if transport == "rtu":
        frame = bytes([unit & 0xFF]) + pdu
        crc = crc16_modbus(frame)
        return frame + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    raise ValueError(f"不支持的传输方式: {transport}")


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def split_adu(frame: bytes, transport: str = "tcp") -> bytes:
    """从 ADU 中取出 PDU，并校验基本完整性。"""
    if transport == "tcp":
        if len(frame) < 8:
            raise ValueError("Modbus TCP 帧过短")
        length = u16be(frame, 4)
        if len(frame) < 6 + length:
            raise ValueError("MBAP 长度与实际帧长不符")
        return frame[7:]
    if transport == "rtu":
        if len(frame) < 5:
            raise ValueError("Modbus RTU 帧过短")
        body, crc_bytes = frame[:-2], frame[-2:]
        crc = crc16_modbus(body)
        if bytes([crc & 0xFF, (crc >> 8) & 0xFF]) != crc_bytes:
            raise ValueError(f"CRC 校验失败: 期望 {crc:04X}, 实际 {crc_bytes.hex().upper()}")
        return body[1:]
    raise ValueError(f"不支持的传输方式: {transport}")


def parse_response(request: bytes, response: bytes, function: int,
                   transport: str = "tcp", params: dict | None = None) -> dict:
    """解析响应 PDU，返回 {function, ok, values, exception, ...}。"""
    params = params or {}
    pdu = split_adu(response, transport)
    if not pdu:
        raise ValueError("空响应")
    fc = pdu[0]
    if fc & 0x80:
        code = pdu[1] if len(pdu) > 1 else 0
        return {"function": fc & 0x7F, "ok": False, "exception": code,
                "exceptionDesc": EXCEPTION_DESC.get(code, "未知异常"), "values": []}
    info = FUNC_BY_CODE.get(function, {})
    kind = info.get("kind", "words")
    result: dict = {"function": fc, "ok": True, "exception": 0, "values": []}

    if fc in (1, 2):
        count = int(params.get("count", 0))
        if len(pdu) < 2:
            raise ValueError("读位响应缺少字节数")
        nbytes = pdu[1]
        result["byteCount"] = nbytes
        result["values"] = bytes_to_bits(pdu[2:2 + nbytes], count)
        result["display"] = " ".join(str(v) for v in result["values"])
    elif fc in (3, 4):
        if len(pdu) < 2:
            raise ValueError("读寄存器响应缺少字节数")
        nbytes = pdu[1]
        result["byteCount"] = nbytes
        result["values"] = bytes_to_words(pdu[2:2 + nbytes])
        result["display"] = " ".join(str(v) for v in result["values"])
    elif fc == 5:
        result["addr"] = u16be(pdu, 1)
        result["value"] = 1 if u16be(pdu, 3) == 0xFF00 else 0
        result["values"] = [result["value"]]
        result["display"] = str(result["value"])
    elif fc == 6:
        result["addr"] = u16be(pdu, 1)
        result["value"] = u16be(pdu, 3)
        result["values"] = [result["value"]]
        result["display"] = str(result["value"])
    elif fc in (15, 16):
        result["addr"] = u16be(pdu, 1)
        result["count"] = u16be(pdu, 3)
        result["display"] = f"写入 {result['count']} 个{'位' if fc == 15 else '寄存器'}"
    return result


# ---------------------------------------------------------------------------
# 模拟从站
# ---------------------------------------------------------------------------
class ModbusSimulator:
    """内存从站：持保持/输入寄存器、线圈、离散输入四张表，按请求生成合规响应。"""

    def __init__(self, seed: int = 1):
        self.unit = 1
        self.holding = [(i * 7 + seed * 13) & 0xFFFF for i in range(100)]
        self.input_regs = [(i * 3 + seed * 5) & 0xFFFF for i in range(100)]
        self.coils = [(i + seed) % 3 == 0 for i in range(128)]
        self.discrete = [(i + seed) % 5 == 0 for i in range(128)]

    def apply(self, frame: bytes, transport: str = "tcp") -> bytes:
        pdu = split_adu(frame, transport)
        if not pdu:
            return b""
        fc = pdu[0]
        template = build_request(fc, {"addr": 0, "count": 1, "value": 0, "values": [0]},
                                 transport, transaction=u16be(frame, 0) if transport == "tcp" else 1)
        out_pdu = self._handle(fc, pdu)
        if transport == "tcp":
            unit = frame[6] if len(frame) > 6 else 1
            tid = frame[0:2]
            return tid + b"\x00\x00" + be16(len(out_pdu) + 1) + bytes([unit]) + out_pdu
        unit = frame[0] if frame else 1
        body = bytes([unit]) + out_pdu
        crc = crc16_modbus(body)
        return body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    def _handle(self, fc: int, pdu: bytes) -> bytes:
        if fc not in FUNC_BY_CODE:
            return bytes([fc | 0x80, 1])
        addr = u16be(pdu, 1)
        try:
            if fc == 1:   # 读线圈
                count = u16be(pdu, 3)
                bits = [1 if self.coils[addr + i] else 0 for i in range(count)]
                return bytes([fc, len(bits_to_bytes(bits))]) + bits_to_bytes(bits)
            if fc == 2:   # 读离散输入
                count = u16be(pdu, 3)
                bits = [1 if self.discrete[addr + i] else 0 for i in range(count)]
                return bytes([fc, len(bits_to_bytes(bits))]) + bits_to_bytes(bits)
            if fc == 3:   # 读保持寄存器
                count = u16be(pdu, 3)
                words = [self.holding[addr + i] for i in range(count)]
                return bytes([fc, len(words) * 2]) + words_to_bytes(words)
            if fc == 4:   # 读输入寄存器
                count = u16be(pdu, 3)
                words = [self.input_regs[addr + i] for i in range(count)]
                return bytes([fc, len(words) * 2]) + words_to_bytes(words)
            if fc == 5:   # 写单线圈
                value = u16be(pdu, 3) == 0xFF00
                self.coils[addr] = value
                return pdu[:5]
            if fc == 6:   # 写单寄存器
                self.holding[addr] = u16be(pdu, 3)
                return pdu[:5]
            if fc == 15:  # 写多线圈
                count = u16be(pdu, 3)
                nbytes = pdu[5]
                bits = bytes_to_bits(pdu[6:6 + nbytes], count)
                for i, b in enumerate(bits):
                    self.coils[addr + i] = bool(b)
                return bytes([fc]) + be16(addr) + be16(count)
            if fc == 16:  # 写多寄存器
                count = u16be(pdu, 3)
                nbytes = pdu[5]
                words = bytes_to_words(pdu[6:6 + nbytes])
                for i, w in enumerate(words):
                    self.holding[addr + i] = w
                return bytes([fc]) + be16(addr) + be16(count)
        except IndexError:
            return bytes([fc | 0x80, 2])  # 非法地址
        except Exception:
            return bytes([fc | 0x80, 3])  # 非法数据
        return bytes([fc | 0x80, 1])

    def snapshot(self) -> dict:
        """返回当前寄存器/线圈值（供 UI 显示内存镜像）。"""
        return {
            "holding": self.holding[:32],
            "input": self.input_regs[:32],
            "coils": [1 if v else 0 for v in self.coils[:64]],
            "discrete": [1 if v else 0 for v in self.discrete[:64]],
        }
