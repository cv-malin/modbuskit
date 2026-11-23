"""
utils.py - ModbusKit 协议引擎公共工具层

提供：十六进制格式化/解析、Modbus CRC16、字节拆分/合并、统一数据模型。
所有函数零第三方依赖，可在 PyInstaller 打包环境中直接使用。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# 十六进制工具
# ---------------------------------------------------------------------------
def hexstr(data: bytes | bytearray, sep: str = " ", upper: bool = True) -> str:
    """字节序列 -> '50 00 00 FF' 形式；upper 控制大小写。"""
    s = sep.join(f"{b:02x}" for b in data)
    return s.upper() if upper else s


def hexdump(data: bytes | bytearray, width: int = 16) -> str:
    """带偏移量的多行 hex 转储，便于报文监视窗口显示。"""
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:04X}  {h:<{width * 3 - 1}}  {a}")
    return "\n".join(out)


def unhex(text: str) -> bytes:
    """十六进制字符串 -> bytes，容错处理空格、逗号、0x 前缀、换行。"""
    import re
    # 先去掉 0x/0X 前缀，再抽取十六进制字符
    s = re.sub(r"0[xX]", "", text)
    s = "".join(ch for ch in s if ch in "0123456789abcdefABCDEF")
    if len(s) % 2:
        s = "0" + s
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


# ---------------------------------------------------------------------------
# 数值 / 字节工具
# ---------------------------------------------------------------------------
def crc16_modbus(data: bytes) -> int:
    """Modbus RTU CRC16（多项式 0xA001，初值 0xFFFF，低字节在前）。"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def be16(v: int) -> bytes:
    """大端 16 位（Modbus / FINS 地址与数量）。"""
    return (v & 0xFFFF).to_bytes(2, "big")


def le16(v: int) -> bytes:
    """小端 16 位（三菱 MC / CIP 长度与数值）。"""
    return (v & 0xFFFF).to_bytes(2, "little")


def be32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "big")


def le32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def u16be(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off:off + 2], "big")


def u16le(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off:off + 2], "little")


def u32le(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off:off + 4], "little")


def bcd2int(buf: bytes) -> int:
    """BCD 编码 -> 整数（FINS 地址/数量使用 BCD）。"""
    v = 0
    for b in buf:
        v = v * 100 + ((b >> 4) * 10 + (b & 0x0F))
    return v


def int2bcd(value: int, width: int) -> bytes:
    """整数 -> BCD 编码，固定字节宽度。"""
    out = bytearray(width)
    for i in range(width - 1, -1, -1):
        out[i] = ((value % 10) | ((value // 10 % 10) << 4)) & 0xFF
        value //= 100
    return bytes(out)


def bits_to_bytes(bits: list[int] | list[bool]) -> bytes:
    """位列表 -> 字节串（低位在前，符合 Modbus 线圈打包规则）。"""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def bytes_to_bits(data: bytes, count: int) -> list[int]:
    """字节串 -> 位列表（低位在前）。"""
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(min(count, len(data) * 8))]


def words_to_bytes(words: list[int]) -> bytes:
    """16 位字列表 -> 大端字节串。"""
    out = bytearray()
    for w in words:
        out += be16(int(w) & 0xFFFF)
    return bytes(out)


def bytes_to_words(data: bytes) -> list[int]:
    """大端字节串 -> 16 位字列表。"""
    return [u16be(data, i) for i in range(0, len(data) - 1, 2)]


# ---------------------------------------------------------------------------
# 统一操作结果
# ---------------------------------------------------------------------------
@dataclass
class OpResult:
    """一次读写操作的完整结果，序列化后直接返回给 Web 层。"""
    ok: bool = False
    request_hex: str = ""
    response_hex: str = ""
    values: list = field(default_factory=list)
    parsed: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    mode: str = "simulator"
    elapsed_ms: float = 0.0
    transport: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "requestHex": self.request_hex,
            "responseHex": self.response_hex,
            "values": self.values,
            "parsed": self.parsed,
            "error": self.error,
            "mode": self.mode,
            "elapsedMs": round(self.elapsed_ms, 2),
            "transport": self.transport,
        }
