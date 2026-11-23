"""
mitsubishi.py - 三菱 MC 协议（Qna 3E 二进制帧）编解码 + 模拟 PLC

帧结构（Qna 3E Binary）：
  副头(2) 50 00 | 网络(1) 00 | 站号(1) FF | 处理器(1) FF | 请求长度(2,LE)
  指令(2,LE) | 子指令(2,LE) | 软元件码(1) | 首地址(3,LE) | 点数(2,LE) | 数据...
响应副头 D0 00，第 10 字节起为结束码（0000=正常）。
字数据低字节在前；位数据按 4bit 压缩，1=ON。
"""
from __future__ import annotations

from .utils import le16, u16le, bits_to_bytes, bytes_to_bits

FUNCTIONS = [
    {"code": "0401", "name": "批量读字", "en": "Read Words", "access": "read",  "kind": "words", "params": ["device", "addr", "count"]},
    {"code": "1401", "name": "批量写字", "en": "Write Words", "access": "write", "kind": "words", "params": ["device", "addr", "values"]},
    {"code": "0403", "name": "批量读位", "en": "Read Bits", "access": "read",  "kind": "bits",  "params": ["device", "addr", "count"]},
    {"code": "1403", "name": "批量写位", "en": "Write Bits", "access": "write", "kind": "bits",  "params": ["device", "addr", "values"]},
]
FUNC_BY_CODE = {f["code"]: f for f in FUNCTIONS}

# 软元件代码（二进制 3E）：D=0xA8 M=0x90 X=0x9C Y=0x9D W=0xB4 L=0x92 R=0xAF ZR=0xB0
DEVICES = {
    "D": 0xA8, "M": 0x90, "X": 0x9C, "Y": 0x9D,
    "W": 0xB4, "L": 0x92, "R": 0xAF, "ZR": 0xB0,
}
DEVICE_NAMES = {v: k for k, v in DEVICES.items()}
BIT_DEVICES = {"M", "X", "Y", "L"}


def _dev_code(device: str) -> int:
    d = device.upper().strip()
    if d not in DEVICES:
        raise ValueError(f"不支持的软元件: {device}（可选 {', '.join(DEVICES)}）")
    return DEVICES[d]


def _code_to_hex(code: int) -> bytes:
    """命令码字符串 0401 -> 小端字节 01 04。"""
    v = int(code, 16)
    return le16(v)


# ---------------------------------------------------------------------------
# 请求构造
# ---------------------------------------------------------------------------
def build_request(command: str, params: dict, network: int = 0,
                  station: int = 255, processor: int = 255) -> bytes:
    fc = str(command).strip()
    if fc not in FUNC_BY_CODE:
        raise ValueError(f"不支持的 MC 指令: {fc}")
    dev = _dev_code(params.get("device", "D"))
    addr = int(params.get("addr", 0))
    cmd = _code_to_hex(fc)
    subcmd = le16(0)
    dev_bytes = bytes([dev]) + (addr & 0xFFFFFF).to_bytes(3, "little")

    data = b""
    if fc in ("0401", "1401"):
        words = [int(v) & 0xFFFF for v in params.get("values", [])]
        count = len(words) if fc == "1401" else int(params.get("count", 1))
        data = b"".join(le16(w) for w in words) if fc == "1401" else b""
        body = cmd + subcmd + dev_bytes + le16(count) + data
    else:  # 0403 / 1403
        bits = [1 if v else 0 for v in params.get("values", [])]
        count = len(bits) if fc == "1403" else int(params.get("count", 1))
        data = bits_to_bytes(bits) if fc == "1403" else b""
        body = cmd + subcmd + dev_bytes + le16(count) + data

    header = bytes([0x50, 0x00, network & 0xFF, station & 0xFF,
                    processor & 0xFF]) + le16(len(body))
    return header + body


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def parse_response(request: bytes, response: bytes, command: str,
                   params: dict | None = None) -> dict:
    if len(response) < 9:
        raise ValueError("MC 响应帧过短")
    sub = response[0:2]
    if sub != b"\xD0\x00":
        raise ValueError(f"非法响应副头: {sub.hex().upper()}")
    end_code = u16le(response, 7)   # D0 00(2) 网络/站/处理器(3) 长度(2) -> 结束码在偏移 7
    result = {"command": command, "ok": end_code == 0,
              "endCode": f"{end_code:04X}", "values": []}
    if end_code != 0:
        result["error"] = f"PLC 结束码 {end_code:04X}"
        return result
    info = FUNC_BY_CODE.get(command, {})
    raw_count = (params or {}).get("count", (params or {}).get("values", 0))
    count = len(raw_count) if isinstance(raw_count, (list, tuple)) else int(raw_count)
    payload = response[9:]         # 结束码之后为数据区
    if command == "0401":
        result["values"] = [u16le(payload, i) for i in range(0, len(payload) - 1, 2)]
        result["display"] = " ".join(str(v) for v in result["values"])
    elif command == "0403":
        result["values"] = bytes_to_bits(payload, count)
        result["display"] = " ".join(str(v) for v in result["values"])
    else:
        result["display"] = "写入成功"
    return result


# ---------------------------------------------------------------------------
# 模拟 PLC
# ---------------------------------------------------------------------------
class MitsubishiSimulator:
    """内存软元件表：D/W/R 字区 + M/X/Y/L 位区。"""

    def __init__(self, seed: int = 1):
        self.words: dict[tuple[str, int], int] = {}
        self.bits: dict[tuple[str, int], int] = {}
        self.seed = seed

    def _get_word(self, dev, addr):
        return self.words.get((dev, addr), (addr * 11 + self.seed * 17) & 0xFFFF)

    def _get_bit(self, dev, addr):
        return self.bits.get((dev, addr), (addr + self.seed) % 3 == 0)

    def apply(self, frame: bytes) -> bytes:
        if len(frame) < 12:
            return b""
        cmd = int.from_bytes(frame[7:9], "little")
        dev = DEVICE_NAMES.get(frame[11], "D")
        addr = int.from_bytes(frame[12:15], "little")
        count = u16le(frame, 15)
        data = frame[17:]
        end_ok = b"\x00\x00"

        if cmd == 0x0401:                      # 读字
            payload = b"".join(le16(self._get_word(dev, addr + i)) for i in range(count))
            body = b"\x00\x00" + payload
        elif cmd == 0x1401:                    # 写字
            for i in range(min(count, len(data) // 2)):
                self.words[(dev, addr + i)] = u16le(data, i * 2)
            body = end_ok
        elif cmd == 0x0403:                    # 读位
            bits = [1 if self._get_bit(dev, addr + i) else 0 for i in range(count)]
            body = end_ok + bits_to_bytes(bits)
        elif cmd == 0x1403:                    # 写位
            bits = bytes_to_bits(data, count)
            for i, b in enumerate(bits):
                self.bits[(dev, addr + i)] = bool(b)
            body = end_ok
        else:                                   # 非法指令
            body = le16(0x4002)

        length = len(body)
        return b"\xD0\x00" + frame[2:5] + le16(length) + body

    def snapshot(self) -> dict:
        return {
            "D": [self._get_word("D", i) for i in range(32)],
            "M": [1 if self._get_bit("M", i) else 0 for i in range(32)],
        }
