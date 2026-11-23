"""
omron.py - 欧姆龙 FINS/TCP 协议编解码 + 模拟 PLC

帧结构（FINS/TCP）：
  TCP 头: 0x00000000(固定) | 长度(4,BE) | 命令 0x00000002(发送FINS指令) | 错误码(4)
  FINS 头: ICF=0x80 RSV=0x00 GCT=0x02 | DNA DA1 DA2 SNA SA1 SA2 SID (共10字节)
  指令域: 命令(2,BE) 0x0101读DM / 0x0102写DM | 存储区码(1) 0x82=DM | 地址(2,BCD) | 点数(2,BCD) | 数据
响应结束码: 0000 正常。
"""
from __future__ import annotations

from .utils import be16, be32, u16be, bcd2int, int2bcd, words_to_bytes, bytes_to_words

FUNCTIONS = [
    {"code": "0101", "name": "读 DM 区", "en": "Read DM Area", "access": "read",  "kind": "words", "params": ["addr", "count"]},
    {"code": "0102", "name": "写 DM 区", "en": "Write DM Area", "access": "write", "kind": "words", "params": ["addr", "values"]},
    {"code": "0101-CIO", "name": "读 CIO 区", "en": "Read CIO Area", "access": "read", "kind": "words", "params": ["addr", "count"]},
    {"code": "0102-CIO", "name": "写 CIO 区", "en": "Write CIO Area", "access": "write", "kind": "words", "params": ["addr", "values"]},
]
FUNC_BY_CODE = {f["code"]: f for f in FUNCTIONS}
AREA_CODES = {"DM": 0x82, "CIO": 0xB0, "WR": 0xB1, "H": 0xB2, "AR": 0xB3}


def _fins_header(dst_node: int = 1, src_node: int = 0, sid: int = 0) -> bytes:
    return bytes([0x80, 0x00, 0x02, 0x00, dst_node & 0xFF, 0x00,
                  0x00, src_node & 0xFF, 0x00, sid & 0xFF])


def _parse_area(command: str) -> tuple[int, int]:
    """返回 (FINS命令码, 存储区码)。'0101-CIO' -> (0x0101, 0xB0)。"""
    parts = command.split("-")
    code = int(parts[0], 16)
    area = "DM" if len(parts) == 1 else parts[1].upper()
    if area not in AREA_CODES:
        raise ValueError(f"不支持的存储区: {area}")
    return code, AREA_CODES[area]


# ---------------------------------------------------------------------------
# 请求构造
# ---------------------------------------------------------------------------
def build_request(command: str, params: dict, dst_node: int = 1,
                  src_node: int = 0, sid: int = 0) -> bytes:
    code, area = _parse_area(command)
    addr = int(params.get("addr", 0))
    fins = _fins_header(dst_node, src_node, sid) + be16(code) + bytes([area])
    if code == 0x0101:                       # 读
        count = int(params.get("count", 1))
        fins += int2bcd(addr, 2) + int2bcd(count, 2)
    elif code == 0x0102:                     # 写
        words = [int(v) & 0xFFFF for v in params.get("values", [])]
        fins += int2bcd(addr, 2) + int2bcd(len(words), 2) + words_to_bytes(words)
    else:
        raise ValueError(f"不支持的 FINS 命令: {command}")
    # FINS/TCP: 长度 = FINS 帧长 + 8（命令4 + 错误码4）
    return be32(0) + be32(len(fins) + 8) + be32(2) + be32(0) + fins


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def parse_response(request: bytes, response: bytes, command: str,
                   params: dict | None = None) -> dict:
    if len(response) < 24:
        raise ValueError("FINS 响应帧过短")
    tcp_cmd = u16be(response, 8)
    error = int.from_bytes(response[12:16], "big")
    fins = response[16:]
    # FINS 响应帧: 头(10) 命令(2) 结束码(2) 数据 -> 结束码在偏移 12
    end_code = u16be(fins, 12)
    result = {"command": command, "ok": error == 0 and end_code == 0,
              "tcpCommand": tcp_cmd, "tcpError": error,
              "endCode": f"{end_code:04X}", "values": []}
    if not result["ok"]:
        result["error"] = f"FINS 异常: TCP={error}, END={end_code:04X}"
        return result
    code, _ = _parse_area(command)
    payload = fins[14:]
    if code == 0x0101:
        result["values"] = bytes_to_words(payload)
        result["display"] = " ".join(str(v) for v in result["values"])
    else:
        result["display"] = "写入成功"
    return result


# ---------------------------------------------------------------------------
# 模拟 PLC
# ---------------------------------------------------------------------------
class OmronSimulator:
    """内存 DM/CIO 字区。地址以 BCD 编码出现在报文里。"""

    def __init__(self, seed: int = 1):
        self.areas: dict[int, dict[int, int]] = {0x82: {}, 0xB0: {}}
        self.seed = seed

    def _get(self, area, addr):
        return self.areas.get(area, {}).get(addr, (addr * 5 + self.seed * 23) & 0xFFFF)

    def apply(self, frame: bytes) -> bytes:
        if len(frame) < 28:
            return b""
        fins = frame[16:]
        if len(fins) < 12:
            return b""
        cmd = u16be(fins, 10)
        area = fins[12]
        addr = bcd2int(fins[13:15])
        count = bcd2int(fins[15:17])
        data = fins[17:]

        # 构造响应 FINS 头（交换源/目标节点）
        src = fins[4]
        dst = fins[7]
        resp_head = bytes([0xC0, 0x00, 0x02, dst, src, 0x00,
                           0x00, fins[7], 0x00, fins[9]]) + be16(cmd)
        end_ok = b"\x00\x00"
        if cmd == 0x0101:
            payload = b"".join(be16(self._get(area, addr + i)) for i in range(count))
            body = resp_head + end_ok + payload
        elif cmd == 0x0102:
            words = bytes_to_words(data)
            for i, w in enumerate(words):
                self.areas.setdefault(area, {})[addr + i] = w
            body = resp_head + end_ok
        else:
            body = resp_head + be16(0x0201)

        return be32(0) + be32(len(body) + 8) + be32(2) + be32(0) + body

    def snapshot(self) -> dict:
        return {"DM": [self._get(0x82, i) for i in range(32)]}
