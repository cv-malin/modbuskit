"""
ab.py - Allen-Bradley (罗克韦尔) Ethernet/IP CIP 协议编解码 + 模拟 PLC

采用 CIP 未连接报文（UCMM）封装，走 EtherNet/IP 显式报文（端口 44818）：
  EIP 封装头(24) = 命令(2LE) 长度(2LE) 会话(4LE) 状态(4LE) 上下文(8) 选项(4LE)
  命令 0x006F = SendRRData（发送/接收数据）
  CPF 公共包格式 = 接口句柄(4) 超时(2LE) 条目数(2LE) + 条目[类型(2LE) 长度(2LE) 数据]
    条目1: 空地址 0x0000；条目2: 未连接消息 0x00B1
  CIP 消息 = 服务码(1) 路径大小(1,字) 路径字节... 服务特定数据
  服务: 0x0E Get_Attribute_Single(读) / 0x10 Set_Attribute_Single(写)
  路径: 0x20 类(1) 0x24 实例(1) 0x30 属性(1)，类 0x02=Message(标量标签)
"""
from __future__ import annotations

from .utils import le16, le32, u16le, u32le

FUNCTIONS = [
    {"code": "0E", "name": "读标签 (Get Attribute)", "en": "Get Attribute Single", "access": "read",  "kind": "tag", "params": ["tag", "instance"]},
    {"code": "10", "name": "写标签 (Set Attribute)", "en": "Set Attribute Single", "access": "write", "kind": "tag", "params": ["tag", "instance", "value"]},
    {"code": "63", "name": "识别设备 (List Identity)", "en": "List Identity", "access": "read",  "kind": "identity", "params": []},
]
FUNC_BY_CODE = {f["code"]: f for f in FUNCTIONS}

EIP_PORT = 44818


def _cip_path(instance: int, attribute: int = 3) -> bytes:
    """构造 CIP 端口路径：Class 0x02 (Message) / Instance / Attribute Value。"""
    return bytes([0x20, 0x02, 0x24, instance & 0xFF, 0x30, attribute & 0xFF])


def _cip_message(service: int, instance: int, value: int | None = None) -> bytes:
    path = _cip_path(instance)
    path_words = (len(path) + 1) // 2   # 路径字数（向上取整）
    msg = bytes([service, path_words]) + path
    if service == 0x10:                # Set Attribute: 4 字节值 + 类型 0x00C3(DINT)
        msg += le32(int(value or 0)) + le16(0x00C3)
    return msg


def _encapsulate(cmd: int, payload: bytes, session: int = 0) -> bytes:
    """EIP 封装头 + payload。"""
    header = le16(cmd) + le16(len(payload)) + le32(session) + le32(0) + b"\x00" * 8 + le32(0)
    return header + payload


def _send_rr_data(cip: bytes) -> bytes:
    """将 CIP 消息封装为 SendRRData 的 CPF 载荷。"""
    cpf = le32(0) + le16(0) + le16(2)          # 接口句柄 / 超时 / 条目数
    cpf += le16(0x0000) + le16(0)              # 条目1: Null Address
    cpf += le16(0x00B1) + le16(len(cip)) + cip  # 条目2: Unconnected Message
    return _encapsulate(0x006F, cpf)


# ---------------------------------------------------------------------------
# 请求构造
# ---------------------------------------------------------------------------
def build_request(command: str, params: dict, session: int = 0) -> bytes:
    code = str(command).strip()
    if code == "63":
        return _encapsulate(0x0063, b"")
    if code == "0E":
        return _send_rr_data(_cip_message(0x0E, int(params.get("instance", 1))))
    if code == "10":
        return _send_rr_data(_cip_message(0x10, int(params.get("instance", 1)),
                                          int(params.get("value", 0))))
    raise ValueError(f"不支持的 CIP 服务: {code}")


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def parse_response(request: bytes, response: bytes, command: str,
                   params: dict | None = None) -> dict:
    if len(response) < 24:
        raise ValueError("EIP 响应帧过短")
    cmd = u16le(response, 0)
    status = u32le(response, 8)
    result = {"command": command, "ok": status == 0,
              "eipCommand": f"0x{cmd:04X}", "status": status, "values": []}

    # List Identity 响应：返回产品名（ASCII，位于 Session Handle 之后）
    if command == "63":
        payload = response[24:]
        readable = "".join(chr(b) if 32 <= b < 127 else "" for b in payload)
        result["display"] = readable[:80] or "AB device detected"
        result["values"] = [readable[:80]]
        if status != 0:
            result["error"] = f"List Identity 状态 {status}"
        return result

    if status != 0:
        result["error"] = f"EIP 状态 0x{status:08X}"
        return result
    cpf = response[24:]
    # CPF: 接口句柄(4) 超时(2) 条目数(2) 条目1(4) 条目2头(4) -> CIP 从偏移 16 开始
    if len(cpf) < 16:
        result["error"] = "CPF 载荷过短"
        result["ok"] = False
        return result
    cip_off = 16
    if len(cpf) < cip_off + 4:
        result["error"] = "CIP 消息过短"
        result["ok"] = False
        return result
    service = cpf[cip_off] & 0x7F
    cip_status = cpf[cip_off + 2]
    result["cipService"] = f"0x{service:02X}"
    result["cipStatus"] = cip_status
    result["ok"] = cip_status == 0
    if cip_status != 0:
        result["error"] = f"CIP 状态 0x{cip_status:02X}"
        return result
    if service == 0x0E:                       # Get Attribute 响应 (0x8E & 0x7F)
        value = int.from_bytes(cpf[cip_off + 4:cip_off + 8], "little")
        result["values"] = [value]
        result["display"] = str(value)
    elif service == 0x10:                     # Set Attribute 响应 (0x90 & 0x7F)
        result["display"] = "写入成功"
    return result


# ---------------------------------------------------------------------------
# 模拟 PLC
# ---------------------------------------------------------------------------
class ABSimulator:
    """内存标签表（instance -> DINT 值）。"""

    def __init__(self, seed: int = 1):
        self.tags: dict[int, int] = {}
        self.seed = seed
        self.identity = "AB Simulator | CompactLogix L3X | 5069-L306ER"

    def _get(self, inst):
        return self.tags.get(inst, inst * 100 + self.seed * 7)

    def apply(self, frame: bytes) -> bytes:
        if len(frame) < 24:
            return b""
        cmd = u16le(frame, 0)
        session = u32le(frame, 4)
        if cmd == 0x0063:                      # List Identity
            payload = self.identity.encode("ascii", "ignore")
            return _encapsulate(0x0063, payload, session)
        if cmd == 0x006F:                      # SendRRData
            cpf = frame[24:]
            if len(cpf) < 16:
                return _encapsulate(0x006F, b"", session)
            cip = cpf[16:]
            if not cip:
                return _encapsulate(0x006F, b"", session)
            service = cip[0] & 0x7F
            # 解析路径：cip[1] 为路径字数，路径从偏移 2 开始，长度 = 字数*2
            path_end = 2 + (cip[1] & 0xFF) * 2
            inst = 1
            j = 2
            while j + 1 < path_end:
                if cip[j] == 0x24:             # Instance
                    inst = cip[j + 1]
                j += 2
            if service == 0x0E:                # Get Attribute
                reply = bytes([0x8E, 0x00, 0x00, 0x00]) + le32(self._get(inst))
            elif service == 0x10:              # Set Attribute — 值紧跟在路径之后
                value = int.from_bytes(cip[path_end:path_end + 4], "little")
                self.tags[inst] = value
                reply = bytes([0x90, 0x00, 0x00, 0x00])
            else:
                reply = bytes([service | 0x80, 0x00, 0x08, 0x00])
            return _send_rr_data(reply)
        return _encapsulate(cmd, b"", session)

    def snapshot(self) -> dict:
        return {"tags": {f"Tag_{k}": self._get(k) for k in range(1, 9)}}
