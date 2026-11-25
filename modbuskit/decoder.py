"""
decoder.py - 报文字段级解码（把十六进制拆成「字节区间 → 字段释义」）

为五种协议分别实现请求 / 响应的字段布局。前端拿到 fields 后：
- 每个字节渲染成可点击 span，点击高亮所属字段
- 右侧显示字段名、解析值、说明（tip）

每个字段结构：
  {"start": 字节起始偏移, "len": 字节数, "label": "字段名",
   "value": "可读值", "tip": "解释"}

纯标准库，零第三方依赖。
"""
from __future__ import annotations

from .utils import unhex, u16be, u16le, u32le, bcd2int, bytes_to_words, bytes_to_bits

# ---------------------------------------------------------------------------
# 公共辅助
# ---------------------------------------------------------------------------
def _f(start: int, length: int, label: str, value, tip: str = "") -> dict:
    return {"start": int(start), "len": int(length), "label": label,
            "value": str(value), "tip": tip}


def _hex(buf: bytes) -> str:
    return buf.hex(" ").upper()


def _safe(buf: bytes, start: int, length: int) -> bytes:
    if start < 0 or length <= 0 or start >= len(buf):
        return b""
    return buf[start:start + length]


def _modbus_fn_name(fc: int) -> str:
    names = {1: "读线圈", 2: "读离散输入", 3: "读保持寄存器", 4: "读输入寄存器",
             5: "写单线圈", 6: "写单寄存器", 15: "写多线圈", 16: "写多寄存器"}
    return names.get(fc & 0x7F, "未知功能码")


# ---------------------------------------------------------------------------
# Modbus TCP / RTU
# ---------------------------------------------------------------------------
def _decode_modbus(buf: bytes, direction: str, transport: str) -> list[dict]:
    fields: list[dict] = []
    tcp = transport == "tcp"
    if tcp:
        if len(buf) < 7:
            return []
        fields += [
            _f(0, 2, "事务 ID", u16be(buf, 0), "主机生成，用于匹配请求与响应"),
            _f(2, 2, "协议 ID", u16be(buf, 2), "0 = 标准 Modbus TCP"),
            _f(4, 2, "长度", u16be(buf, 4), "后续字节数（单元 ID + PDU）"),
            _f(6, 1, "单元 ID", buf[6], "从站地址 1-247；255 为广播"),
        ]
        pdu_off = 7
    else:
        if len(buf) < 5:
            return []
        fields.append(_f(0, 1, "从站地址", buf[0], "RTU 从站地址 1-247"))
        pdu_off = 1

    if len(buf) <= pdu_off:
        return fields
    fc = buf[pdu_off]
    exception = bool(fc & 0x80)
    if exception:
        fields.append(_f(pdu_off, 1, "异常功能码", f"0x{fc:02X}", "最高位为 1，表示异常响应"))
        if len(buf) > pdu_off + 1:
            code = buf[pdu_off + 1]
            desc = {1: "非法功能码", 2: "非法数据地址", 3: "非法数据值", 4: "设备故障",
                    5: "确认", 6: "设备忙"}.get(code, "未知异常")
            fields.append(_f(pdu_off + 1, 1, "异常码", f"0x{code:02X} · {desc}",
                             "诊断助手会给出排查步骤"))
        if not tcp:
            fields.append(_f(len(buf) - 2, 2, "CRC16", _hex(_safe(buf, len(buf) - 2, 2)),
                             "低字节在前，校验前面所有字节"))
        return fields

    fields.append(_f(pdu_off, 1, "功能码", f"0x{fc:02X} · {_modbus_fn_name(fc)}",
                     "0x01-0x10 标准 Modbus 功能码"))
    o = pdu_off + 1
    base = fc
    if base in (1, 2, 3, 4):
        if direction == "request":
            if len(buf) >= o + 4:
                fields.append(_f(o, 2, "起始地址", u16be(buf, o), "寄存器/线圈起始地址（0 基）"))
                fields.append(_f(o + 2, 2, "读取数量", u16be(buf, o + 2), "连续读取的点数"))
        else:
            if len(buf) > o:
                n = buf[o]
                fields.append(_f(o, 1, "字节数", n, "后续数据区的字节总数"))
                data = _safe(buf, o + 1, n)
                if data:
                    if base in (1, 2):
                        bits = bytes_to_bits(data, n * 8)
                        val = " ".join(str(b) for b in bits[:16]) + (" ..." if len(bits) > 16 else "")
                    else:
                        words = bytes_to_words(data)
                        val = " ".join(str(w) for w in words[:12]) + (" ..." if len(words) > 12 else "")
                    fields.append(_f(o + 1, n, "数据区", val, "按位或按字解析的返回数据"))
    elif base in (5, 6):
        if len(buf) >= o + 4:
            fields.append(_f(o, 2, "地址", u16be(buf, o), "目标寄存器/线圈地址"))
            v = u16be(buf, o + 2)
            fields.append(_f(o + 2, 2, "值", 1 if (base == 5 and v == 0xFF00) else v,
                             "写线圈时 0xFF00=ON，0x0000=OFF"))
    elif base in (15, 16):
        if len(buf) >= o + 5:
            fields.append(_f(o, 2, "起始地址", u16be(buf, o), "写入起始地址"))
            fields.append(_f(o + 2, 2, "写入数量", u16be(buf, o + 2), "位/寄存器个数"))
            n = buf[o + 4]
            fields.append(_f(o + 4, 1, "字节数", n, "后续数据区字节数"))
            data = _safe(buf, o + 5, n)
            if data:
                fields.append(_f(o + 5, n, "写入数据", _hex(data) if base == 15 else
                                 " ".join(str(w) for w in bytes_to_words(data)),
                                 "本次写入的实际数据"))
    if not tcp and len(buf) >= 2:
        fields.append(_f(len(buf) - 2, 2, "CRC16", _hex(_safe(buf, len(buf) - 2, 2)),
                         "低字节在前，校验前面所有字节"))
    return fields


# ---------------------------------------------------------------------------
# 三菱 MC 3E
# ---------------------------------------------------------------------------
def _decode_mc(buf: bytes, direction: str) -> list[dict]:
    if len(buf) < 9:
        return []
    fields = [
        _f(0, 2, "副头", _hex(buf[0:2]), "0x5000 = 请求，0xD000 = 响应"),
        _f(2, 1, "网络号", buf[2], "Multidrop 网络号，通常 0"),
        _f(3, 1, "站号", buf[3], "目标站号，255 = 本机"),
        _f(4, 1, "处理器号", buf[4], "多 CPU 时的处理器号，255 = 默认"),
        _f(5, 2, "请求长度", u16le(buf, 5), "副头之后的可变长度（小端）"),
    ]
    if buf[0] == 0xD0:  # 响应
        end = u16le(buf, 7)
        fields.append(_f(7, 2, "结束码", f"0x{end:04X}", "0x0000 = 正常，其余为错误码"))
        data = buf[9:]
        if data:
            fields.append(_f(9, len(data), "数据区", _hex(data[:32]) + (" ..." if len(data) > 32 else ""),
                             "字数据低字节在前"))
        return fields
    if len(buf) < 17:
        return fields
    code = u16le(buf, 7)
    names = {0x0401: "批量读字", 0x1401: "批量写字", 0x0403: "批量读位", 0x1403: "批量写位"}
    fields.append(_f(7, 2, "指令", f"0x{code:04X} · {names.get(code, '未知')}", "MC 3E 指令码（小端）"))
    fields.append(_f(9, 2, "子指令", u16le(buf, 9), "0 = 默认"))
    devices = {0xA8: "D", 0x90: "M", 0x9C: "X", 0x9D: "Y", 0xB4: "W", 0x92: "L", 0xAF: "R"}
    dev = devices.get(buf[11], f"0x{buf[11]:02X}")
    fields.append(_f(11, 1, "软元件", dev, "D/M/X/Y/W/L/R 等软元件代码"))
    addr = int.from_bytes(buf[12:15], "little")
    fields.append(_f(12, 3, "首地址", addr, "软元件起始编号（小端 3 字节）"))
    fields.append(_f(15, 2, "点数", u16le(buf, 15), "读/写的软元件点数"))
    data = buf[17:]
    if data:
        fields.append(_f(17, len(data), "数据区", _hex(data[:32]) + (" ..." if len(data) > 32 else ""),
                         "写指令时为写入值"))
    return fields


# ---------------------------------------------------------------------------
# 欧姆龙 FINS/TCP
# ---------------------------------------------------------------------------
def _decode_fins(buf: bytes, direction: str) -> list[dict]:
    if len(buf) < 16:
        return []
    fields = [
        _f(0, 4, "固定头", u32le(buf, 0), "FINS/TCP 固定为 0"),
        _f(4, 4, "长度", int.from_bytes(buf[4:8], "big"), "FINS 帧长 + 8"),
        _f(8, 4, "命令", int.from_bytes(buf[8:12], "big"), "2 = 发送 FINS 指令"),
        _f(12, 4, "错误码", int.from_bytes(buf[12:16], "big"), "0 = 无错误"),
    ]
    if len(buf) < 26:
        return fields
    fields += [
        _f(16, 3, "ICF/RSV/GCT", _hex(buf[16:19]), "信息控制字段 / 保留 / 网关计数"),
        _f(19, 3, "目标节点", _hex(buf[19:22]), "DNA/DA1/DA2，DA1 为目标节点号"),
        _f(22, 3, "源节点", _hex(buf[22:25]), "SNA/SA1/SA2"),
        _f(25, 1, "服务 ID", buf[25], "用于匹配请求与响应"),
    ]
    cmd = u16be(buf, 26)
    names = {0x0101: "读 DM/CIO 区", 0x0102: "写 DM/CIO 区"}
    fields.append(_f(26, 2, "FINS 命令", f"0x{cmd:04X} · {names.get(cmd, '其他')}", "0x0101 读 / 0x0102 写"))
    if direction == "response":
        code = u16be(buf, 28)
        fields.append(_f(28, 2, "结束码", f"0x{code:04X}", "0000 = 正常"))
        data = buf[30:]
        if data:
            fields.append(_f(30, len(data), "数据区", " ".join(str(w) for w in bytes_to_words(data)),
                             "字数据，高字节在前"))
        return fields
    if len(buf) < 29:
        return fields
    areas = {0x82: "DM", 0xB0: "CIO", 0xB1: "WR", 0xB2: "H", 0xB3: "AR"}
    fields.append(_f(28, 1, "存储区", areas.get(buf[28], f"0x{buf[28]:02X}"), "82=DM，B0=CIO"))
    if len(buf) >= 31:
        fields.append(_f(29, 2, "起始地址", bcd2int(buf[29:31]), "BCD 编码"))
    if len(buf) >= 33:
        fields.append(_f(31, 2, "点数", bcd2int(buf[31:33]), "BCD 编码"))
    data = buf[33:]
    if data:
        fields.append(_f(33, len(data), "写入数据", " ".join(str(w) for w in bytes_to_words(data)), ""))
    return fields


# ---------------------------------------------------------------------------
# AB Ethernet/IP CIP
# ---------------------------------------------------------------------------
def _decode_ab(buf: bytes, direction: str) -> list[dict]:
    if len(buf) < 24:
        return []
    cmd = u16le(buf, 0)
    cmds = {0x0063: "List Identity", 0x006F: "SendRRData", 0x0070: "SendUnitData"}
    fields = [
        _f(0, 2, "封装命令", f"0x{cmd:04X} · {cmds.get(cmd, '其他')}", "EIP 封装头命令字"),
        _f(2, 2, "长度", u16le(buf, 2), "后续载荷字节数"),
        _f(4, 4, "会话句柄", u32le(buf, 4), "0 = 未注册会话（UCMM）"),
        _f(8, 4, "状态", u32le(buf, 8), "0 = 成功"),
        _f(12, 8, "上下文", _hex(buf[12:20]), "发起方自定义标识"),
        _f(20, 4, "选项", u32le(buf, 20), "通常为 0"),
    ]
    payload = buf[24:]
    if cmd == 0x0063:
        ascii_val = "".join(chr(b) if 32 <= b < 127 else "" for b in payload)
        if ascii_val:
            fields.append(_f(24, len(payload), "设备标识", ascii_val[:80], "List Identity 返回的 ASCII 描述"))
        return fields
    if len(payload) < 16:
        return fields
    fields += [
        _f(24, 4, "接口句柄", u32le(payload, 0), "CPF 接口句柄，0 = UCMM"),
        _f(28, 2, "超时", u16le(payload, 4), "封装消息超时（毫秒）"),
        _f(30, 2, "条目数", u16le(payload, 6), "CPF 数据条目数量"),
        _f(32, 2, "条目 1 类型", u16le(payload, 8), "0x0000 = Null Address"),
        _f(34, 2, "条目 1 长度", u16le(payload, 10), "通常为 0"),
        _f(36, 2, "条目 2 类型", u16le(payload, 12), "0x00B1 = Unconnected Message"),
        _f(38, 2, "条目 2 长度", u16le(payload, 14), "CIP 消息字节数"),
    ]
    cip = payload[16:]
    if not cip:
        return fields
    svc = cip[0] & 0x7F
    names = {0x0E: "Get Attribute Single", 0x10: "Set Attribute Single"}
    fields.append(_f(40, 1, "CIP 服务", f"0x{cip[0]:02X} · {names.get(svc, '其他')}", "最高位为响应标志"))
    if len(cip) < 2:
        return fields
    fields.append(_f(41, 1, "路径字数", cip[1], "端口路径长度（16 位字）"))
    path_len = cip[1] * 2
    path = cip[2:2 + path_len]
    if path:
        pieces = []
        i = 0
        while i + 1 < len(path):
            tag, val = path[i], path[i + 1]
            key = {0x20: "Class", 0x24: "Instance", 0x30: "Attribute"}.get(tag, f"0x{tag:02X}")
            pieces.append(f"{key}={val}")
            i += 2
        fields.append(_f(42, len(path), "端口路径", " / ".join(pieces), "Class 0x02 = Message 标签"))
    rest = cip[2 + path_len:]
    if direction == "response" and len(rest) >= 4:
        if svc == 0x0E:
            val = int.from_bytes(rest[:4], "little")
            fields.append(_f(42 + path_len, 4, "返回值", val, "DINT 小端"))
        else:
            fields.append(_f(42 + path_len, len(rest), "响应数据", _hex(rest), "写操作响应"))
    elif rest:
        if svc == 0x10 and len(rest) >= 6:
            val = int.from_bytes(rest[:4], "little")
            fields.append(_f(42 + path_len, 4, "写入值", val, "DINT 小端"))
            fields.append(_f(46 + path_len, 2, "数据类型", f"0x{u16le(rest, 4):04X}", "0x00C3 = DINT"))
    return fields


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def decode_frame(protocol: str, hex_text: str, direction: str = "request",
                 transport: str | None = None) -> dict:
    """解码一帧报文。direction: request / response。"""
    buf = unhex(hex_text) if isinstance(hex_text, str) else bytes(hex_text or b"")
    if not buf:
        return {"ok": False, "fields": [], "error": "空帧或非法十六进制", "byteCount": 0}
    try:
        if protocol in ("modbus_tcp", "modbus_rtu"):
            t = transport or ("rtu" if protocol == "modbus_rtu" else "tcp")
            fields = _decode_modbus(buf, direction, t)
        elif protocol == "mitsubishi_mc":
            fields = _decode_mc(buf, direction)
        elif protocol == "omron_fins":
            fields = _decode_fins(buf, direction)
        elif protocol == "ab_eip":
            fields = _decode_ab(buf, direction)
        else:
            return {"ok": False, "fields": [], "error": f"不支持的协议: {protocol}", "byteCount": len(buf)}
        return {"ok": bool(fields), "fields": fields, "byteCount": len(buf),
                "error": "" if fields else "报文过短，无法解析字段"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "fields": [], "error": f"{type(e).__name__}: {e}", "byteCount": len(buf)}


__all__ = ["decode_frame"]
