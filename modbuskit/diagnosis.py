"""
diagnosis.py - 异常诊断助手

把设备返回的异常码 / 超时 / 连接失败翻译成「可能原因 + 排查步骤」，
让调试台从「显示错误」升级到「指导排障」。

输入：execute() 的 OpResult（或等价 dict）。
输出：{category, severity, title, causes: [...], steps: [...]}。
纯规则表驱动，零第三方依赖。
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# 规则表
# ---------------------------------------------------------------------------
MODBUS_EXCEPTION = {
    1: ("非法功能码", ["设备不支持该功能码", "从站类型与所选协议不匹配（如线圈地址用了寄存器功能码）"],
        ["核对设备手册支持的功能码清单", "用 03 读保持寄存器先验证链路，再试其他功能码"]),
    2: ("非法数据地址", ["寄存器/线圈地址超出设备范围", "从站 ID 指向了另一台地址映射不同的设备"],
        ["确认起始地址 + 读取数量不超过设备点数", "用扫描功能确认在线从站 ID", "尝试从 0 地址读取"]),
    3: ("非法数据值", ["写入值超出寄存器范围", "数量字段为 0 或过大", "线圈值不是 0xFF00/0x0000"],
        ["检查写入值是否在 0-65535（或设备允许范围）", "读取数量设为 1-125 之间"]),
    4: ("从站设备故障", ["设备处于故障/保护状态", "外设未就绪"],
        ["查看设备面板报警代码", "断电重启后再试"]),
    5: ("确认", ["设备已收到但需要额外确认"], ["等待设备就绪后重试", "查设备手册关于该功能的确认流程"]),
    6: ("从站忙", ["设备正在处理其他任务", "轮询频率过高"],
        ["稍后重试", "降低轮询频率或增大超时"]),
}

FINS_END_CODE = {
    "0101": ("指令格式错误", ["命令码/参数长度不符合 FINS 规范"]),
    "0201": ("指令不支持", ["目标节点不支持该功能", "CPU 型号不支持该指令"]),
    "0401": ("地址错误", ["DM/CIO 地址超出范围", "存储区代码与地址不匹配"]),
    "1101": ("参数错误", ["点数超过单次上限", "地址未对齐"]),
}

CIP_STATUS = {
    0x01: "服务不支持", 0x02: "路径错误", 0x04: "属性不可读", 0x05: "属性不可写",
    0x06: "媒体不可用", 0x07: "属性数量错误", 0x08: "服务错误", 0x09: "数据错误",
    0x0A: "目标对象错误", 0x0B: "目标连接失败", 0x0D: "资源不足", 0x10: "设备状态冲突",
    0x1E: "路径目标不可用", 0x20: "对象错误",
}


def _result(category: str, title: str, causes: list[str], steps: list[str],
            severity: str = "error") -> dict:
    return {"category": category, "severity": severity, "title": title,
            "causes": causes, "steps": steps}


def _network_diagnosis(error: str) -> dict | None:
    e = error.lower()
    if "connectionrefused" in e or "refused" in e or "10061" in e:
        return _result("network", "连接被拒绝", [
            "目标 IP 正确但端口未开放", "设备未上电或服务未启动",
            "IP 填成了本机地址而不是设备地址",
        ], ["用 ping 确认设备 IP 可达", "确认设备端口号（Modbus TCP 通常 502）",
            "检查设备防火墙/访问控制", "对 PLC 用厂商工具确认服务已启用"])
    if "timed out" in e or "timeout" in e or "timeouterror" in e or "无应答" in error or "超时" in error:
        return _result("timeout", "设备无应答（超时）", [
            "IP/端口错误或网线不通", "从站 ID 不存在", "设备忙或串口波特率/校验位不匹配",
        ], ["ping 目标 IP，并点「测试连接」确认 TCP 能否握手",
            "用「扫描从站 ID」确认总线上真实设备",
            "串口模式核对波特率、校验位、停止位与设备一致",
            "确认 A/B 线未接反（RS485）", "适当增大超时时间后重试"])
    if "unreachable" in e or "no route" in e or "network" in e and "10051" in e:
        return _result("network", "网络不可达", ["IP 网段错误", "网线断开或交换机端口异常"],
                       ["ping 目标 IP", "检查网线/交换机指示灯", "确认本机与设备在同一网段"])
    if "name or service not known" in e or "getaddrinfo" in e:
        return _result("network", "主机名解析失败", ["IP/主机名拼写错误", "DNS 无法解析"],
                       ["改用设备 IP 地址", "检查主机名拼写"])
    if "already in use" in e or "permission" in e or "port" in e and "占用" in error:
        return _result("config", "端口被占用", ["本机另一程序占用了串口/端口"],
                       ["关闭占用程序或换一个端口", "串口模式换用其他 COM 口"])
    if "resett" in e or "brok" in e or "closed" in e or "关闭" in error:
        return _result("network", "连接被对端重置", [
            "设备只支持单连接，旧会话未释放", "设备主动断开空闲连接",
            "请求帧不合法导致设备断链",
        ], ["本工具会自动重连并重发，若仍失败请点「断开连接」后重试",
            "检查请求功能码/地址是否符合设备规范"])
    return None


def diagnose(protocol: str, result: Any, mode: str = "simulator") -> dict:
    """根据一次操作结果生成诊断；成功时返回 None。"""
    d = result if isinstance(result, dict) else result.to_dict()
    parsed = d.get("parsed") or {}
    error = str(d.get("error") or "")

    if d.get("ok"):
        return None

    # 1. 协议层异常帧（有明确异常码）
    exc = parsed.get("exception")
    if exc is not None:
        title, causes, steps = MODBUS_EXCEPTION.get(
            int(exc), ("未知异常码", ["设备返回了规范外的异常码"], ["查设备协议手册"]))
        return _result("protocol", f"Modbus 异常 0x{int(exc):02X} · {title}", causes, steps)

    # 2. 三菱 MC 结束码
    end = str(parsed.get("endCode") or "")
    if end and end != "0000":
        if end.startswith("40") or end.startswith("C"):
            title = "MC 指令/参数错误"
            causes = ["指令码不受支持", "软元件代码或地址超范围", "点数设置过大"]
            steps = ["核对指令码：0401 读字 / 1401 写字 / 0403 读位 / 1403 写位",
                     "确认软元件代码与地址范围（D/M/X/Y/W/L/R）",
                     "减小读取点数后重试"]
        else:
            title = f"PLC 结束码 {end}"
            causes = ["PLC 侧拒绝了该请求"]
            steps = ["查三菱 CPU 手册的结束码说明", "确认目标站号/网络号设置正确"]
        return _result("protocol", title, causes, steps)

    # 3. 欧姆龙 FINS 异常
    if "FINS" in error or (end and parsed.get("tcpError") not in (None, 0)):
        return _result("protocol", "FINS 指令被拒绝", [
            "目标节点号错误", "DM/CIO 地址超出范围", "存储区代码与命令不匹配",
        ], ["检查目标节点（DA1）设置", "DM 区地址通常用 0-9999，CIO 用 0-9999",
            "读用 0101，写用 0102，CIO 用 0101-CIO/0102-CIO"])

    # 4. AB CIP 状态
    cip_status = parsed.get("cipStatus")
    if cip_status is not None:
        code = int(cip_status)
        return _result("protocol", f"CIP 状态 0x{code:02X} · {CIP_STATUS.get(code, '未定义状态')}", [
            "实例号不存在于目标标签表", "服务码与标签类型不匹配", "目标对象属性不可访问",
        ], ["用「识别设备」确认在线设备", "检查实例号（Instance）是否为 1-8",
            "Get 用 0E，Set 用 10"])

    # 5. CRC 校验失败（RTU）
    if "crc" in error.lower():
        return _result("protocol", "CRC16 校验失败", [
            "波特率/校验位/停止位与设备不一致", "RS485 A/B 线接反",
            "线缆干扰或帧被截断", "串口被其他程序占用",
        ], ["核对串口参数与设备拨码一致", "交换 A/B 线后重试",
            "缩短线缆或加终端电阻（120Ω）", "关闭占用串口的程序"])

    # 6. 网络 / 超时 / 配置类错误
    net = _network_diagnosis(error)
    if net:
        return net

    # 7. 参数校验类
    if any(k in error for k in ("需要填写", "非法", "不支持", "仅支持", "端口")):
        return _result("config", "参数配置错误", ["输入值不符合协议或工具约束"],
                       ["按提示修正参数后重试", "从站 ID 范围 1-247",
                        "Modbus 端口默认 502，三菱 MC 1031，FINS 9600，AB EIP 44818"])

    # 8. 兜底
    return _result("unknown", "未归类错误", ["设备或链路返回了无法识别的响应"],
                   ["查看「报文监视」中的 TX/RX 十六进制",
                    "对比正常报文定位差异字节", "在 GitHub Issue 附上报文与设备型号"])


__all__ = ["diagnose"]
