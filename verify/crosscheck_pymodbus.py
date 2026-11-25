# -*- coding: utf-8 -*-
"""交叉校验：pymodbus（业界标准实现） vs ModbusKit 自研协议引擎。

用 pymodbus 3.x 的 FramerSocket / FramerRTU 生成标准帧，
与 modbus.build_request() 的字节逐字节比对，验证 ModbusKit 的帧正确性。

仅用于离线校验，pymodbus 不进入 ModbusKit 运行时/打包依赖。
运行：D:/xtrain-venv/Scripts/python.exe verify/crosscheck_pymodbus.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.framer import FramerSocket, FramerRTU
from pymodbus.pdu import DecodePDU
from pymodbus.pdu.bit_message import (ReadCoilsRequest, ReadDiscreteInputsRequest,
                                       WriteSingleCoilRequest, WriteMultipleCoilsRequest)
from pymodbus.pdu.register_message import (ReadHoldingRegistersRequest,
                                            ReadInputRegistersRequest,
                                            WriteSingleRegisterRequest,
                                            WriteMultipleRegistersRequest)

from modbuskit import modbus

CASES = [
    # (功能码, pymodbus请求, ModbusKit参数, 说明)
    (1, lambda: ReadCoilsRequest(address=0, count=10, dev_id=1, transaction_id=1),
     {"addr": 0, "count": 10}, "01 读线圈"),
    (2, lambda: ReadDiscreteInputsRequest(address=5, count=8, dev_id=1, transaction_id=1),
     {"addr": 5, "count": 8}, "02 读离散输入"),
    (3, lambda: ReadHoldingRegistersRequest(address=0, count=10, dev_id=1, transaction_id=1),
     {"addr": 0, "count": 10}, "03 读保持寄存器"),
    (4, lambda: ReadInputRegistersRequest(address=100, count=4, dev_id=1, transaction_id=1),
     {"addr": 100, "count": 4}, "04 读输入寄存器"),
    (5, lambda: WriteSingleCoilRequest(address=1, bits=[True], dev_id=1, transaction_id=1),
     {"addr": 1, "value": 1}, "05 写单线圈"),
    (6, lambda: WriteSingleRegisterRequest(address=2, registers=[4321], dev_id=1, transaction_id=1),
     {"addr": 2, "value": 4321}, "06 写单寄存器"),
    (15, lambda: WriteMultipleCoilsRequest(address=0, bits=[True, False, True, True, False, True, False, False, True],
                                            dev_id=1, transaction_id=1),
     {"addr": 0, "values": [1, 0, 1, 1, 0, 1, 0, 0, 1]}, "15 写多线圈"),
    (16, lambda: WriteMultipleRegistersRequest(address=10, registers=[100, 200, 300],
                                                dev_id=1, transaction_id=1),
     {"addr": 10, "values": [100, 200, 300]}, "16 写多寄存器"),
]


def pymodbus_frame(factory, transport):
    msg = factory()
    # pymodbus 3.x 用 transaction_id / dev_id 字段填地址
    msg.transaction_id = 1
    msg.dev_id = 1
    framer = FramerSocket(DecodePDU(False)) if transport == "tcp" else FramerRTU(DecodePDU(False))
    return framer.buildFrame(msg)


def run():
    print("=" * 74)
    print("ModbusKit × pymodbus 帧级交叉校验 (pymodbus 3.16.2)")
    print("=" * 74)
    total = 0
    passed = 0
    for fc, factory, params, desc in CASES:
        for transport in ("tcp", "rtu"):
            total += 1
            try:
                std = pymodbus_frame(factory, transport)
                ours = modbus.build_request(fc, params, transport,
                                            unit=1, transaction=1)
                ok = std == ours
                if ok:
                    passed += 1
                flag = "PASS" if ok else "FAIL"
                print(f"[{flag}] {desc:18s} {transport.upper():3s}  "
                      f"标准={std.hex(' ').upper()}")
                if not ok:
                    print(f"       {'':18s}      ModbusKit={ours.hex(' ').upper()}")
            except Exception as e:
                total -= 1
                print(f"[SKIP] {desc:18s} {transport.upper():3s}  {type(e).__name__}: {e}")
    print("-" * 74)
    print(f"请求帧结果: {passed}/{total} 帧与 pymodbus 标准实现逐字节一致")

    # ---- 反向校验：用 pymodbus Framer 解析 ModbusKit 模拟从站生成的响应 ----
    print("-" * 74)
    print("反向校验：pymodbus 解析 ModbusKit 响应帧")
    from modbuskit.client import execute as mk_execute
    mk_execute("modbus_tcp", 6, {"addr": 0, "value": 111})
    mk_execute("modbus_tcp", 6, {"addr": 1, "value": 222})
    mk_execute("modbus_tcp", 6, {"addr": 2, "value": 333})
    r = mk_execute("modbus_tcp", 3, {"addr": 0, "count": 3})
    resp = bytes.fromhex(r.response_hex.replace(" ", ""))
    framer = FramerSocket(DecodePDU(True))
    # decode 返回 (used_len, dev_id, tid, pdu)；pdu = 03 06 <regs...>
    used_len, dev_id, tid, pdu = framer.decode(resp)
    py_regs = [int.from_bytes(pdu[2 + i:4 + i], "big") for i in range(0, pdu[1], 2)]
    ok_resp = (dev_id == 1 and tid == 1 and py_regs == r.values)
    total += 1
    passed += 1 if ok_resp else 0
    print(f"[{'PASS' if ok_resp else 'FAIL'}] 03 响应帧: pymodbus 解出寄存器 {py_regs} "
          f"== ModbusKit {r.values} (used={used_len}, dev={dev_id}, tid={tid})")
    print("=" * 74)
    print(f"总计: {passed}/{total} 项交叉校验通过")
    return passed, total


if __name__ == "__main__":
    p, t = run()
    sys.exit(0 if p == t else 1)
