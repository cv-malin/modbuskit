# ModbusKit 协议兼容性矩阵

> 记录方式：帧级交叉校验（与业界标准实现 pymodbus 逐字节比对）+ 内建单元测试。
> 生成日期：2026-11-24　校验工具：`verify/crosscheck_pymodbus.py`（pymodbus 3.16.2）

## 一、验证等级说明

| 等级 | 含义 |
|---|---|
| **A · 帧级交叉验证** | 请求/响应帧与 pymodbus 标准实现逐字节一致，且单元测试通过 |
| **B · 自测通过** | 通过 ModbusKit 自身单元测试与模拟器闭环，无第三方交叉比对 |
| **C · 待真机验证** | 已实现但仅在模拟器验证，尚未接实际设备 |

## 二、Modbus TCP / RTU

| 功能码 | 名称 | TCP | RTU | 交叉校验 |
|---|---|---|---|---|
| 0x01 | 读线圈 | A | A | 逐字节一致 |
| 0x02 | 读离散输入 | A | A | 逐字节一致 |
| 0x03 | 读保持寄存器 | A | A | 逐字节一致 |
| 0x04 | 读输入寄存器 | A | A | 逐字节一致 |
| 0x05 | 写单线圈 | A | A | 逐字节一致 |
| 0x06 | 写单寄存器 | A | A | 逐字节一致 |
| 0x0F | 写多线圈 | A | A | 逐字节一致 |
| 0x10 | 写多寄存器 | A | A | 逐字节一致 |
| 异常帧 | 0x83 + 0x02 等 | B | B | 自研从站按规范构造，诊断助手覆盖 |
| CRC16 | RTU 校验 | — | A | 标准多项式 0xA001，与 pymodbus RTU 帧校验值一致 |

**校验结果**：16/16 请求帧（8 功能码 × TCP/RTU）逐字节一致；反向解析 03 响应帧，pymodbus 解出寄存器值与 ModbusKit 一致（17/17 通过）。

## 三、其他协议

| 协议 | 指令 | 等级 | 说明 |
|---|---|---|---|
| 三菱 MC 3E | 0401/1401 字读写 | B | Qna 3E 二进制帧，自研编解码 + 模拟器闭环 |
| 三菱 MC 3E | 0403/1403 位读写 | B | 位压缩按 4bit，1=ON |
| 欧姆龙 FINS/TCP | 0101/0102 DM 区 | B | FINS/TCP 头 + BCD 地址编码 |
| 欧姆龙 FINS/TCP | 0101-CIO/0102-CIO | B | CIO 存储区码 0xB0 |
| AB EtherNet/IP | 0x0E Get Attribute | B | UCMM + CPF + CIP 显式报文 |
| AB EtherNet/IP | 0x10 Set Attribute | B | DINT 类型 0x00C3 |
| AB EtherNet/IP | 0x63 List Identity | B | 设备识别 |

> 三菱 MC / 欧姆龙 FINS / AB EIP 三个协议当前**未做与第三方库的交叉校验**（pymodbus 仅覆盖 Modbus）。
> 帧结构依据各厂商公开协议规范实现，已在模拟器完成读写闭环与字段解码，但**标记为 B 级，尚未接真机**。

## 四、连接模式

| 模式 | 等级 | 说明 |
|---|---|---|
| 模拟器 | A | 内存从站，读写状态持久，零硬件演示 |
| 真机 TCP（短连接） | A | 会话池长连接复用，断线自动重连重发 |
| 真机 TCP（长连接） | A | 显式建立/断开，线程安全会话锁 |
| 真机 TCP ↔ 标准从站 | A | v1.3 端到端实测：直连 pymodbus TCP 从站，03 读 `[1,2,3,4,5]`、06 写后回读 4321、断会话自动重连，全通过 |
| 从站扫描 | A | 独立短连接并发探询，不污染长连接会话 |
| 串口 RTU | B | pyserial 直连，RS485/RS232，参数校验齐全；需实际串口硬件验证 |

## 五、限制与已知边界

1. **真机差异**：模拟器按协议规范实现，实际 PLC 可能有厂商特定行为（如地址偏移、字节序、单次点数上限）。遇到异常请用「复制报文」功能导出实际收发帧对比。
2. **MC/FINS/EIP 未交叉校验**：这三个协议缺第三方标准库交叉验证，生产环境使用前建议先用厂商工具（GX Works / CX-Programmer / Studio 5000）比对报文。
3. **扫描探询**：真机扫描用 1-247 并发短连接，部分设备对瞬时多连接有限制，可调小并发数或缩短范围。
4. **单点写入上限**：Modbus 单次写多寄存器/线圈受设备限制（通常 123 寄存器 / 1968 线圈），工具未自动分片。

## 六、复现方式

```bat
:: 需安装校验依赖（不进入 ModbusKit 运行时）
D:\xtrain-venv\Scripts\python.exe -m pip install pymodbus
D:\xtrain-venv\Scripts\python.exe verify\crosscheck_pymodbus.py
```

预期输出：`总计: 17/17 项交叉校验通过`。

单元测试 + API 集成测试（64 项）：
```bat
D:\xtrain-venv\Scripts\python.exe -m unittest discover -s tests -v
```

其中 `tests/test_api_integration.py` 用真实 HTTP 服务 + pymodbus 标准 TCP 从站做端到端验证，覆盖全部 API 端点、真机读写、断线重连与批量取消。未安装 pymodbus 时相关 5 项自动跳过，不影响其余测试。
