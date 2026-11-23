"""
test_protocols.py - ModbusKit 协议引擎单元测试（字节级正确性）

覆盖：CRC16、十六进制工具、四协议请求构造/响应解析/模拟从站状态机、异常响应。
运行：python -m unittest discover -s tests -v
"""
import unittest

from modbuskit.utils import (crc16_modbus, hexstr, unhex, bits_to_bytes,
                             bytes_to_bits, words_to_bytes, bytes_to_words,
                             int2bcd, bcd2int)
from modbuskit import modbus, mitsubishi, omron, ab
from modbuskit.client import execute, reset, PROTOCOLS, snapshot


class TestUtils(unittest.TestCase):
    def test_crc16_known_vector(self):
        # Modbus 标准校验向量: 01 03 00 00 00 0A -> CRC 0xCDC5
        frame = bytes.fromhex("01030000000A")
        self.assertEqual(crc16_modbus(frame), 0xCDC5)

    def test_hex_roundtrip(self):
        self.assertEqual(unhex(hexstr(b"\x50\x00\xff")), b"\x50\x00\xff")
        self.assertEqual(unhex("50 00, ff 0X0a"), b"\x50\x00\xff\x0a")

    def test_bits_packing(self):
        bits = [1, 0, 1, 1, 0, 0, 0, 1, 1]
        packed = bits_to_bytes(bits)
        self.assertEqual(packed.hex(), "8d01")
        self.assertEqual(bytes_to_bits(packed, len(bits)), bits)

    def test_words_bytes(self):
        words = [0x1234, 0xABCD, 0x0001]
        self.assertEqual(bytes_to_words(words_to_bytes(words)), words)

    def test_bcd(self):
        self.assertEqual(int2bcd(1234, 2).hex(), "1234")
        self.assertEqual(bcd2int(bytes.fromhex("1234")), 1234)


class TestModbus(unittest.TestCase):
    def setUp(self):
        reset("modbus_tcp")

    def test_read_holding_request_bytes(self):
        req = modbus.build_request(3, {"addr": 0, "count": 10}, "tcp", transaction=1)
        # MBAP: 事务(2) 协议(2)=0 长度(2)=6 单元(1)=1 + PDU 03 0000 000A
        self.assertEqual(req.hex().upper(), "00010000000601030000000A")

    def test_rtu_crc_appended_low_first(self):
        req = modbus.build_request(3, {"addr": 0, "count": 10}, "rtu", unit=1)
        self.assertEqual(req[:6].hex().upper(), "01030000000A")
        crc = crc16_modbus(req[:-2])
        self.assertEqual(req[-2], crc & 0xFF)
        self.assertEqual(req[-1], (crc >> 8) & 0xFF)

    def test_simulator_read_write_persistence(self):
        execute("modbus_tcp", 16, {"addr": 5, "values": [100, 200]})
        r = execute("modbus_tcp", 3, {"addr": 5, "count": 2})
        self.assertTrue(r.ok)
        self.assertEqual(r.values, [100, 200])

    def test_all_eight_functions(self):
        cases = [
            (1, {"addr": 0, "count": 8}),
            (2, {"addr": 0, "count": 8}),
            (3, {"addr": 0, "count": 4}),
            (4, {"addr": 0, "count": 4}),
            (5, {"addr": 1, "value": 1}),
            (6, {"addr": 1, "value": 4321}),
            (15, {"addr": 0, "values": [1, 0, 1]}),
            (16, {"addr": 0, "values": [7, 8, 9]}),
        ]
        for fc, params in cases:
            with self.subTest(fc=fc):
                r = execute("modbus_tcp", fc, params)
                self.assertTrue(r.ok, f"FC {fc}: {r.error}")

    def test_exception_illegal_address(self):
        r = execute("modbus_tcp", 3, {"addr": 9999, "count": 2})
        self.assertFalse(r.ok)
        self.assertEqual(r.parsed.get("exception"), 2)
        self.assertEqual(r.parsed.get("exceptionDesc"), "非法数据地址")

    def test_rtu_roundtrip(self):
        r = execute("modbus_rtu", 3, {"addr": 2, "count": 3})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(r.values), 3)


class TestMitsubishi(unittest.TestCase):
    def setUp(self):
        reset("mitsubishi_mc")

    def test_read_request_bytes(self):
        req = mitsubishi.build_request("0401", {"device": "D", "addr": 100, "count": 3})
        # 50 00 00 FF FF 0A00 0104 0000 A8 640000 0300
        self.assertEqual(req[:2].hex().upper(), "5000")
        self.assertEqual(req[7:9].hex().upper(), "0104")
        self.assertEqual(req[11], 0xA8)
        self.assertEqual(int.from_bytes(req[12:15], "little"), 100)

    def test_word_read_write(self):
        execute("mitsubishi_mc", "1401", {"device": "D", "addr": 50, "values": [11, 22, 33]})
        r = execute("mitsubishi_mc", "0401", {"device": "D", "addr": 50, "count": 3})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.values, [11, 22, 33])

    def test_bit_read_write(self):
        execute("mitsubishi_mc", "1403", {"device": "M", "addr": 10, "values": [1, 1, 0, 1]})
        r = execute("mitsubishi_mc", "0403", {"device": "M", "addr": 10, "count": 4})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.values[:4], [1, 1, 0, 1])

    def test_invalid_device(self):
        with self.assertRaises(ValueError):
            mitsubishi.build_request("0401", {"device": "Z", "addr": 0, "count": 1})


class TestOmron(unittest.TestCase):
    def setUp(self):
        reset("omron_fins")

    def test_read_request_structure(self):
        req = omron.build_request("0101", {"addr": 100, "count": 10}, dst_node=2)
        # 长度 = FINS帧长(10头+2命令+1区码+2地址+2点数=17) + 8(命令+错误码)
        self.assertEqual(int.from_bytes(req[4:8], "big"), 17 + 8)
        self.assertEqual(req[8:12].hex().upper(), "00000002")
        self.assertEqual(req[16], 0x80)   # ICF
        fins = req[16:]
        self.assertEqual(fins[4], 2)      # DA1 = dst node
        self.assertEqual(fins[10:12].hex().upper(), "0101")

    def test_dm_read_write(self):
        execute("omron_fins", "0102", {"addr": 200, "values": [55, 66, 77]})
        r = execute("omron_fins", "0101", {"addr": 200, "count": 3})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.values, [55, 66, 77])

    def test_cio_area(self):
        r = execute("omron_fins", "0101-CIO", {"addr": 10, "count": 2})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(r.values), 2)


class TestAB(unittest.TestCase):
    def setUp(self):
        reset("ab_eip")

    def test_list_identity(self):
        r = execute("ab_eip", "63", {})
        self.assertTrue(r.ok, r.error)
        self.assertIn("CompactLogix", r.values[0])

    def test_get_set_attribute(self):
        execute("ab_eip", "10", {"instance": 3, "value": 9999})
        r = execute("ab_eip", "0E", {"instance": 3})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.values, [9999])

    def test_eip_header_command(self):
        req = ab.build_request("0E", {"instance": 1})
        self.assertEqual(int.from_bytes(req[0:2], "little"), 0x006F)  # SendRRData
        self.assertEqual(int.from_bytes(req[6:10], "little"), 0)      # status OK


class TestProtocolRegistry(unittest.TestCase):
    def test_five_protocols(self):
        self.assertEqual(len(PROTOCOLS), 5)
        for key in ("modbus_tcp", "modbus_rtu", "mitsubishi_mc", "omron_fins", "ab_eip"):
            self.assertIn(key, PROTOCOLS)
            self.assertIn("defaultPort", PROTOCOLS[key])

    def test_snapshot(self):
        for p in PROTOCOLS:
            s = snapshot(p)
            self.assertTrue(s, f"{p} snapshot empty")


if __name__ == "__main__":
    unittest.main()
