"""P0 新功能测试：从站扫描 / 串口参数 / 历史导入导出。"""
import unittest

from modbuskit import scanner, serialport, history, execute


class TestScanner(unittest.TestCase):
    def test_simulator_scan_finds_virtual_units(self):
        r = scanner.scan_units("modbus_tcp", "simulator")
        self.assertEqual([f["unit"] for f in r["found"]], scanner.VIRTUAL_UNITS)
        self.assertEqual(r["probed"], len(scanner.VIRTUAL_UNITS))
        self.assertGreaterEqual(r["elapsedMs"], 0)

    def test_scan_range_filter(self):
        r = scanner.scan_units("modbus_tcp", "simulator", start=4, end=20)
        self.assertEqual([f["unit"] for f in r["found"]], [7, 16])
        self.assertEqual(r["range"], [4, 20])

    def test_scan_rtu_simulator(self):
        r = scanner.scan_units("modbus_rtu", "simulator")
        self.assertIn(1, [f["unit"] for f in r["found"]])

    def test_unsupported_protocol(self):
        r = scanner.scan_units("ab_eip", "simulator")
        self.assertEqual(r["found"], [])
        self.assertIn("Modbus", r["error"])

    def test_unit_bounds(self):
        r = scanner.scan_units("modbus_tcp", "simulator", start=0, end=999)
        self.assertEqual(r["range"], [1, 247])


class TestSerialPort(unittest.TestCase):
    def test_normalize_valid(self):
        p = serialport.normalize_params({"port": "COM3", "baudrate": 115200,
                                         "bytesize": 8, "parity": "e", "stopbits": 2})
        self.assertEqual(p, {"port": "COM3", "baudrate": 115200, "bytesize": 8,
                             "parity": "E", "stopbits": 2})

    def test_normalize_invalid(self):
        with self.assertRaises(ValueError):
            serialport.normalize_params({})
        for bad in ({"port": "COM1", "baudrate": 12345},
                    {"port": "COM1", "bytesize": 9},
                    {"port": "COM1", "parity": "X"},
                    {"port": "COM1", "stopbits": 3}):
            with self.assertRaises(ValueError):
                serialport.normalize_params(bad)

    def test_list_ports_no_crash(self):
        ports = serialport.list_ports()
        self.assertIsInstance(ports, list)

    def test_test_port_missing(self):
        r = serialport.test_port({"port": "COM__NOT_EXIST__"}, 0.1)
        self.assertFalse(r["ok"])
        self.assertTrue(r["message"])

    def test_serial_only_rtu(self):
        r = execute("modbus_tcp", 3, {"addr": 0, "count": 1}, "serial",
                    {"port": "COM1"}, 1.0)
        self.assertFalse(r.ok)
        self.assertIn("Modbus RTU", r.error)


class TestHistoryIO(unittest.TestCase):
    SAMPLE = [{
        "ts": "12:34:56", "protocol": "modbus_tcp", "function": 3,
        "params": {"addr": 0, "count": 5}, "mode": "simulator", "ok": True,
        "requestHex": "00 01 00 00 00 06 01 03 00 00 00 05",
        "responseHex": "00 01 00 00 00 0D 01 03 0A 00 01",
        "values": [1, 2, 3], "error": "", "elapsedMs": 1.25,
        "transport": "内存模拟从站",
    }]

    def test_csv_roundtrip(self):
        back = history.from_csv(history.to_csv(self.SAMPLE))
        self.assertEqual(len(back), 1)
        self.assertEqual(back[0]["values"], [1, 2, 3])
        self.assertEqual(back[0]["params"], {"addr": 0, "count": 5})
        self.assertTrue(back[0]["ok"])
        self.assertAlmostEqual(back[0]["elapsedMs"], 1.25)

    def test_json_roundtrip(self):
        back = history.from_json(history.to_json(self.SAMPLE))
        self.assertEqual(back[0]["requestHex"], self.SAMPLE[0]["requestHex"])

    def test_bad_input(self):
        self.assertEqual(history.from_csv(""), [])
        self.assertEqual(history.from_json("not json"), [])


if __name__ == "__main__":
    unittest.main()
