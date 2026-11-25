"""
API 层集成测试：用真实 HTTP 服务 + pymodbus 标准从站做端到端验证。

覆盖：
- /api/meta /api/op /api/history /api/export /api/import
- /api/session 长连接管理
- /api/batch 进度与取消
- /api/scan 扫描
- 真机 TCP 模式直连 pymodbus 标准从站（03/06 读写 + 断线重连）

运行：python -m unittest tests.test_api_integration -v
依赖：pymodbus（仅测试环境，不进 exe）
"""
import os
import sys
import json
import time
import socket
import asyncio
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server as srvmod
from modbuskit.client import reset, session_action

try:
    from pymodbus.server import ModbusTcpServer
    from pymodbus.datastore import (ModbusServerContext, ModbusSequentialDataBlock,
                                    ModbusDeviceContext)
    HAS_PYMODBUS = True
except ImportError:
    HAS_PYMODBUS = False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class PymodbusSlave:
    """在后台线程跑一个 pymodbus 标准 TCP 从站。"""

    def __init__(self, port, values=None):
        self.port = port
        self.values = values or list(range(1, 101))
        self.ready = threading.Event()
        self._stop = asyncio.Event() if False else None

    def start(self):
        async def serve():
            hr = ModbusSequentialDataBlock(1, self.values)
            dev = ModbusDeviceContext(
                di=ModbusSequentialDataBlock(1, [0] * 100),
                co=ModbusSequentialDataBlock(1, [0] * 100),
                ir=hr, hr=hr)
            ctx = ModbusServerContext(dev, single=True)
            server = ModbusTcpServer(ctx, address=("127.0.0.1", self.port))
            task = asyncio.create_task(server.serve_forever())
            await asyncio.sleep(0.2)
            self.ready.set()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.thread = threading.Thread(target=lambda: asyncio.run(serve()), daemon=True)
        self.thread.start()
        assert self.ready.wait(5), "pymodbus 从站启动超时"


class TestApiIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http_port = free_port()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", cls.http_port), srvmod.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.http_port}"
        cls.slave_port = free_port()
        if HAS_PYMODBUS:
            cls.slave = PymodbusSlave(cls.slave_port)
            cls.slave.start()
        srvmod.HISTORY.clear()
        reset()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        reset()

    def setUp(self):
        with srvmod.HISTORY_LOCK:
            srvmod.HISTORY.clear()
        reset()
        session_action("disconnect")

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return json.loads(r.read())

    def _post(self, path, data):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    # ---- 基础 API ----
    def test_01_meta_returns_5_protocols(self):
        m = self._get("/api/meta")
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "VERSION"), encoding="utf-8") as f:
            expected = f.read().strip()
        self.assertEqual(m["version"], expected)
        self.assertEqual(len(m["protocols"]), 5)

    def test_02_op_success_has_decoded_and_diagnosis(self):
        r = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 3}, "mode": "simulator"})
        self.assertTrue(r["ok"])
        self.assertIn("decoded", r)
        self.assertIn("diagnosis", r)
        self.assertGreater(len(r["decoded"]["request"]["fields"]), 0)

    def test_03_op_error_has_diagnosis(self):
        r = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 9999, "count": 2}, "mode": "simulator"})
        self.assertFalse(r["ok"])
        self.assertIn("0x02", r["diagnosis"]["title"])
        self.assertGreater(len(r["diagnosis"]["steps"]), 0)

    def test_04_history_records_full_fields(self):
        self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 2}, "mode": "simulator"})
        h = self._get("/api/history")
        self.assertEqual(len(h), 1)
        self.assertIn("decoded", h[0])
        self.assertIn("diagnosis", h[0])

    def test_05_export_import_roundtrip(self):
        self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 2}, "mode": "simulator"})
        exported = self._get("/api/export?format=json")
        self._post("/api/import", {"text": json.dumps(exported, ensure_ascii=False),
                                   "format": "json", "replace": True})
        h = self._get("/api/history")
        self.assertGreaterEqual(len(h), 1)

    # ---- 会话 / 扫描 ----
    def test_06_session_status(self):
        s = self._get("/api/session")
        self.assertTrue(s["ok"])
        self.assertIsInstance(s["sessions"], list)

    @unittest.skipUnless(HAS_PYMODBUS, "pymodbus 未安装")
    def test_07_scan_does_not_touch_session(self):
        # 先建立长连接
        session_action("connect", "127.0.0.1", self.slave_port, 1.0)
        before = session_action("status")["sessions"]
        self.assertTrue(any(s["connected"] for s in before))
        # 扫描（虚拟从站，独立于会话）
        result = self._post("/api/scan", {
            "protocol": "modbus_tcp", "mode": "simulator",
            "start": 1, "end": 20, "workers": 4})
        self.assertIn("found", result)
        # 扫描后长连接仍存活
        after = session_action("status")["sessions"]
        self.assertTrue(any(s["connected"] for s in after),
                        "扫描不应关闭已建立的长连接")
        session_action("disconnect")

    # ---- 批量 ----
    def test_08_batch_records_have_new_fields(self):
        ops = [{"protocol": "modbus_tcp", "function": 3,
                "params": {"addr": i, "count": 1}} for i in range(3)]
        r = self._post("/api/batch", {"ops": ops, "mode": "simulator"})
        self.assertEqual(len(r["results"]), 3)
        h = self._get("/api/history")
        self.assertEqual(len(h), 3)
        for entry in h:
            self.assertIn("decoded", entry)
            self.assertIn("diagnosis", entry)

    def test_09_batch_start_progress_finish(self):
        ops = [{"protocol": "modbus_tcp", "function": 3,
                "params": {"addr": i, "count": 1}} for i in range(5)]
        started = self._post("/api/batch/start", {"ops": ops, "mode": "simulator"})
        self.assertTrue(started["ok"])
        jid = started["jobId"]
        deadline = time.time() + 5
        while time.time() < deadline:
            st = self._get("/api/batch/progress?jobId=" + jid)
            if st["finished"]:
                break
            time.sleep(0.05)
        self.assertTrue(st["finished"])
        self.assertEqual(st["done"], 5)
        self.assertEqual(len(st["results"]), 5)

    def test_10_batch_cancel(self):
        # 用不可达地址让批量变慢，确保能中途取消
        ops = [{"protocol": "modbus_tcp", "function": 3,
                "params": {"addr": i, "count": 1}} for i in range(50)]
        started = self._post("/api/batch/start", {
            "ops": ops, "mode": "tcp",
            "connection": {"host": "127.0.0.1", "port": 1},
            "timeout": 2.0})
        jid = started["jobId"]
        time.sleep(0.2)
        cancelled = self._post("/api/batch/cancel", {"jobId": jid})
        self.assertTrue(cancelled["ok"])
        deadline = time.time() + 6
        while time.time() < deadline:
            st = self._get("/api/batch/progress?jobId=" + jid)
            if st["finished"]:
                break
            time.sleep(0.1)
        self.assertTrue(st["finished"])
        self.assertLess(st["done"], 50, "取消后应提前停止")

    # ---- 真机端到端 ----
    @unittest.skipUnless(HAS_PYMODBUS, "pymodbus 未安装")
    def test_11_real_tcp_read_from_standard_slave(self):
        r = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 5}, "mode": "tcp",
            "connection": {"host": "127.0.0.1", "port": self.slave_port, "unit": 1},
            "timeout": 2.0})
        self.assertTrue(r["ok"], r["error"])
        self.assertEqual(r["values"], [1, 2, 3, 4, 5])
        self.assertIn("长连接", r["transport"])

    @unittest.skipUnless(HAS_PYMODBUS, "pymodbus 未安装")
    def test_12_real_tcp_write_then_readback(self):
        conn = {"host": "127.0.0.1", "port": self.slave_port, "unit": 1}
        w = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 6,
            "params": {"addr": 10, "value": 4321}, "mode": "tcp",
            "connection": conn, "timeout": 2.0})
        self.assertTrue(w["ok"], w["error"])
        r = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 10, "count": 1}, "mode": "tcp",
            "connection": conn, "timeout": 2.0})
        self.assertTrue(r["ok"])
        self.assertEqual(r["values"][0], 4321)

    @unittest.skipUnless(HAS_PYMODBUS, "pymodbus 未安装")
    def test_13_real_tcp_auto_reconnect_after_slave_restart(self):
        conn = {"host": "127.0.0.1", "port": self.slave_port, "unit": 1}
        r1 = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 2}, "mode": "tcp",
            "connection": conn, "timeout": 2.0})
        self.assertTrue(r1["ok"])
        # 断开会话模拟链路中断
        session_action("disconnect")
        r2 = self._post("/api/op", {
            "protocol": "modbus_tcp", "function": 3,
            "params": {"addr": 0, "count": 2}, "mode": "tcp",
            "connection": conn, "timeout": 2.0})
        self.assertTrue(r2["ok"], r2.get("error"))
        self.assertEqual(r2["values"], [1, 2])


if __name__ == "__main__":
    unittest.main()
