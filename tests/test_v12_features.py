"""v1.2 新功能测试：会话复用/重连、字段解码、异常诊断。"""
import socket
import threading
import time
import unittest

from modbuskit import decoder, diagnosis, modbus, scanner
from modbuskit.session import SessionManager
from modbuskit.client import execute, reset, session_action


class TestDecoder(unittest.TestCase):
    def test_modbus_tcp_request_fields(self):
        req = modbus.build_request(3, {"addr": 10, "count": 5}, "tcp", transaction=7)
        d = decoder.decode_frame("modbus_tcp", req.hex(" "), "request")
        self.assertTrue(d["ok"])
        labels = {f["label"]: f["value"] for f in d["fields"]}
        self.assertEqual(labels["事务 ID"], "7")
        self.assertEqual(labels["起始地址"], "10")
        self.assertEqual(labels["读取数量"], "5")
        self.assertIn("读保持寄存器", labels["功能码"])

    def test_modbus_tcp_exception_fields(self):
        # 03 功能码非法地址异常：事务1 协议0 长度3 单元1 83 02
        d = decoder.decode_frame("modbus_tcp", "00 01 00 00 00 03 01 83 02", "response")
        self.assertTrue(d["ok"])
        labels = {f["label"]: f["value"] for f in d["fields"]}
        self.assertIn("异常功能码", labels)
        self.assertIn("非法数据地址", labels["异常码"])

    def test_modbus_rtu_crc_field(self):
        req = modbus.build_request(3, {"addr": 0, "count": 2}, "rtu", unit=1)
        d = decoder.decode_frame("modbus_rtu", req.hex(" "), "request")
        self.assertEqual(d["fields"][-1]["label"], "CRC16")

    def test_mitsubishi_fields(self):
        from modbuskit import mitsubishi
        req = mitsubishi.build_request("0401", {"device": "D", "addr": 100, "count": 3})
        d = decoder.decode_frame("mitsubishi_mc", req.hex(" "), "request")
        labels = {f["label"]: f["value"] for f in d["fields"]}
        self.assertEqual(labels["软元件"], "D")
        self.assertEqual(labels["首地址"], "100")
        self.assertEqual(labels["点数"], "3")

    def test_omron_fields(self):
        from modbuskit import omron
        req = omron.build_request("0101", {"addr": 200, "count": 5})
        d = decoder.decode_frame("omron_fins", req.hex(" "), "request")
        labels = {f["label"]: f["value"] for f in d["fields"]}
        self.assertEqual(labels["存储区"], "DM")
        self.assertEqual(labels["起始地址"], "200")
        self.assertEqual(labels["点数"], "5")

    def test_ab_fields(self):
        from modbuskit import ab
        req = ab.build_request("0E", {"instance": 3})
        d = decoder.decode_frame("ab_eip", req.hex(" "), "request")
        labels = {f["label"]: f["value"] for f in d["fields"]}
        self.assertIn("SendRRData", labels["封装命令"])
        self.assertIn("Get Attribute Single", labels["CIP 服务"])
        self.assertIn("Instance=3", labels["端口路径"])

    def test_empty_frame(self):
        d = decoder.decode_frame("modbus_tcp", "", "request")
        self.assertFalse(d["ok"])


class TestDiagnosis(unittest.TestCase):
    def test_modbus_exception(self):
        r = execute("modbus_tcp", 3, {"addr": 9999, "count": 2})
        dg = diagnosis.diagnose("modbus_tcp", r)
        self.assertEqual(dg["category"], "protocol")
        self.assertIn("非法数据地址", dg["title"])
        self.assertTrue(dg["steps"])

    def test_timeout(self):
        r = {"ok": False, "error": "TimeoutError: 设备 192.168.1.9 在 3.0s 内无应答"}
        dg = diagnosis.diagnose("modbus_tcp", r)
        self.assertEqual(dg["category"], "timeout")
        self.assertIn("ping", " ".join(dg["steps"]).lower())

    def test_connection_refused(self):
        r = {"ok": False, "error": "ConnectionRefusedError: [WinError 10061] 拒绝连接"}
        dg = diagnosis.diagnose("modbus_tcp", r)
        self.assertEqual(dg["category"], "network")
        self.assertIn("连接被拒绝", dg["title"])

    def test_ok_no_diagnosis(self):
        self.assertIsNone(diagnosis.diagnose("modbus_tcp", {"ok": True}))


class _EchoServer:
    """本地假设备：收到一帧后原样回显；可配置在第 N 帧后先断开一次。"""
    def __init__(self, close_once=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.running = True
        self.close_once = close_once
        self.conn_count = 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conn_count += 1
            n = self.conn_count
            def handle(c, first):
                try:
                    c.settimeout(1.0)
                    if self.close_once and first:
                        c.recv(64)
                        c.close()          # 第一连接建好后立即断开，触发重连
                        return
                    while self.running:
                        data = c.recv(4096)
                        if not data:
                            break
                        c.sendall(data)     # 原样回显
                except Exception:
                    pass
                finally:
                    c.close()
            threading.Thread(target=handle, args=(conn, n == 1), daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


class TestSessionManager(unittest.TestCase):
    def test_connection_reuse(self):
        srv = _EchoServer(close_once=False)
        try:
            mgr = SessionManager()
            a = mgr.exchange("127.0.0.1", srv.port, bytes.fromhex("010300000001"), 1.0)
            b = mgr.exchange("127.0.0.1", srv.port, bytes.fromhex("010300000002"), 1.0)
            self.assertEqual(a.hex(), "010300000001")
            self.assertEqual(b.hex(), "010300000002")
            self.assertEqual(srv.conn_count, 1, "同一会话应复用同一条连接")
            info = mgr.status()[0]
            self.assertEqual(info["txCount"], 2)
            mgr.disconnect()
        finally:
            srv.stop()

    def test_auto_reconnect_on_peer_close(self):
        srv = _EchoServer(close_once=True)
        try:
            mgr = SessionManager()
            resp = mgr.exchange("127.0.0.1", srv.port, bytes.fromhex("010300000001"), 1.0, retries=2)
            self.assertEqual(resp.hex(), "010300000001")
            self.assertGreaterEqual(srv.conn_count, 2, "对端断开后应重连")
            self.assertEqual(mgr.status()[0]["reconnects"], 1)
            mgr.disconnect()
        finally:
            srv.stop()


class TestScanSessionIsolation(unittest.TestCase):
    """回归测试：扫描必须用独立短连接，不能污染/串行化用户已建立的长连接。"""

    def test_scan_does_not_touch_user_session(self):
        srv = _EchoServer(close_once=False)
        try:
            session_action("disconnect")  # 清空历史会话
            # 1) 用户先建立一条长连接
            conn = {"host": "127.0.0.1", "port": srv.port}
            r = session_action("connect", conn["host"], conn["port"], 1.0)
            self.assertTrue(r["ok"])
            baseline_conns = srv.conn_count
            self.assertEqual(len(session_action("status")["sessions"]), 1)

            # 2) 扫描 3 个 ID（独立短连接）
            scan = scanner.scan_units("modbus_tcp", "tcp", conn, timeout=0.5,
                                      start=1, end=3, max_workers=3)
            self.assertLessEqual(scan["probed"], 3)

            # 3) 关键断言：用户的长连接仍在，且没被关闭
            sessions = [s for s in session_action("status")["sessions"] if s["connected"]]
            self.assertEqual(len(sessions), 1, "扫描后用户长连接仍应存活")
            self.assertEqual(sessions[0]["port"], srv.port)
            self.assertEqual(sessions[0]["txCount"], 0, "扫描不应在共享会话上发报文")

            # 4) 扫描确实新建了独立连接（ conn_count 增加 ）
            self.assertGreater(srv.conn_count, baseline_conns,
                               "扫描应建立独立短连接而非复用用户会话")
            session_action("disconnect")
        finally:
            srv.stop()

    def test_scan_exec_uses_independent_flag(self):
        """扫描探询生成的 transport 标注应含“独立短连接”。"""
        srv = _EchoServer(close_once=False)
        try:
            r = execute("modbus_tcp", 3, {"addr": 0, "count": 1}, "tcp",
                        {"host": "127.0.0.1", "port": srv.port}, 1.0,
                        independent=True)
            self.assertIn("独立短连接", r.transport)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
