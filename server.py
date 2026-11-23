"""
server.py - ModbusKit 本地调试服务（Python 标准库，零 Web 框架）

双击 exe / run_demo.bat -> 自动开浏览器 -> 进入多协议调试台。
所有报文在本地编解码，模拟器模式零硬件即可演示；真机模式经 TCP 连接实际设备。
"""
import os
import sys
import json
import time
import threading
import argparse
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from modbuskit.client import PROTOCOLS, execute, snapshot, reset
from modbuskit import scanner, serialport, history
from modbuskit import __version__


def resource_root():
    """打包成 exe 时资源在临时解包目录，源码运行时在项目目录。"""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(os.path.abspath(__file__))


ROOT = resource_root()
WEB = os.path.join(ROOT, "web")

# 报文历史（线程安全，保留最近 200 条）
HISTORY = deque(maxlen=200)
HISTORY_LOCK = threading.Lock()


def record(entry: dict):
    with HISTORY_LOCK:
        HISTORY.append(entry)


def meta_payload() -> dict:
    protocols = []
    for key, info in PROTOCOLS.items():
        protocols.append({
            "key": key, "name": info["name"], "vendor": info["vendor"],
            "defaultPort": info["defaultPort"], "frame": info["frame"],
            "note": info["note"],
            "functions": info["module"].FUNCTIONS,
        })
    return {"version": __version__, "protocols": protocols,
            "serialPorts": serialport.list_ports()}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(200, "")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(WEB, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/meta":
            self._send(200, json.dumps(meta_payload(), ensure_ascii=False))
        elif path == "/api/history":
            with HISTORY_LOCK:
                self._send(200, json.dumps(list(HISTORY), ensure_ascii=False))
        elif path == "/api/snapshot":
            protocol = urlparse(self.path).query
            protocol = protocol.split("protocol=")[-1].split("&")[0] if "protocol=" in protocol else "modbus_tcp"
            self._send(200, json.dumps(snapshot(protocol), ensure_ascii=False))
        elif path == "/api/ports":
            self._send(200, json.dumps(serialport.list_ports(), ensure_ascii=False))
        elif path == "/api/export":
            fmt = "json" if "format=json" in urlparse(self.path).query else "csv"
            with HISTORY_LOCK:
                entries = list(HISTORY)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            if fmt == "json":
                body = history.to_json(entries)
                self._send(200, body, "application/json; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="modbuskit_{stamp}.json"'})
            else:
                body = history.to_csv(entries)
                self._send(200, body, "text/csv; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="modbuskit_{stamp}.csv"'})
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        req = self._body()
        try:
            if path == "/api/op":
                protocol = req.get("protocol", "modbus_tcp")
                function = req.get("function")
                params = req.get("params", {})
                mode = req.get("mode", "simulator")
                conn = req.get("connection", {})
                timeout = float(req.get("timeout", 3.0))
                result = execute(protocol, function, params, mode, conn, timeout)
                record({
                    "ts": time.strftime("%H:%M:%S"), "protocol": protocol,
                    "function": function, "params": params, "mode": mode,
                    "ok": result.ok, "requestHex": result.request_hex,
                    "responseHex": result.response_hex,
                    "values": result.values[:16], "error": result.error,
                    "elapsedMs": round(result.elapsed_ms, 2),
                    "transport": result.transport,
                })
                self._send(200, json.dumps(result.to_dict(), ensure_ascii=False))
            elif path == "/api/batch":
                ops = req.get("ops", [])
                mode = req.get("mode", "simulator")
                conn = req.get("connection", {})
                out = []
                for op in ops[:50]:
                    r = execute(op.get("protocol", "modbus_tcp"), op.get("function"),
                                op.get("params", {}), mode, conn)
                    out.append(r.to_dict())
                    record({
                        "ts": time.strftime("%H:%M:%S"),
                        "protocol": op.get("protocol"), "function": op.get("function"),
                        "params": op.get("params", {}), "mode": mode, "ok": r.ok,
                        "requestHex": r.request_hex, "responseHex": r.response_hex,
                        "values": r.values[:16], "error": r.error,
                        "elapsedMs": round(r.elapsed_ms, 2), "transport": r.transport,
                    })
                self._send(200, json.dumps({"results": out}, ensure_ascii=False))
            elif path == "/api/scan":
                result = scanner.scan_units(
                    protocol=req.get("protocol", "modbus_tcp"),
                    mode=req.get("mode", "simulator"),
                    conn=req.get("connection", {}),
                    timeout=float(req.get("timeout", 0.3)),
                    start=int(req.get("start", 1)), end=int(req.get("end", 247)),
                    max_workers=int(req.get("workers", 12)))
                record({"ts": time.strftime("%H:%M:%S"), "protocol": req.get("protocol"),
                        "function": "SCAN", "params": {"start": req.get("start", 1), "end": req.get("end", 247)},
                        "mode": req.get("mode"), "ok": bool(result.get("found")),
                        "requestHex": "", "responseHex": "",
                        "values": [f["unit"] for f in result.get("found", [])],
                        "error": result.get("error", ""),
                        "elapsedMs": result["elapsedMs"], "transport": "从站扫描"})
                self._send(200, json.dumps(result, ensure_ascii=False))
            elif path == "/api/import":
                text = req.get("text", "")
                fmt = req.get("format", "csv")
                entries = (history.from_json(text) if fmt == "json" else history.from_csv(text))
                replace = bool(req.get("replace", False))
                with HISTORY_LOCK:
                    if replace:
                        HISTORY.clear()
                    for e in entries[-200:]:
                        HISTORY.append(e)
                    total = len(HISTORY)
                self._send(200, json.dumps({"ok": True, "imported": len(entries),
                                            "total": total}, ensure_ascii=False))
            elif path == "/api/reset":
                protocol = req.get("protocol") or None
                reset(protocol)
                self._send(200, json.dumps({"ok": True}, ensure_ascii=False))
            elif path == "/api/connect":
                # 串口模式：开关一次端口做预检
                if req.get("mode") == "serial" or req.get("serial"):
                    r = serialport.test_port(req.get("serial") or req, 0.5)
                    self._send(200, json.dumps(r, ensure_ascii=False))
                    return
                # 真机模式连通性预检：尝试 TCP 握手后断开
                import socket
                host = req.get("host", "127.0.0.1")
                port = int(req.get("port", 502))
                timeout = float(req.get("timeout", 3.0))
                t0 = time.perf_counter()
                try:
                    with socket.create_connection((host, port), timeout=timeout):
                        pass
                    self._send(200, json.dumps({
                        "ok": True, "message": f"已连接 {host}:{port}",
                        "elapsedMs": round((time.perf_counter() - t0) * 1000, 2),
                    }, ensure_ascii=False))
                except Exception as e:
                    self._send(200, json.dumps({
                        "ok": False, "message": f"{type(e).__name__}: {e}",
                    }, ensure_ascii=False))
            elif path == "/api/history/clear":
                with HISTORY_LOCK:
                    HISTORY.clear()
                self._send(200, json.dumps({"ok": True}, ensure_ascii=False))
            else:
                self._send(404, "not found", "text/plain; charset=utf-8")
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8767)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"ModbusKit running at http://127.0.0.1:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
