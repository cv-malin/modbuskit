"""
server.py - ModbusKit 本地调试服务（Python 标准库，零 Web 框架）

双击 exe / run_demo.bat -> 自动开浏览器 -> 进入多协议调试台。
所有报文在本地编解码，模拟器模式零硬件即可演示；真机模式经 TCP 连接实际设备。
"""
import os
import sys
import json
import time
import uuid
import threading
import argparse
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from modbuskit.client import PROTOCOLS, execute, snapshot, reset, session_action
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


def result_record(op: dict, mode: str, result) -> dict:
    """把 OpResult 转成历史条目（op / batch 共用，保证字段完全一致）。"""
    return {
        "ts": time.strftime("%H:%M:%S"),
        "protocol": op.get("protocol"), "function": op.get("function"),
        "params": op.get("params", {}), "mode": mode, "ok": result.ok,
        "requestHex": result.request_hex, "responseHex": result.response_hex,
        "values": result.values[:16], "error": result.error,
        "elapsedMs": round(result.elapsed_ms, 2), "transport": result.transport,
        "decoded": result.decoded, "diagnosis": result.diagnosis,
    }


# ---- 批量任务（可取消 + 进度查询）----
BATCH_JOBS: dict[str, dict] = {}
BATCH_LOCK = threading.Lock()


def _batch_worker(job_id: str, ops: list, mode: str, conn: dict,
                  timeout: float, retries: int):
    """后台执行批量操作，逐条记录进度，响应取消请求。"""
    job = BATCH_JOBS[job_id]
    for op in ops:
        with BATCH_LOCK:
            if job["cancelled"]:
                break
        r = execute(op.get("protocol", "modbus_tcp"), op.get("function"),
                    op.get("params", {}), mode, conn, timeout, retries)
        record(result_record(op, mode, r))
        with BATCH_LOCK:
            job["results"].append(r.to_dict())
            job["done"] += 1
    with BATCH_LOCK:
        job["finished"] = True
        job["cancelled"] = bool(job["cancelled"])


def batch_start(ops: list, mode: str, conn: dict,
                timeout: float = 3.0, retries: int = 1) -> dict:
    ops = ops[:50]
    job_id = uuid.uuid4().hex[:12]
    job = {"total": len(ops), "done": 0, "results": [],
           "finished": False, "cancelled": False}
    with BATCH_LOCK:
        BATCH_JOBS[job_id] = job
    th = threading.Thread(target=_batch_worker,
                          args=(job_id, ops, mode, conn, timeout, retries),
                          daemon=True)
    th.start()
    return {"ok": True, "jobId": job_id, "total": len(ops)}


def batch_progress(job_id: str) -> dict:
    with BATCH_LOCK:
        j = BATCH_JOBS.get(job_id)
        if not j:
            return {"ok": False, "message": "任务不存在或已过期"}
        return {"ok": True, "jobId": job_id,
                "total": j["total"], "done": j["done"],
                "finished": j["finished"], "cancelled": j["cancelled"],
                "results": list(j["results"])}


def batch_cancel(job_id: str) -> dict:
    with BATCH_LOCK:
        j = BATCH_JOBS.get(job_id)
        if not j:
            return {"ok": False, "message": "任务不存在或已过期"}
        if j["finished"]:
            return {"ok": False, "message": "任务已结束，无法取消"}
        j["cancelled"] = True
        return {"ok": True, "message": "已请求取消，将在当前指令完成后停止"}


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
        elif path == "/api/session":
            self._send(200, json.dumps(session_action("status"), ensure_ascii=False))
        elif path == "/api/batch/progress":
            job_id = urlparse(self.path).query.split("jobId=")[-1].split("&")[0] \
                if "jobId=" in urlparse(self.path).query else ""
            self._send(200, json.dumps(batch_progress(job_id), ensure_ascii=False))
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
                retries = int(req.get("retries", 1))
                result = execute(protocol, function, params, mode, conn, timeout, retries)
                record(result_record(
                    {"protocol": protocol, "function": function, "params": params},
                    mode, result))
                self._send(200, json.dumps(result.to_dict(), ensure_ascii=False))
            elif path == "/api/batch":
                # 同步批量（兼容旧调用）：补齐字段、透传 timeout/retries
                ops = req.get("ops", [])
                mode = req.get("mode", "simulator")
                conn = req.get("connection", {})
                timeout = float(req.get("timeout", 3.0))
                retries = int(req.get("retries", 1))
                out = []
                for op in ops[:50]:
                    r = execute(op.get("protocol", "modbus_tcp"), op.get("function"),
                                op.get("params", {}), mode, conn, timeout, retries)
                    out.append(r.to_dict())
                    record(result_record(op, mode, r))
                self._send(200, json.dumps({"results": out}, ensure_ascii=False))
            elif path == "/api/batch/start":
                self._send(200, json.dumps(batch_start(
                    req.get("ops", []), req.get("mode", "simulator"),
                    req.get("connection", {}),
                    float(req.get("timeout", 3.0)),
                    int(req.get("retries", 1))), ensure_ascii=False))
            elif path == "/api/batch/cancel":
                self._send(200, json.dumps(
                    batch_cancel(req.get("jobId", "")), ensure_ascii=False))
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
            elif path == "/api/session":
                self._send(200, json.dumps(session_action(
                    req.get("action", "status"),
                    req.get("host", ""), int(req.get("port", 502)),
                    float(req.get("timeout", 3.0)),
                    bool(req.get("force", False))), ensure_ascii=False))
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
