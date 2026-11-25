"""
session.py - 真机 TCP 会话管理：长连接复用 + 断线自动重连

背景：v1.1 每条报文都新建一个 TCP 连接。真实 PLC 通常只允许少量并发连接，
频繁握手会出现「测试连接成功、读写就超时」。本模块把连接提升为会话级资源：

- 按 (host, port) 复用同一条 socket，避免反复三次握手
- 每条会话带独立锁，ThreadingHTTPServer 多线程下不会串包
- 检测到对端关闭 / BrokenPipe / ConnectionReset 时自动重连并重发一次
- 提供 connect / disconnect / status 供调试台显式管理连接生命周期

标准库实现，零第三方依赖，可在 PyInstaller 打包环境直接使用。
"""
from __future__ import annotations

import select
import socket
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Session:
    """一条 (host, port) 上的 TCP 会话。"""
    host: str
    port: int
    sock: socket.socket | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    created_at: float = field(default_factory=time.time)
    tx_count: int = 0
    rx_count: int = 0
    reconnect_count: int = 0
    last_error: str = ""

    @property
    def alive(self) -> bool:
        return self.sock is not None

    def close(self):
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def info(self) -> dict:
        return {
            "host": self.host, "port": self.port, "connected": self.alive,
            "txCount": self.tx_count, "rxCount": self.rx_count,
            "reconnects": self.reconnect_count,
            "ageSec": round(time.time() - self.created_at, 1),
            "lastError": self.last_error,
        }


class SessionManager:
    """线程安全的 TCP 会话池（进程内单例 SESSIONS）。"""

    def __init__(self):
        self._sessions: dict[tuple[str, int], Session] = {}
        self._guard = threading.RLock()

    def _key(self, host: str, port: int) -> tuple[str, int]:
        return (str(host), int(port))

    def _get_or_create(self, host: str, port: int) -> Session:
        key = self._key(host, port)
        with self._guard:
            s = self._sessions.get(key)
            if s is None:
                s = Session(host=str(host), port=int(port))
                self._sessions[key] = s
            return s

    @staticmethod
    def _dial(host: str, port: int, timeout: float) -> socket.socket:
        if not host:
            raise ValueError("真机模式需要填写目标 IP/主机")
        if not (1 <= port <= 65535):
            raise ValueError(f"非法端口: {port}")
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # 禁用 Nagle，工业小包要求低延迟
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def connect(self, host: str, port: int, timeout: float = 3.0,
                force: bool = False) -> dict:
        """显式建立长连接。force=True 时先断开旧会话再建。"""
        s = self._get_or_create(host, port)
        t0 = time.perf_counter()
        with s.lock:
            if force or not s.alive:
                s.close()
            else:
                return {"ok": True, "reused": True,
                        "message": f"复用已有连接 {host}:{port}", "elapsedMs": 0.0}
            try:
                s.sock = self._dial(host, port, timeout)
                s.created_at = time.time()
                s.last_error = ""
                return {"ok": True, "reused": False,
                        "message": f"已连接 {host}:{port}",
                        "elapsedMs": round((time.perf_counter() - t0) * 1000, 2)}
            except Exception as e:
                s.last_error = f"{type(e).__name__}: {e}"
                return {"ok": False, "message": s.last_error,
                        "elapsedMs": round((time.perf_counter() - t0) * 1000, 2)}

    def disconnect(self, host: str | None = None, port: int | None = None) -> dict:
        """断开一条会话；host/port 省略时断开全部。"""
        with self._guard:
            if host is None:
                n = len(self._sessions)
                for s in list(self._sessions.values()):
                    with s.lock:
                        s.close()
                self._sessions.clear()
                return {"ok": True, "closed": n, "message": f"已断开 {n} 条连接"}
            key = self._key(host, port or 0)
            s = self._sessions.get(key)
            if s is None:
                return {"ok": True, "closed": 0, "message": "会话不存在"}
            with s.lock:
                s.close()
            self._sessions.pop(key, None)
            return {"ok": True, "closed": 1, "message": f"已断开 {host}:{port}"}

    def status(self) -> list[dict]:
        with self._guard:
            return [s.info() for s in self._sessions.values()]

    @staticmethod
    def _has_more(sock: socket.socket, wait: float) -> bool:
        """短暂探测是否还有后续字节，避免长连接下每次都等满超时。"""
        try:
            return bool(select.select([sock], [], [], wait)[0])
        except Exception:
            return False

    def exchange(self, host: str, port: int, request: bytes, timeout: float = 3.0,
                 retries: int = 1) -> bytes:
        """复用会话收发一帧；断线时自动重连并重发（最多 retries 次）。

        返回原始响应字节。任何失败都以异常抛出，由 execute() 统一转成 OpResult。
        """
        s = self._get_or_create(host, port)
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            with s.lock:
                try:
                    if not s.alive:
                        s.sock = self._dial(host, port, timeout)
                        s.created_at = time.time()
                    sock = s.sock
                    assert sock is not None
                    sock.settimeout(timeout)
                    sock.sendall(request)
                    s.tx_count += 1
                    chunks: list[bytes] = []
                    # 首帧：允许等满 timeout；后续帧：短探测即可
                    first = True
                    while True:
                        try:
                            part = sock.recv(4096)
                        except socket.timeout:
                            if not first and chunks:
                                break
                            if chunks:
                                break
                            raise TimeoutError(
                                f"设备 {host}:{port} 在 {timeout}s 内无应答")
                        if not part:
                            if not chunks:
                                raise ConnectionError("对端已关闭连接（设备未应答或会话过期）")
                            break
                        chunks.append(part)
                        s.rx_count += 1
                        if len(part) < 4096 and not self._has_more(sock, 0.05):
                            break
                    s.last_error = ""
                    return b"".join(chunks)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                        ConnectionError, TimeoutError, OSError) as exc:
                    last_exc = exc
                    s.last_error = f"{type(exc).__name__}: {exc}"
                    s.close()
                    if attempt >= retries:
                        break
                    # 重连后重发；reconnect_count 仅统计真实重连
                    s.reconnect_count += 1
                    continue
        assert last_exc is not None
        raise last_exc


SESSIONS = SessionManager()
