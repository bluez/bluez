# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Simple RPC over sockets / character devices

"""
import sys
import os
import struct
import socket
import fcntl
import select
import time
import pickle
import logging
import traceback
from pathlib import Path

log = logging.getLogger("rpc")

__all__ = [
    "Connection",
    "RemoteError",
    "server_stream",
    "server_file",
    "server_unix_socket",
    "client_unix_socket",
]


class RemoteError(Exception):
    def __init__(self, exc, traceback):
        super().__init__(str(exc))
        self.exc = exc
        self.traceback = traceback

    def __str__(self):
        tb = "    ".join(self.traceback)
        return f"{self.exc}\nRemote traceback:\n    {tb}"


def server_stream(stream, implementation):
    """
    Run client side on the given stream.

    Parameters
    ----------
    stream : file
        Stream to use for I/O
    implementation : object
        Object on which remote methods are called

    """
    conn = _Connection(stream, None)

    conn._flush()
    conn._send("hello")

    while True:
        sys.stdout.flush()
        msg = conn._recv()
        message = msg["message"]

        if message in ("call", "call-noreply"):
            log.info(f"server: {msg['method']} {msg['a']} {msg['kw']}")
            try:
                method = getattr(implementation, msg["method"])
                result = method(*msg["a"], **msg["kw"])
                if message == "call":
                    conn._send("call:reply", result=result)
            except BaseException as exc:
                if message == "call":
                    conn._send(
                        "call:reply",
                        error=exc,
                        traceback=traceback.format_exception(exc),
                    )
                else:
                    log.error(traceback.format_exc())
            log.debug("server: done")
        elif message == "quit":
            method = getattr(implementation, "teardown", None)
            if method is not None:
                try:
                    method()
                except BaseException as exc:
                    log.error(f"implementation quit() failed: {exc}")

            log.info(f"server: quit")
            return
        else:
            raise RuntimeError(f"unknown {message=}")


def server_file(filename, implementation):
    """Open given file and run server on it"""
    with open(filename, "r+b", buffering=0) as stream:
        server_stream(stream, implementation)


def server_unix_socket(socket_path, implementation):
    """Open given file and run server on it"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(socket_path))
        sock.listen(1)

        s, addr = sock.accept()
        try:
            server_stream(s, implementation)
        finally:
            s.close()


def client_unix_socket(socket_path, timeout=10, name=None):
    """
    Connect client to Unix socket

    Parameters
    ----------
    socket_path : str
        Path to Unix socket to bind to and listen
    proxy_cls : type
        Proxy class to make instance of

    Returns
    -------
    conn : Connection
        Client connection object

    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    end = time.time() + timeout
    while time.time() < end:
        try:
            sock.connect(str(socket_path))
            break
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            time.sleep(max(0, min(0.5, end - time.time())))
    else:
        sock.connect(str(socket_path))

    conn = _Connection(sock, timeout, name=name)

    reply = conn._recv()
    if reply["message"] != "hello":
        raise RuntimeError("Bad hello message")

    return conn


class _Connection:
    """
    Bidirectional message queue on a stream, pickle-based
    """

    def __init__(self, stream, timeout, name=None):
        fd = stream.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self.stream = stream
        self.timeout = timeout

        if name is None:
            self.log = log
        else:
            self.log = logging.getLogger(f"rpc.{name}")

    def _do_recv(self, size):
        recv = getattr(self.stream, "recv", None) or self.stream.read
        try:
            return recv(size)
        except BlockingIOError:
            return None

    def _do_send(self, data):
        send = getattr(self.stream, "send", None) or self.stream.write
        try:
            return send(data)
        except BlockingIOError:
            return 0

    def _flush(self):
        while self._do_recv(8192):
            pass

    def _recvall(self, size, timeout=None):
        if timeout is None:
            timeout = self.timeout
        if timeout is not None:
            end = time.time() + timeout

        data = b""
        while len(data) < size:
            if timeout is not None:
                dt = end - time.time()
                if dt <= 0:
                    raise TimeoutError("Connection recv timed out")
            else:
                dt = None

            r, w, x = select.select([self.stream], [], [self.stream], dt)

            if x:
                raise IOError("Connection failed")
            elif not r:
                continue

            s = self._do_recv(size - len(data))
            if not s:
                raise IOError("Connection has no data")

            data += s

        return data

    def _sendall(self, data, timeout=None):
        if timeout is None:
            timeout = self.timeout
        if timeout is not None:
            end = time.time() + timeout

        while data:
            if timeout is not None:
                dt = end - time.time()
                if dt <= 0:
                    raise TimeoutError("Connection send timed out")
            else:
                dt = None

            r, w, x = select.select([], [self.stream], [self.stream], dt)

            if x:
                raise IOError("Connection failed")
            elif not w:
                continue

            size = self._do_send(data)
            if not size:
                continue

            data = data[size:]

    def _recv(self, timeout=None):
        (size,) = struct.unpack("<Q", self._recvall(8, timeout=timeout))
        if size > 2**24:
            raise ValueError("Invalid size")
        data = self._recvall(size, timeout=timeout)
        return pickle.loads(data)

    def _send(self, message, timeout=None, **kw):
        data = pickle.dumps(
            dict(message=message, **kw), protocol=pickle.HIGHEST_PROTOCOL
        )
        size = struct.pack("<Q", len(data))
        self._sendall(size + data, timeout=timeout)

    def call_noreply(self, method, *a, **kw):
        self.log.info(f"client: {method} {a} {kw}")

        timeout = kw.pop("timeout", None)

        self._send("call-noreply", method=str(method), a=a, kw=kw, timeout=timeout)

    def call(self, method, *a, **kw):
        self.log.info(f"client: {method} {a} {kw}")

        timeout = kw.pop("timeout", None)

        self._send("call", method=str(method), a=a, kw=kw, timeout=timeout)
        reply = self._recv(timeout=timeout)
        if reply["message"] != "call:reply":
            raise RuntimeError("Invalid reply")

        if reply.get("error"):
            raise RemoteError(reply["error"], reply["traceback"])

        self.log.debug(f"client-reply")
        return reply["result"]

    def close(self):
        try:
            self._send("quit")
        except BrokenPipeError:
            pass

        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()
