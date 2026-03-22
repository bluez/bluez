# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
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
    "RemoteTimeoutError",
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
        tb = "\n    ".join(self.traceback.split("\n"))
        return f"{self.exc}\nRemote traceback:\n    {tb}"


class RemoteTimeoutError(TimeoutError):
    pass


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
    conn = Connection(stream, None)

    while True:
        try:
            msg = conn._recv()
        except BrokenPipeError:
            log.info("server: end of input")
            return

        message = msg["message"]
        ident = msg.get("ident", None)

        if message in ("call", "call-noreply"):
            log.info(f"server: {msg['method']} {msg['a']} {msg['kw']}")
            try:
                method = getattr(implementation, msg["method"])
                result = method(*msg["a"], **msg["kw"])
                if message == "call":
                    conn._send("call:reply", result=result, ident=ident)
            except BaseException as exc:
                if message == "call":
                    conn._send(
                        "call:reply",
                        error=exc,
                        traceback=traceback.format_exc(),
                        ident=ident,
                    )
                else:
                    log.error(traceback.format_exc())
            log.debug(f"server: reply")
        elif message == "hello":
            conn._send("hello:reply", ident=ident)
        elif message == "quit":
            method = getattr(implementation, "teardown", None)
            exc_info = {}
            if method is not None:
                try:
                    method()
                except BaseException as exc:
                    log.error(f"implementation quit() failed: {exc}")
                    exc_info = dict(error=exc, traceback=traceback.format_exc())

            log.info(f"server: quit")
            conn._send("quit:reply", ident=ident, **exc_info)
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
    log.debug(f"client: connect")

    wait = 0.5
    end = time.time() + timeout
    while True:
        dt = end - time.time()
        if dt <= 0:
            raise RemoteTimeoutError("Failed to establish connection")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(socket_path))
        except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
            log.debug(f"client: retry connect ({exc})")
            sock.close()
            time.sleep(min(0.5, dt))
            continue

        conn = Connection(sock, timeout, name=name)
        try:
            conn._send_reply("hello", timeout=min(wait, dt))
            break
        except (BrokenPipeError, TimeoutError) as exc:
            log.debug(f"client: retry connect ({exc})")
            sock.close()
            conn = None
            wait *= 1.5
            continue

    log.debug(f"client: connected")
    return conn


class Connection:
    """
    Bidirectional message queue on a stream, pickle-based
    """

    def __init__(self, stream, timeout, name=None):
        fd = stream.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self.stream = stream
        self.timeout = timeout
        self._close_async = None

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
                    raise RemoteTimeoutError("Connection recv timed out")
            else:
                dt = None

            try:
                r, w, x = select.select([self.stream], [], [self.stream], dt)
            except ValueError:
                raise BrokenPipeError()

            if x:
                raise IOError("Connection failed")
            elif not r:
                continue

            s = self._do_recv(size - len(data))
            if not s:
                raise BrokenPipeError()

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
                    raise RemoteTimeoutError("Connection send timed out")
            else:
                dt = None

            try:
                r, w, x = select.select([], [self.stream], [self.stream], dt)
            except ValueError:
                raise BrokenPipeError()

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
            dict(message=message, **kw),
            protocol=pickle.HIGHEST_PROTOCOL,
        )
        size = struct.pack("<Q", len(data))
        self._sendall(size + data, timeout=timeout)

    def _send_reply_async(self, message, timeout=None, **kw):
        """
        Send-reply pair. If there are unprocessed messages in
        input queue (e.g. failed send-reply pair), those are dropped.

        """
        ident = time.time_ns()

        self._send(message, timeout=timeout, ident=ident, **kw)

        yield

        while True:
            reply = self._recv(timeout=timeout)
            if reply["message"] == f"{message}:reply" and reply["ident"] == ident:
                return reply
            if reply["message"] == "hello":
                # hello from different instance on the other side: our
                # session is gone
                self.stream.close()
                raise BrokenPipeError("Session was terminated")

    def _send_reply(self, *a, **kw):
        try:
            coro = self._send_reply_async(*a, **kw)
            coro.send(None)
            coro.send(None)
            raise RuntimeError()
        except StopIteration as exc:
            return exc.value

    def call_noreply(self, method, *a, **kw):
        timeout = kw.pop("timeout", None)

        self.log.info(f"client: (noreply) {method} {a} {kw}")
        self._send("call-noreply", method=str(method), a=a, kw=kw, timeout=timeout)

    def call(self, method, *a, **kw):
        timeout = kw.pop("timeout", None)

        self.log.info(f"client: {method} {a} {kw}")

        reply = self._send_reply(
            "call", method=str(method), a=a, kw=kw, timeout=timeout
        )
        if reply.get("error"):
            raise RemoteError(reply["error"], reply["traceback"])

        self.log.debug(f"client-reply")
        return reply["result"]

    def close(self):
        """
        Close connection synchronously
        """
        try:
            self.close_start()
        finally:
            self.close_finish()

    def close_start(self):
        """
        Initiate connection close
        """
        self.log.info(f"client: quit")
        if self._close_async is not None:
            raise RuntimeError("double close start")
        self._close_async = self._send_reply_async("quit")
        try:
            self._close_async.send(None)
        except BrokenPipeError:
            self._close_async = None
        except:
            self._close_async = None
            raise

    def close_finish(self, force=False):
        """
        Finish connection close
        """
        try:
            if self._close_async is not None and not force:
                self._close_async.send(None)
        except BrokenPipeError:
            pass
        except StopIteration as exc:
            reply = exc.value
            if reply.get("error"):
                raise RemoteError(reply["error"], reply["traceback"])
        finally:
            self._close_async = None
            self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()
