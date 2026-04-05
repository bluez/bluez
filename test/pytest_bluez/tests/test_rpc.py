# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import pytest
import subprocess
import threading
import traceback

from .. import rpc


def test_basic(tmp_path):

    def impl_1(text):
        print("pid", os.getpid())
        return f"1: got {text}"

    class Impl2:
        def method(self, text):
            print("pid", os.getpid())
            return f"2: got {text}"

        def error(self):
            raise FloatingPointError("test")

    socket_1 = tmp_path / "socket.1"
    socket_2 = tmp_path / "socket.2"

    def server_1():
        try:
            rpc.server_unix_socket(socket_1, impl_1)
        except:
            traceback.print_exc()
            raise

    def server_2():
        try:
            rpc.server_unix_socket(socket_2, Impl2())
        except:
            traceback.print_exc()
            raise

    s_1 = threading.Thread(target=server_1)
    s_2 = threading.Thread(target=server_2)

    s_1.start()
    s_2.start()

    try:
        with rpc.client_unix_socket(socket_1) as c_1, rpc.client_unix_socket(
            socket_2
        ) as c_2:
            assert c_1.call("__call__", "hello 1") == "1: got hello 1"
            assert c_2.call("method", "hello 2") == "2: got hello 2"
            with pytest.raises(rpc.RemoteError, match="Remote traceback"):
                c_2.call("error")
    except:
        traceback.print_exc()
        raise
    finally:
        s_1.join()
        s_2.join()
