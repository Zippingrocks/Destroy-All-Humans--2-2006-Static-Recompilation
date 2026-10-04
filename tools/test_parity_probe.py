"""Protocol and comparison tests using fake sockets, never existing emulators."""

import argparse
import ctypes
import io
import json
import os
import unittest
from unittest.mock import patch

import parity_probe as probe


def rsp(payload):
    return b"$" + payload + f"#{sum(payload) & 255:02x}".encode()


class FakeSocket:
    def __init__(self, inbound):
        self.inbound = io.BytesIO(inbound)
        self.sent = []
        self.closed = False

    def makefile(self, mode):
        return self.inbound

    def recv(self, count):
        return self.inbound.read(count)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class ProtocolTests(unittest.TestCase):
    def test_qmp_events_and_id_matching(self):
        messages = [{"QMP": {"version": {}}}, {"event": "STOP"},
                    {"return": {}, "id": 1}, {"event": "RESUME"},
                    {"return": {"running": True}, "id": 2}]
        sock = FakeSocket(b"".join(json.dumps(message).encode() + b"\r\n" for message in messages))
        with patch.object(probe.socket, "create_connection", return_value=sock):
            qmp = probe.QMP(1234)
            self.assertEqual(qmp.execute("query-status"), {"running": True})
            self.assertEqual(len(qmp.events), 2)
            self.assertTrue(all(message.endswith(b"\r\n") for message in sock.sent))
            self.assertEqual(json.loads(sock.sent[-1])["id"], 2)
            qmp.close()
            self.assertTrue(sock.closed)

    def test_qmp_rejects_execution_control(self):
        qmp = probe.QMP.__new__(probe.QMP)
        with self.assertRaises(probe.ProbeError):
            qmp.execute("stop")
        with self.assertRaises(probe.ProbeError):
            qmp.hmp("system_reset")

    def test_qmp_hmp_memory_address_spaces_and_short_read(self):
        qmp = probe.QMP.__new__(probe.QMP)
        with patch.object(qmp, "hmp", return_value="0000000000001234: 0x01 0xab 0xff\r\n") as hmp:
            self.assertEqual(qmp.memory(0x1234, 3), bytes.fromhex("01abff"))
            hmp.assert_called_with("x /3bx 0x1234")
            self.assertEqual(qmp.memory(0x1234, 3, True), bytes.fromhex("01abff"))
            hmp.assert_called_with("xp /3bx 0x1234")
            with self.assertRaises(probe.ProbeError):
                qmp.memory(0x1234, 4)

    def test_qmp_response_error_and_mismatched_id(self):
        for message in ({"error": {"desc": "unknown"}, "id": 2}, {"return": {}, "id": 3}):
            qmp = probe.QMP.__new__(probe.QMP)
            qmp.sequence = 1
            qmp.events = []
            qmp.sock = FakeSocket(b"")
            with patch.object(qmp, "receive", return_value=message):
                with self.assertRaises(probe.ProbeError):
                    qmp.execute("query-status")

    def test_gdb_checksums_ack_nack_and_console_packets(self):
        good = rsp(b"1234")
        sock = FakeSocket(b"-+" + rsp(b"O6869") + b"$1234#00" + good)
        with patch.object(probe.socket, "create_connection", return_value=sock):
            gdb = probe.GDB(1234)
            self.assertEqual(gdb.memory(0x10000, 2), bytes.fromhex("1234"))
            self.assertEqual(sock.sent[0], rsp(b"m10000,2"))
            self.assertEqual(sock.sent[1], sock.sent[0])
            self.assertIn(b"-", sock.sent)
            self.assertEqual(sock.sent[-1], b"+")

    def test_gdb_escape_and_run_length_decode(self):
        self.assertEqual(probe.GDB.decode(b"0* "), b"0000")
        self.assertEqual(probe.GDB.decode(b"}\x03}\x04}\x0a}]"), b"#$*}")
        for payload in (b"}", b"* ", b"0*", b"0*\x00"):
            with self.assertRaises(probe.ProbeError):
                probe.GDB.decode(payload)

    def test_gdb_short_remote_error_and_closed_connection(self):
        for data in (rsp(b"E14"), rsp(b"01"), b""):
            sock = FakeSocket(b"+" + data)
            with patch.object(probe.socket, "create_connection", return_value=sock):
                with self.assertRaises(probe.ProbeError):
                    probe.GDB(1234).memory(0x1000, 2)

    def test_gdb_memory_chunks(self):
        sock = FakeSocket(b"+" + rsp(b"ab" * 256) + b"+" + rsp(b"cd"))
        with patch.object(probe.socket, "create_connection", return_value=sock):
            self.assertEqual(probe.GDB(1234).memory(0x2000, 257), b"\xab" * 256 + b"\xcd")
            self.assertIn(rsp(b"m2100,1"), sock.sent)

    def test_gdb_registers_and_disallowed_writes(self):
        payload = b"".join(value.to_bytes(4, "little").hex().encode() for value in range(16))
        sock = FakeSocket(b"+" + rsp(payload))
        with patch.object(probe.socket, "create_connection", return_value=sock):
            gdb = probe.GDB(1234)
            self.assertEqual(gdb.registers()["i386"]["eip"], "0x00000008")
            for packet in ("c", "s", "M1000,1:ff", "Z0,1000,1", "D"):
                with self.assertRaises(probe.ProbeError):
                    gdb.request(packet)


class ComparisonTests(unittest.TestCase):
    def test_exact_byte_diff_and_length_diff(self):
        self.assertTrue(probe.compare_bytes(b"a", b"a")["equal"])
        self.assertEqual(probe.compare_bytes(b"abcd", b"abce")["first_difference_offset"], 3)
        self.assertEqual(probe.compare_bytes(b"abc", b"abcd")["different_bytes"], 1)
        self.assertEqual(probe.compare_bytes(b"abc", b"abcd")["first_difference_offset"], 3)

    def test_capture_error_retains_timestamps(self):
        def fail(address, length):
            raise probe.ProbeError("unmapped")
        result = probe.capture(fail, 1, 1)
        self.assertEqual(result["error"], "unmapped")
        self.assertGreaterEqual(result["finished"]["monotonic_ns"], result["started"]["monotonic_ns"])

    def test_manifest_refuses_mismatched_address_spaces(self):
        first = {"ranges": [{"name": "a", "address": "0x00001000", "length": 1,
                              "address_space": "virtual", "xemu": {"hex": "aa"}}]}
        second = json.loads(json.dumps(first))
        second["ranges"][0]["address_space"] = "physical"
        self.assertIn("error", probe.compare_manifests(first, second, "xemu")["ranges"][0])
        second["ranges"][0]["address_space"] = "virtual"
        self.assertTrue(probe.compare_manifests(first, second, "xemu")["ranges"][0]["equal"])

    def test_range_validation(self):
        self.assertEqual(probe.parse_range("state:0x10000:64"), ("state", 0x10000, 64))
        for value in ("state:-1:1", "state:0x100000000:1", "state:0xffffffff:2", "state:1:0", ":1:1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                probe.parse_range(value)

    @unittest.skipUnless(os.name == "nt", "Windows memory API")
    def test_windows_read_own_buffer_with_offset(self):
        buffer = ctypes.create_string_buffer(b"parity")
        reader = probe.ProcessMemory(os.getpid(), ctypes.addressof(buffer) - 0x1234)
        try:
            self.assertEqual(reader.memory(0x1234, 6), b"parity")
        finally:
            reader.close()


if __name__ == "__main__":
    unittest.main()
