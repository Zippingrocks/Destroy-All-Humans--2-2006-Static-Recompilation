"""Offline races/gaps and Windows-access contract; never opens a real process."""
from __future__ import annotations

import ctypes
from unittest import TestCase, main, mock

import read_parity_state_ring as ring

LATEST, RING = 0x1000, 0x2000
FIELD_COUNT = len(ring.SAMPLE.unpack(bytes(ring.SAMPLE.size)))


def record(sequence, wall=None, marker=0):
    values = [0] * FIELD_COUNT
    values[0] = sequence
    values[1] = sequence * 33 if wall is None else wall
    values[2] = marker
    return ring.SAMPLE.pack(*values)


def image(latest, overrides=None):
    raw = bytearray(ring.CAPACITY * ring.SAMPLE.size)
    for sequence in range(max(1, latest - ring.CAPACITY + 1), latest + 1):
        offset = ((sequence - 1) % ring.CAPACITY) * ring.SAMPLE.size
        raw[offset:offset + ring.SAMPLE.size] = record(sequence)
    for sequence, replacement in (overrides or {}).items():
        offset = ((sequence - 1) % ring.CAPACITY) * ring.SAMPLE.size
        raw[offset:offset + ring.SAMPLE.size] = replacement
    return bytes(raw)


class FakeReader:
    def __init__(self, publications, images):
        self.publications = iter(publications)
        self.images = iter(images)
        self.reads = []

    def read(self, address, length):
        self.reads.append((address, length))
        if address == LATEST:
            assert length == 8
            return next(self.publications).to_bytes(8, "little")
        assert address == RING and length == ring.CAPACITY * ring.SAMPLE.size
        return next(self.images)


def sequences(raw):
    return [ring.SAMPLE.unpack_from(raw, index * ring.SAMPLE.size)[0]
            for index in range(ring.CAPACITY)
            if ring.SAMPLE.unpack_from(raw, index * ring.SAMPLE.size)[0]]


class SnapshotTests(TestCase):
    def snapshot(self, publications, images, limit=120, retries=3):
        return ring.read_coherent_snapshot(FakeReader(publications, images),
                                           LATEST, RING, limit, retries)

    def test_stable_default_range(self):
        latest, raw, status = self.snapshot([150, 150], [image(150)] * 2)
        self.assertEqual(latest, 150)
        self.assertEqual(sequences(raw), list(range(31, 151)))
        self.assertTrue(status["complete"])
        self.assertFalse(status["processSuspended"])
        self.assertFalse(status["atomicWholeRing"])
        self.assertEqual(status["attempts"], 1)

    def test_publisher_advances_but_requested_range_is_fixed(self):
        latest, raw, status = self.snapshot([3, 5], [image(4), image(5)], 3)
        self.assertEqual(latest, 3)
        self.assertEqual(sequences(raw), [1, 2, 3])
        self.assertEqual(status["observedLatestAfter"], 5)
        self.assertEqual(status["publicationReads"], [[3, 5]])

    def test_raced_sequence_then_retry_recovers_original_range(self):
        changing = image(3, {2: record(0)})
        latest, raw, status = self.snapshot(
            [3, 4, 4, 6], [image(3), changing, image(6), image(6)], 3)
        self.assertEqual(latest, 3)
        self.assertEqual(sequences(raw), [1, 2, 3])
        self.assertEqual(status["sequenceMismatchObservations"], 1)
        self.assertEqual(status["attempts"], 2)
        self.assertTrue(status["complete"])

    def test_stable_sequence_with_changed_payload_is_rejected(self):
        changed = image(3, {2: record(2, marker=99)})
        latest, raw, status = self.snapshot([3, 3], [image(3), changed], 3, 1)
        self.assertEqual(latest, 3)
        self.assertEqual(sequences(raw), [1, 3])
        self.assertEqual(status["missingSequences"], [2])
        self.assertEqual(status["payloadChangeObservations"], 1)
        self.assertFalse(status["complete"])

    def test_missing_gaps_summary_and_bounded_retry(self):
        missing = image(6, {2: record(0), 3: record(99), 5: record(0)})
        latest, raw, status = self.snapshot([6, 6] * 3, [missing] * 6, 6, 3)
        self.assertEqual(sequences(raw), [1, 4, 6])
        self.assertEqual(status["missingSequences"], [2, 3, 5])
        self.assertEqual(status["missingRanges"], [[2, 3], [5, 5]])
        self.assertEqual(status["attempts"], 3)
        self.assertEqual(status["inconsistentRecordObservations"], 9)

    def test_ring_wrap_and_clamped_limit(self):
        latest, raw, status = self.snapshot([5000, 5000], [image(5000)] * 2, 9000)
        self.assertEqual(latest, 5000)
        self.assertEqual(set(sequences(raw)), set(range(905, 5001)))
        self.assertEqual(status["requestedRecords"], ring.CAPACITY)
        self.assertTrue(status["complete"])

    def test_overwritten_oldest_never_substitutes_new_sequence(self):
        old, new = ring.CAPACITY, ring.CAPACITY + 1
        latest, raw, status = self.snapshot([old, new], [image(old), image(new)],
                                           ring.CAPACITY, 1)
        self.assertEqual(latest, old)
        self.assertEqual(status["missingSequences"], [1])
        self.assertNotIn(new, sequences(raw))
        self.assertEqual(status["validRecords"], ring.CAPACITY - 1)

    def test_zero_presents_and_zero_limit(self):
        latest, raw, status = self.snapshot([0, 0], [image(0)] * 2, 0)
        self.assertEqual(latest, 0)
        self.assertEqual(sequences(raw), [])
        self.assertEqual(status["requestedRecords"], 0)
        self.assertTrue(status["complete"])
        latest, raw, status = self.snapshot([3, 3], [image(3)] * 2, 0)
        self.assertEqual(sequences(raw), [3])

    def test_backwards_publication_and_retry_limits_fail(self):
        with self.assertRaisesRegex(RuntimeError, "backwards"):
            self.snapshot([3, 2], [image(3)] * 2)
        for retries in (0, 17):
            with self.assertRaises(ValueError):
                self.snapshot([], [], retries=retries)

    def test_short_read_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "short"):
            self.snapshot([3, 3], [image(3), b""], 3, 1)


    def test_retry_publication_cannot_move_backwards(self):
        missing = image(3, {2: record(0)})
        with self.assertRaisesRegex(RuntimeError, "backwards"):
            self.snapshot([3, 4, 3], [missing, missing], 3, 2)

    def test_empty_publication_still_rejects_short_memory(self):
        with self.assertRaisesRegex(RuntimeError, "short"):
            self.snapshot([0, 0], [b"", b""], 3, 1)


class LayoutTests(TestCase):
    class Map:
        def __init__(self, text):
            self.text = text

        def read_text(self, **kwargs):
            return self.text

    class SizeReader:
        base = ring.IMAGE_BASE

        def __init__(self, size):
            self.size = size
            self.reads = []

        def read(self, address, length):
            self.reads.append((address, length))
            assert address == self.base + 0x1234 and length == 4
            return self.size.to_bytes(4, "little")

    def size_map(self):
        return self.Map(" 0001:00000000 g_dah2_parity_state_sample_size 0000000140001234 f test.obj\n")

    def test_legacy_absent_export_uses400_without_extra_process_read(self):
        reader = self.SizeReader(560)
        version, sample, source = ring.resolve_sample_layout(reader, self.Map(""))
        self.assertEqual((version, sample.size, source), (1, 400, "legacy_missing_size_symbol"))
        self.assertEqual(reader.reads, [])
        with self.assertRaisesRegex(RuntimeError, "disagrees"):
            ring.resolve_sample_layout(reader, self.Map(""), "2")

    def test_exported_sizes_and_explicit_confirmation(self):
        for version, size in ((1, 400), (2, 560)):
            reader = self.SizeReader(size)
            detected, sample, source = ring.resolve_sample_layout(reader, self.size_map(), str(version))
            self.assertEqual((detected, sample.size, source), (version, size, "exported_sample_size"))
            self.assertEqual(reader.reads, [(reader.base + 0x1234, 4)])
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                ring.resolve_sample_layout(reader, self.size_map(), str(3 - version))

    def test_unsupported_size_fails_before_ring_decode(self):
        for size in (0, 399, 404, 556, 568, 640):
            with self.assertRaisesRegex(RuntimeError, "unsupported parity sample size"):
                ring.resolve_sample_layout(self.SizeReader(size), self.size_map())

    def test_v2_profiles_append_without_changing_legacy_fields(self):
        legacy_values = list(ring.SAMPLE.unpack(record(7, wall=1000, marker=42)))
        legacy_values[9] = -3
        values = legacy_values + list(range(100, 140))
        decoded = ring.decode_sample(values, 2)
        profiles = decoded.pop("frameProfiles")
        self.assertEqual(decoded, ring.decode_sample(legacy_values, 1))
        self.assertEqual(profiles, {
            "accepted": list(range(100, 110)), "rejected": list(range(110, 120)),
            "acceptedInline": list(range(120, 130)), "clipped": list(range(130, 140))})
        self.assertEqual(decoded["title"]["gate"], -3)
        packed = ring.SAMPLE_V2.pack(*values)
        self.assertEqual(len(packed), 560)
        self.assertEqual(ring.decode_sample(ring.SAMPLE_V2.unpack(packed), 2)["frameProfiles"], profiles)
        with self.assertRaises(ValueError):
            ring.decode_sample(values, 3)

    def test_v2_non_suspending_snapshot_uses560byte_slot_offsets(self):
        values = list(ring.SAMPLE.unpack(record(1))) + list(range(40))
        raw = bytearray(ring.CAPACITY * ring.SAMPLE_V2.size)
        raw[:ring.SAMPLE_V2.size] = ring.SAMPLE_V2.pack(*values)

        class V2Reader:
            def read(self, address, length):
                if address == LATEST:
                    assert length == 8
                    return (1).to_bytes(8, "little")
                assert address == RING and length == len(raw)
                return bytes(raw)

        latest, copied, status = ring.read_coherent_snapshot(
            V2Reader(), LATEST, RING, 1, 3, ring.SAMPLE_V2)
        self.assertEqual(latest, 1)
        self.assertTrue(status["complete"])
        self.assertEqual(copied, bytes(raw))
        self.assertEqual(ring.decode_sample(ring.SAMPLE_V2.unpack_from(copied), 2)["frameProfiles"]["clipped"], list(range(30, 40)))


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class AccessTests(TestCase):
    def libraries(self):
        self.access = []
        self.closed = []
        self.suspends = []
        self.resumes = []
        kernel = mock.Mock()
        kernel.OpenProcess = Function(lambda access, inherit, pid: self.access.append(access) or 123)
        kernel.ReadProcessMemory = Function(lambda *args: 1)
        kernel.CloseHandle = Function(lambda handle: self.closed.append(handle) or 1)
        psapi = mock.Mock()

        def modules(handle, module, size, needed):
            ctypes.cast(module, ctypes.POINTER(ctypes.c_void_p))[0] = 0x140000000
            return 1

        psapi.EnumProcessModules = Function(modules)
        ntdll = mock.Mock()
        ntdll.NtSuspendProcess = Function(lambda handle: self.suspends.append(handle) or 0)
        ntdll.NtResumeProcess = Function(lambda handle: self.resumes.append(handle) or 0)
        return {"kernel32": kernel, "psapi": psapi, "ntdll": ntdll}

    def test_no_suspend_access_never_loads_or_calls_ntdll(self):
        libraries = self.libraries()
        with mock.patch.object(ctypes, "WinDLL",
                               side_effect=lambda name, **kwargs: libraries[name]) as loader:
            reader = ring.Reader(99, suspend=False)
            self.assertEqual(reader.base, 0x140000000)
            reader.close()
        self.assertEqual(self.access, [0x0410])
        self.assertEqual([call.args[0] for call in loader.call_args_list], ["kernel32", "psapi"])
        self.assertEqual(self.suspends, [])
        self.assertEqual(self.resumes, [])
        self.assertEqual(self.closed, [123])

    def test_compatibility_default_still_suspends_and_resumes_once(self):
        libraries = self.libraries()
        with mock.patch.object(ctypes, "WinDLL",
                               side_effect=lambda name, **kwargs: libraries[name]):
            reader = ring.Reader(99)
            self.assertTrue(reader.suspended)
            reader.close()
        self.assertEqual(self.access, [0x0C10])
        self.assertEqual(self.suspends, [123])
        self.assertEqual(self.resumes, [123])


if __name__ == "__main__":
    main(verbosity=2)
