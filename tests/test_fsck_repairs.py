#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Offline fsck repair regressions using disposable 64 MiB regular files.

Run after building: python3 tests/test_fsck_repairs.py --build-dir .
No mounts, root privileges, external images, or third-party packages are needed.
The fixture parser only handles the fresh, uncompressed images made here.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


IMAGE_SIZE = 64 * 1024 * 1024
BUILD_DIR = Path(__file__).resolve().parents[1]


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(name, *args):
    binary = BUILD_DIR / "src" / name
    if not binary.is_file():
        binary = BUILD_DIR / name
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    return subprocess.run([str(binary), *map(str, args)], input=b"",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=env, timeout=30, check=False)


class Image:
    def __init__(self, path):
        self.path = path
        boot = self.read(0, 512)
        require(boot[3:11] == b"NTFS    ", "invalid fixture boot sector")
        self.sector_size = u16(boot, 11)
        self.cluster_size = self.sector_size * boot[13]
        self.nr_clusters = u64(boot, 40) // boot[13]
        code = struct.unpack_from("<b", boot, 64)[0]
        self.record_size = 1 << -code if code < 0 else code * self.cluster_size
        self.mft_offset = u64(boot, 48) * self.cluster_size
        self.mirror_offset = u64(boot, 56) * self.cluster_size
        record = self.unprotect(self.read(self.mft_offset, self.record_size))
        self.mft_runs, self.mft_size = self.data_stream(record)

    def read(self, offset, size):
        require(0 <= offset <= IMAGE_SIZE and 0 <= size <= IMAGE_SIZE - offset,
                "fixture read outside image")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        require(len(data) == size, "short fixture read")
        return data

    def write(self, offset, data):
        require(0 <= offset <= IMAGE_SIZE and len(data) <= IMAGE_SIZE - offset,
                "fixture write outside image")
        with self.path.open("r+b") as stream:
            stream.seek(offset)
            require(stream.write(data) == len(data), "short fixture write")

    def unprotect(self, raw):
        record = bytearray(raw)
        require(record[:4] == b"FILE", "fixture record is not FILE")
        usa, count = struct.unpack_from("<HH", record, 4)
        require(count == self.record_size // self.sector_size + 1 and
                usa + 2 * count <= self.record_size, "invalid fixture fixup")
        for sector in range(1, count):
            tail = sector * self.sector_size - 2
            require(record[tail:tail + 2] == record[usa:usa + 2],
                    "fixture fixup mismatch")
            record[tail:tail + 2] = record[usa + 2 * sector:usa + 2 * sector + 2]
        return record

    def record(self, number):
        raw = self.read_stream(self.mft_runs, number * self.record_size,
                               self.record_size)
        return self.unprotect(raw)

    def write_record(self, number, record):
        record = bytearray(record)
        usa, count = struct.unpack_from("<HH", record, 4)
        for sector in range(1, count):
            tail = sector * self.sector_size - 2
            record[usa + 2 * sector:usa + 2 * sector + 2] = record[tail:tail + 2]
            record[tail:tail + 2] = record[usa:usa + 2]
        self.write_stream(self.mft_runs, number * self.record_size, record)

    @staticmethod
    def attrs(record):
        offset, used = u16(record, 20), u32(record, 24)
        require(48 <= offset <= used <= len(record), "invalid fixture attributes")
        while offset + 16 <= used and u32(record, offset) != 0xffffffff:
            length = u32(record, offset + 4)
            require(length >= 24 and length % 8 == 0 and length <= used - offset,
                    "invalid fixture attribute length")
            name_len, name_off = record[offset + 9], u16(record, offset + 10)
            require(not name_len or name_off + 2 * name_len <= length,
                    "invalid fixture attribute name")
            name = record[offset + name_off:offset + name_off + 2 * name_len]
            yield offset, u32(record, offset), bytes(name).decode("utf-16le")
            offset += length

    @classmethod
    def attr(cls, record, attr_type=0x80, name=""):
        return next(offset for offset, typ, stream in cls.attrs(record)
                    if (typ, stream) == (attr_type, name))

    @staticmethod
    def runs(record, offset, allow_holes=False):
        require(record[offset + 8] == 1, "fixture stream is resident")
        end = offset + u32(record, offset + 4)
        pos = offset + u16(record, offset + 32)
        result = []
        vcn = lcn = 0
        while pos < end and record[pos]:
            sizes = record[pos]
            pos += 1
            count_size, delta_size = sizes & 15, sizes >> 4
            require(1 <= count_size <= 8 and 0 <= delta_size <= 8 and
                    (delta_size or allow_holes) and
                    pos + count_size + delta_size <= end,
                    "invalid fixture mapping pairs")
            count = int.from_bytes(record[pos:pos + count_size], "little")
            pos += count_size
            if delta_size:
                lcn += int.from_bytes(record[pos:pos + delta_size], "little", signed=True)
            pos += delta_size
            require(count > 0 and lcn >= 0, "invalid fixture run")
            result.append((vcn, lcn if delta_size else -1, count))
            vcn += count
        require(pos < end and record[pos] == 0, "missing mapping pairs terminator")
        return result

    @classmethod
    def data_stream(cls, record):
        offset = cls.attr(record)
        return cls.runs(record, offset), u64(record, offset + 48)

    def spans(self, runs, offset, size):
        end = offset + size
        for vcn, lcn, count in runs:
            start, stop = vcn * self.cluster_size, (vcn + count) * self.cluster_size
            if start <= offset < stop:
                length = min(stop, end) - offset
                yield lcn * self.cluster_size + offset - start, length
                offset += length
                if offset == end:
                    return
        require(offset == end, "fixture stream range not mapped")

    def read_stream(self, runs, offset, size):
        return b"".join(self.read(pos, count) for pos, count in
                        self.spans(runs, offset, size))

    def write_stream(self, runs, offset, data):
        consumed = 0
        for pos, count in self.spans(runs, offset, len(data)):
            self.write(pos, data[consumed:consumed + count])
            consumed += count

    def find(self, name):
        for number in range(self.mft_size // self.record_size):
            record = self.record(number)
            if not u16(record, 22) & 1:
                continue
            for offset, typ, _ in self.attrs(record):
                if typ != 0x30:
                    continue
                value = offset + u16(record, offset + 20)
                length = record[value + 64]
                actual = bytes(record[value + 66:value + 66 + length * 2])
                if actual.decode("utf-16le") == name:
                    return number
        raise AssertionError("fixture file not found: " + name)


class RepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="ntfsck-repairs-")
        cls.directory = Path(cls.workspace.name)
        cls.pristine = cls.directory / "pristine.img"
        with cls.pristine.open("wb") as stream:
            stream.truncate(IMAGE_SIZE)
        result = command("mkntfs", "-F", "-Q", cls.pristine)
        require(result.returncode == 0, result.stderr.decode(errors="replace"))

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.image = self.directory / "case.img"
        shutil.copyfile(self.pristine, self.image)

    def check_result(self, result, code):
        output = (result.stdout + result.stderr).decode(errors="replace")
        self.assertEqual(result.returncode, code, output)
        return output

    def add_file(self, name, data):
        source = self.directory / "input.bin"
        source.write_bytes(data)
        self.check_result(command("ntfscp", self.image, source, "/" + name), 0)
        fixture = Image(self.image)
        return fixture, fixture.find(name)

    def check_only(self, code):
        before = hashlib.sha256(self.image.read_bytes()).digest()
        result = command("ntfsck", "-n", self.image)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), before)
        return self.check_result(result, code)

    def test_zero_allocated_size_preserves_data(self):
        payload = bytes(range(256)) * 64
        fixture, number = self.add_file("payload.bin", payload)
        record = fixture.record(number)
        offset = fixture.attr(record)
        struct.pack_into("<Q", record, offset + 40, 0)
        fixture.write_record(number, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        result = command("ntfscat", self.image, "/payload.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, payload)
        self.check_only(0)

    def test_empty_stream_stale_runs_are_removed(self):
        fixture, number = self.add_file("empty.bin", b"A" * 16384)
        record = fixture.record(number)
        offset = fixture.attr(record)
        struct.pack_into("<QQQ", record, offset + 40, 0, 0, 0)
        fixture.write_record(number, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        record = fixture.record(number)
        self.assertEqual(record[fixture.attr(record) + 8], 0)
        result = command("ntfscat", self.image, "/empty.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, b"")
        self.check_only(0)

    def duplicate_fixture(self):
        payload = b"".join(bytes([value]) * 4096 for value in range(4))
        self.add_file("a.bin", payload)
        fixture, number = self.add_file("b.bin", b"B" * 8192)
        source = fixture.record(fixture.find("a.bin"))
        runs, _ = fixture.data_stream(source)
        require(len(runs) == 1 and runs[0][2] == 4,
                "expected one four-cluster source run")
        lcn = runs[0][1]
        record = fixture.record(number)
        offset = fixture.attr(record)
        pairs = b"\x21\x01" + struct.pack("<h", lcn) + b"\x11\x01\x02\x00"
        start = offset + u16(record, offset + 32)
        require(start + len(pairs) <= offset + u32(record, offset + 4),
                "fixture mapping pairs do not fit")
        record[start:start + len(pairs)] = pairs
        fixture.write_record(number, record)
        return fixture, number, payload, payload[:4096] + payload[8192:12288]

    def test_duplicate_clusters_preserve_data(self):
        _, _, original, duplicate = self.duplicate_fixture()
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        for name, data in (("a.bin", original), ("b.bin", duplicate)):
            result = command("ntfscat", "-f", self.image, "/" + name)
            self.check_result(result, 0)
            self.assertEqual(result.stdout, data)
        self.check_only(0)

    def test_duplicate_clusters_out_of_space_rolls_back(self):
        for free_clusters in (0, 1):
            with self.subTest(free_clusters=free_clusters):
                shutil.copyfile(self.pristine, self.image)
                fixture, number, original, duplicate = self.duplicate_fixture()
                record = fixture.record(number)
                bitmap = fixture.record(6)
                runs, size = fixture.data_stream(bitmap)
                old = fixture.read_stream(runs, 0, size)
                available = [i for i in range(4096, fixture.nr_clusters - 1)
                             if not old[i // 8] & (1 << (i % 8))]
                require(len(available) >= free_clusters, "no free fixture clusters")
                full = bytearray(b"\xff" * size)
                for lcn in available[:free_clusters]:
                    full[lcn // 8] &= ~(1 << (lcn % 8))
                fixture.write_stream(runs, 0, full)
                output = self.check_result(command("ntfsck", "-a", self.image), 4)
                self.assertIn("Failed to separate duplicated cluster runlists", output)
                self.assertEqual(fixture.record(number), record)
                self.assertEqual(fixture.read_stream(runs, 0, size), full)
                for name, data in (("a.bin", original), ("b.bin", duplicate)):
                    result = command("ntfscat", "-f", self.image, "/" + name)
                    self.check_result(result, 0)
                    self.assertEqual(result.stdout, data)

    def hibernated_fixture(self):
        fixture, _ = self.add_file("hiberfil.sys", b"hibr" + bytes(4092))
        # LSN is outside the update-sequence-protected sector tails.
        fixture.write(fixture.mirror_offset + fixture.record_size + 8,
                      struct.pack("<Q", 0x12345678))
        return fixture

    def test_hibernation_refusal_preserves_mirror(self):
        self.hibernated_fixture()
        for mode in ("-a", "-y", "-r"):
            with self.subTest(mode=mode):
                before = hashlib.sha256(self.image.read_bytes()).digest()
                output = self.check_result(command("ntfsck", mode, self.image), 8)
                self.assertIn("Windows is hibernated", output)
                self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), before)
        self.check_only(4)

    def test_forced_hibernation_repair(self):
        self.hibernated_fixture()
        self.check_result(command("ntfsck", "-a", "-f", self.image), 1)
        result = command("ntfscat", self.image, "/hiberfil.sys")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, bytes(4096))
        self.check_only(0)

    def test_unreadable_bootstrap_requires_force(self):
        fixture = Image(self.image)
        fixture.write(3, b"BADFS   ")
        before = hashlib.sha256(self.image.read_bytes()).digest()
        output = self.check_result(command("ntfsck", "-a", self.image), 8)
        self.assertIn("Cannot verify hibernation", output)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), before)
        self.check_result(command("ntfsck", "-a", "-f", self.image), 1)
        self.check_only(0)

    def test_run_crossing_volume_end_rechecks_clean(self):
        for following_run in (False, True):
            with self.subTest(following_run=following_run):
                shutil.copyfile(self.pristine, self.image)
                payload = bytes(range(256)) * 64
                fixture, number = self.add_file("tail.bin", payload)
                record = fixture.record(number)
                offset = fixture.attr(record)
                lcn = fixture.nr_clusters - 2
                pairs = b"\x21\x04" + struct.pack("<h", lcn)
                if following_run:
                    pairs += b"\x11\x01\xff"
                    struct.pack_into("<Q", record, offset + 24, 4)
                    struct.pack_into("<QQQ", record, offset + 40,
                                     20480, 20480, 20480)
                pairs += b"\x00"
                start = offset + u16(record, offset + 32)
                require(start + len(pairs) <= offset + u32(record, offset + 4),
                        "fixture mapping pairs do not fit")
                record[start:start + len(pairs)] = pairs
                fixture.write_record(number, record)
                fixture.write(lcn * fixture.cluster_size, payload[:8192])
                self.check_only(4)
                self.check_result(command("ntfsck", "-a", self.image), 1)
                record = fixture.record(number)
                offset = fixture.attr(record)
                self.assertEqual(u64(record, offset + 24), 1)
                self.assertEqual(struct.unpack_from("<QQQ", record, offset + 40),
                                 (8192, 8192, 8192))
                self.assertEqual(fixture.runs(record, offset), [(0, lcn, 2)])
                result = command("ntfscat", self.image, "/tail.bin")
                self.check_result(result, 0)
                self.assertEqual(result.stdout, payload[:8192])
                self.check_only(0)

    def test_run_outside_volume_rechecks_clean(self):
        fixture, number = self.add_file("outside.bin", b"A" * 16384)
        record = fixture.record(number)
        offset = fixture.attr(record)
        start = offset + u16(record, offset + 32)
        pairs = b"\x21\x04" + struct.pack("<h", fixture.nr_clusters + 8) + b"\x00"
        record[start:start + len(pairs)] = pairs
        fixture.write_record(number, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        result = command("ntfscat", self.image, "/outside.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, b"")
        self.check_only(0)

    @staticmethod
    def mapping_pairs(runs):
        result = bytearray()
        previous = 0
        for _, lcn, count in runs:
            size = max(1, (count.bit_length() + 8) // 8)
            length = count.to_bytes(size, "little", signed=True)
            delta = b""
            if lcn >= 0:
                value = lcn - previous
                size = next(i for i in range(1, 9)
                            if -(1 << (8 * i - 1)) <= value < (1 << (8 * i - 1)))
                delta = value.to_bytes(size, "little", signed=True)
                previous = lcn
            result.append(len(length) | len(delta) << 4)
            result.extend(length + delta)
        result.append(0)
        return result

    @staticmethod
    def resize_fixture_attr(record, offset, length):
        old, used = u32(record, offset + 4), u32(record, 24)
        delta = length - old
        require(length % 8 == 0 and used + delta <= len(record),
                "fixture attribute resize does not fit")
        tail = record[offset + old:used]
        record[offset:used + max(delta, 0)] = bytes(used + max(delta, 0) - offset)
        record[offset + length:used + delta] = tail
        struct.pack_into("<I", record, 24, used + delta)

    def set_bitmap_clusters(self, fixture, clusters, used=True):
        runs, _ = fixture.data_stream(fixture.record(6))
        for lcn in clusters:
            offset = lcn // 8
            value = fixture.read_stream(runs, offset, 1)[0]
            mask = 1 << (lcn % 8)
            value = value | mask if used else value & ~mask
            fixture.write_stream(runs, offset, bytes([value]))

    def bitmap_cluster_used(self, fixture, lcn):
        runs, _ = fixture.data_stream(fixture.record(6))
        return bool(fixture.read_stream(runs, lcn // 8, 1)[0] & (1 << (lcn % 8)))

    def clear_mft_bitmap_bit(self, fixture, number):
        record = fixture.record(0)
        offset = fixture.attr(record, 0xb0)
        if record[offset + 8]:
            runs = fixture.runs(record, offset)
            value = fixture.read_stream(runs, number // 8, 1)[0]
            fixture.write_stream(runs, number // 8, bytes([value & ~(1 << (number % 8))]))
        else:
            value = offset + u16(record, offset + 20) + number // 8
            record[value] &= ~(1 << (number % 8))
            fixture.write_record(0, record)
            raw = fixture.read_stream(fixture.mft_runs, 0, fixture.record_size)
            fixture.write(fixture.mirror_offset, raw)

    def install_badclus(self, clusters, mark_bitmap=True):
        fixture = Image(self.image)
        record = fixture.record(8)
        offset = fixture.attr(record, 0x80, "$Bad")
        runs = []
        vcn = 0
        for lcn in sorted(clusters):
            if vcn < lcn:
                runs.append((vcn, -1, lcn - vcn))
            runs.append((lcn, lcn, 1))
            vcn = lcn + 1
        if vcn < fixture.nr_clusters:
            runs.append((vcn, -1, fixture.nr_clusters - vcn))
        pairs = self.mapping_pairs(runs)
        header = record[offset:offset + 72]
        length = (72 + len(pairs) + 7) & ~7
        self.resize_fixture_attr(record, offset, length)
        record[offset:offset + 72] = header
        struct.pack_into("<I", record, offset + 4, length)
        record[offset + 72:offset + 72 + len(pairs)] = pairs
        fixture.write_record(8, record)
        if mark_bitmap:
            self.set_bitmap_clusters(fixture, clusters)
        return fixture

    def remove_badclus_attr(self, fixture, name="$Bad"):
        record = fixture.record(8)
        offset = fixture.attr(record, 0x80, name)
        self.resize_fixture_attr(record, offset, 0)
        fixture.write_record(8, record)

    def assert_badclus(self, expected):
        fixture = Image(self.image)
        actual = set()
        extents = []
        for number in range(fixture.mft_size // fixture.record_size):
            record = fixture.record(number)
            if number != 8 and u64(record, 32) & ((1 << 48) - 1) != 8:
                continue
            if not u16(record, 22) & 1:
                continue
            for offset, typ, name in fixture.attrs(record):
                if (typ, name) != (0x80, "$Bad"):
                    continue
                self.assertEqual(record[offset + 8], 1)
                self.assertEqual(u16(record, offset + 12), 0)
                runs = fixture.runs(record, offset, allow_holes=True)
                if not u64(record, offset + 16):
                    size = fixture.nr_clusters * fixture.cluster_size
                    self.assertEqual(u64(record, offset + 40), size)
                    self.assertEqual(u64(record, offset + 48), size)
                    self.assertLessEqual(u64(record, offset + 56), size)
                # The parser starts each extent at VCN zero; adjust it here.
                start = u64(record, offset + 16)
                end = start + sum(count for _, _, count in runs)
                self.assertEqual(u64(record, offset + 24), end - 1)
                extents.append((start, end))
                for vcn, lcn, count in runs:
                    if lcn < 0:
                        continue
                    self.assertEqual(start + vcn, lcn)
                    actual.update(range(lcn, lcn + count))
        self.assertEqual(actual, set(expected))
        end = 0
        for start, stop in sorted(extents):
            self.assertEqual(start, end)
            end = stop
        self.assertEqual(end, fixture.nr_clusters)
        for lcn in expected:
            self.assertTrue(self.bitmap_cluster_used(fixture, lcn))

    def test_badclus_missing_bitmap_bit_is_restored(self):
        self.install_badclus([5000], mark_bitmap=False)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000])
        self.check_only(0)

    def test_badclus_size_and_vcn_fields_are_repaired(self):
        for field, value in ((40, 0), (48, 4096), (56, 1 << 63), (24, 1), (16, 1)):
            with self.subTest(field=field):
                shutil.copyfile(self.pristine, self.image)
                fixture = self.install_badclus([5000, 5010])
                record = fixture.record(8)
                offset = fixture.attr(record, 0x80, "$Bad")
                struct.pack_into("<Q", record, offset + field, value)
                fixture.write_record(8, record)
                self.check_only(4)
                self.check_result(command("ntfsck", "-a", self.image), 1)
                self.assert_badclus([5000, 5010])
                self.check_only(0)

    def test_badclus_missing_stream_preserves_unclaimed_allocations(self):
        payload = bytes(range(256)) * 64
        self.add_file("payload.bin", payload)
        fixture = self.install_badclus([5000, 5010])
        self.remove_badclus_attr(fixture)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000, 5010])
        result = command("ntfscat", self.image, "/payload.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, payload)
        self.check_only(0)

    def test_badclus_partial_mapping_preserves_bitmap_reservations(self):
        fixture = self.install_badclus([5000, 5010])
        record = fixture.record(8)
        offset = fixture.attr(record, 0x80, "$Bad")
        pos = offset + u16(record, offset + 32)
        # Keep the first hole and first bad-cluster run, then break the chain.
        for _ in range(2):
            sizes = record[pos]
            pos += 1 + (sizes & 15) + (sizes >> 4)
        record[pos] = 0xff
        fixture.write_record(8, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000, 5010])
        self.check_only(0)

    def test_badclus_rebuild_can_span_extent_records(self):
        fixture = Image(self.image)
        clusters = list(range(5000, 5600, 2))
        self.set_bitmap_clusters(fixture, clusters)
        self.remove_badclus_attr(fixture)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus(clusters)
        self.check_only(0)

    def test_badclus_conflicting_file_is_relocated(self):
        payload = bytes(range(256)) * 64
        fixture, number = self.add_file("payload.bin", payload)
        runs, _ = fixture.data_stream(fixture.record(number))
        bad_lcn = runs[0][1]
        self.install_badclus([bad_lcn])
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([bad_lcn])
        result = command("ntfscat", self.image, "/payload.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, payload)
        fixture = Image(self.image)
        runs, _ = fixture.data_stream(fixture.record(number))
        self.assertFalse(any(lcn <= bad_lcn < lcn + count for _, lcn, count in runs))
        self.check_only(0)

    def test_badclus_missing_unnamed_stream_is_recreated(self):
        fixture = self.install_badclus([5000])
        self.remove_badclus_attr(fixture, "")
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000])
        self.check_only(0)

    def test_badclus_unreadable_record_preserves_bitmap(self):
        fixture = self.install_badclus([5000])
        fixture.write_stream(fixture.mft_runs, 8 * fixture.record_size,
                             bytes(fixture.record_size))
        output = self.check_result(command("ntfsck", "-a", self.image), 4)
        self.assertIn("$BadClus cannot be verified", output)
        self.assertTrue(self.bitmap_cluster_used(fixture, 5000))

    def test_badclus_resident_stream_is_rebuilt(self):
        fixture = self.install_badclus([5000])
        record = fixture.record(8)
        offset = fixture.attr(record, 0x80, "$Bad")
        instance = u16(record, offset + 14)
        self.resize_fixture_attr(record, offset, 40)
        struct.pack_into("<IIBBHHH", record, offset,
                         0x80, 40, 0, 4, 24, 0, instance)
        struct.pack_into("<IH", record, offset + 16, 0, 32)
        record[offset + 24:offset + 32] = "$Bad".encode("utf-16le")
        fixture.write_record(8, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000])
        self.check_only(0)

    def test_badclus_nonidentity_mapping_preserves_both_clusters(self):
        fixture = self.install_badclus([5000])
        record = fixture.record(8)
        offset = fixture.attr(record, 0x80, "$Bad")
        pos = offset + u16(record, offset + 32)
        sizes = record[pos]
        pos += 1 + (sizes & 15) + (sizes >> 4)
        self.assertEqual(record[pos], 0x21)
        struct.pack_into("<h", record, pos + 2, 5001)
        fixture.write_record(8, record)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000, 5001])
        self.check_only(0)

    def test_badclus_recovery_excludes_files_missing_mft_bitmap_bits(self):
        payload = bytes(range(256)) * 64
        _, number = self.add_file("payload.bin", payload)
        fixture = self.install_badclus([5000])
        self.remove_badclus_attr(fixture)
        self.clear_mft_bitmap_bit(fixture, number)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000])
        result = command("ntfscat", self.image, "/payload.bin")
        self.check_result(result, 0)
        self.assertEqual(result.stdout, payload)
        self.check_only(0)

    def test_badclus_missing_mft_bitmap_bit_is_restored(self):
        fixture = self.install_badclus([5000])
        self.clear_mft_bitmap_bit(fixture, 8)
        self.check_only(4)
        self.check_result(command("ntfsck", "-a", self.image), 1)
        self.assert_badclus([5000])
        self.check_only(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=BUILD_DIR)
    options, remaining = parser.parse_known_args()
    BUILD_DIR = options.build_dir.resolve()
    unittest.main(argv=[str(Path(__file__)), *remaining])
