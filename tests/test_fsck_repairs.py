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
    def runs(record, offset):
        require(record[offset + 8] == 1, "fixture stream is resident")
        end = offset + u32(record, offset + 4)
        pos = offset + u16(record, offset + 32)
        result = []
        vcn = lcn = 0
        while pos < end and record[pos]:
            sizes = record[pos]
            pos += 1
            count_size, delta_size = sizes & 15, sizes >> 4
            require(1 <= count_size <= 8 and 1 <= delta_size <= 8 and
                    pos + count_size + delta_size <= end,
                    "invalid fixture mapping pairs")
            count = int.from_bytes(record[pos:pos + count_size], "little")
            pos += count_size
            lcn += int.from_bytes(record[pos:pos + delta_size], "little", signed=True)
            pos += delta_size
            require(count > 0 and lcn >= 0, "invalid fixture run")
            result.append((vcn, lcn, count))
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=BUILD_DIR)
    options, remaining = parser.parse_known_args()
    BUILD_DIR = options.build_dir.resolve()
    unittest.main(argv=[str(Path(__file__)), *remaining])
