#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Offline journal recovery regressions; no mounts or external images.

python3 tests/test_fsck_journal.py --build-dir .
"""
import argparse
import errno
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest

import test_fsck_repairs as fixtures


BUILD_DIR = Path(__file__).resolve().parents[1]
PAGE = 4096


def protect(page, usa):
    page = bytearray(page)
    count = len(page) // 512 + 1
    struct.pack_into("<HH", page, 4, usa, count)
    struct.pack_into("<H", page, usa, 7)
    for sector in range(1, count):
        end = sector * 512 - 2
        page[usa + sector * 2:usa + sector * 2 + 2] = page[end:end + 2]
        page[end:end + 2] = page[usa:usa + 2]
    return page


def unprotect(page):
    page = bytearray(page)
    usa, count = struct.unpack_from("<HH", page, 4)
    for sector in range(1, count):
        tail = sector * 512 - 2
        fixtures.require(page[tail:tail + 2] == page[usa:usa + 2], "invalid fixup")
        page[tail:tail + 2] = page[usa + sector * 2:usa + sector * 2 + 2]
    return page


class Journal:
    """Build LFS 1.0/1.1/2.0 pages and real NTFS checkpoint tables."""
    def __init__(self, image, major=1, checkpoint_version=1, *, page_size=PAGE, minor=None):
        self.image = image
        self.runs, self.size = image.data_stream(image.record(2))
        self.major = major
        self.version = checkpoint_version
        self.minor = (1 if major == 1 else 0) if minor is None else minor
        self.page_size = page_size
        self.data_offset = (40 + 2 * (page_size // 512 + 1) + 7) & ~7
        self.first = 34 if major == 2 else 4
        self.seq_bits = 67 - self.size.bit_length()
        self.file_bits = 64 - self.seq_bits

    def lsn(self, page, sequence=1):
        return (sequence << self.file_bits) | ((page * self.page_size + self.data_offset) >> 3)

    def write_page(self, number, data):
        self.image.write_stream(self.runs, number * self.page_size, data)

    def log(self, redo, undo=0, data=b"", undo_data=b"", *, attr=24,
            lcns=(), record_off=0, attr_off=0, cluster_off=0, vcn=0,
            flags=0, undo_next=0, transaction=24):
        count = len(lcns)
        header_len = 32 + 8 * max(1, count)
        undo_off = (header_len + len(data) + 7) & ~7
        header = struct.pack("<12HQ", redo, undo, header_len, len(data),
                             undo_off if undo_data else (header_len if 0x1d <= redo <= 0x20 else 0),
                             len(undo_data), attr, count,
                             record_off, attr_off, cluster_off, 0, vcn)
        payload = header + struct.pack("<" + "Q" * max(1, count), *(lcns or [0]))
        payload += data
        if undo_data:
            payload += bytes(undo_off - header_len - len(data)) + undo_data
        return payload, flags, undo_next, transaction

    def record(self, number, record, typ=1, lsn=None):
        payload, flags, undo_next, transaction = record
        lsn = self.lsn(number) if lsn is None else lsn
        page = bytearray(self.page_size)
        offset = self.data_offset
        struct.pack_into("<4sHHQIHHH6xQ", page, 0, b"RCRD", 40, self.page_size // 512 + 1,
                         lsn, 1, 1, 0, (offset + 48 + len(payload)) & 0xffff, lsn)
        struct.pack_into("<QQQIHHIIH6x", page, offset, lsn, 0, undo_next,
                         len(payload), 0, 0, typ, transaction, flags)
        page[offset + 48:offset + 48 + len(payload)] = payload
        fixtures.require(len(page) == self.page_size, "journal test record exceeds page")
        self.write_page(number, protect(page, 40))

    def two_page_record(self, number, record):
        payload, flags, undo_next, transaction = record
        lsn = self.lsn(number)
        offset = self.data_offset
        cut = self.page_size - offset - 48
        first, last = bytearray(self.page_size), bytearray(self.page_size)
        struct.pack_into("<4sHHQIHHH6xQ", first, 0, b"RCRD", 40, self.page_size // 512 + 1,
                         lsn, 0, 2, 1, self.page_size & 0xffff, self.lsn(number - 1))
        struct.pack_into("<QQQIHHIIH6x", first, offset, lsn, 0, undo_next,
                         len(payload), 0, 0, 1, transaction, flags | 1)
        first[offset + 48:] = payload[:cut]
        tail = payload[cut:]
        struct.pack_into("<4sHHQIHHH6xQ", last, 0, b"RCRD", 40, self.page_size // 512 + 1,
                         lsn, 1, 2, 2, (offset + len(tail)) & 0xffff, lsn)
        last[offset:offset + len(tail)] = tail
        self.write_page(number, protect(first, 40))
        self.write_page(number + 1, protect(last, 40))

    @staticmethod
    def table(size, entry):
        return struct.pack("<6H3I", size, 1, 1, 0, 0, 0, 0, 0, 0) + entry

    def read_record(self, lsn):
        position = (lsn & ((1 << self.file_bits) - 1)) << 3
        offset = position % self.page_size
        position -= offset
        page = unprotect(self.image.read_stream(self.runs, position, self.page_size))
        header = bytes(page[offset:offset + 48])
        length = fixtures.u32(header, 24)
        offset += 48
        data = bytes(page[offset:offset + length])
        while len(data) < length:
            position += self.page_size
            if position >= self.size:
                position = self.first * self.page_size
            page = unprotect(self.image.read_stream(self.runs, position, self.page_size))
            data += bytes(page[self.data_offset:self.data_offset + length - len(data)])
        return header, data

    def restart(self, number, current, checkpoint, oldest, clean=False):
        page = bytearray(PAGE)
        struct.pack_into("<4sHHQIIHHH", page, 0, b"RSTR", 30, 9, 0,
                         PAGE, self.page_size, 48, self.minor, self.major)
        struct.pack_into("<Q4HIHHQIHHII", page, 48, current, 1, 0xffff, 0,
                         2 if clean else 0, self.seq_bits, 224, 64,
                         self.size, 0, 48, self.data_offset, 1, 0)
        struct.pack_into("<QQHHH6xI", page, 112, oldest, checkpoint,
                         0xffff, 0xffff, 0, 8)
        page[144:152] = "NTFS".encode("utf-16le")
        self.image.write_stream(self.runs, number * PAGE, protect(page, 30))

    def emit(self, actions, *, target_vcn, target_lcns, atype=0x80,
             index_size=0, empty_checkpoint=False, torn_restart=False,
             seed_undo=False, mref=0):
        first = self.first
        a_lsn = self.lsn(first)
        if self.version:
            attr = struct.pack("<IIIBBBBQQQ", 0xffffffff, index_size,
                               atype, 0, 0, 0, 0, mref, 0, 0)
        else:
            attr = struct.pack("<IIQQBB2xIB3xII", 0xffffffff, 0, mref, 0,
                               0, 0, atype, 0, 0, index_size)
        attr_table = self.table(len(attr), attr)
        self.record(first, self.log(0x1d, attr=0, data=attr_table))
        dirty = struct.pack("<IIII", 0xffffffff, 24,
                            len(target_lcns) * self.image.cluster_size, len(target_lcns))
        if not self.version:
            dirty += bytes(4)
        dirty += struct.pack("<QQ", target_vcn, a_lsn)
        dirty += struct.pack("<" + "Q" * len(target_lcns), *target_lcns)
        dirty_table = self.table(len(dirty), dirty)
        self.record(first + 1, self.log(0x1f, attr=0, data=dirty_table))
        action_start = first + (3 if empty_checkpoint else 2)
        for i, action in enumerate(actions):
            self.record(action_start + i, action)
        cp_page = first + 2 if empty_checkpoint else action_start + len(actions)
        trans_lsn = trans_length = 0
        if seed_undo:
            # Seed an active transaction whose undo record precedes cp_start.
            trans_page = cp_page
            cp_page += 1
            trans_lsn = self.lsn(trans_page)
            trans = struct.pack("<IB3xQQQII", 0xffffffff, 1, a_lsn,
                                self.lsn(action_start), self.lsn(action_start), 0, 0)
            trans_table = self.table(40, trans)
            trans_length = len(trans_table)
            self.record(trans_page, self.log(0x20, attr=0, data=trans_table))
        cp_lsn = self.lsn(cp_page)
        cp = struct.pack("<II5Q4I", self.version, 0,
                         0 if empty_checkpoint else (cp_lsn if seed_undo else a_lsn),
                         a_lsn, 0, 0 if empty_checkpoint else self.lsn(first + 1),
                         trans_lsn, len(attr_table), 0,
                         0 if empty_checkpoint else len(dirty_table), trans_length)
        self.record(cp_page, (cp, 0, 0, 0), typ=2)
        self.restart(0, cp_lsn, cp_lsn, a_lsn)
        last = self.lsn(cp_page + 2) if torn_restart else cp_lsn
        self.restart(1, last, last, a_lsn)
        return cp_page, action_start


class JournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.BUILD_DIR = BUILD_DIR
        cls.temp = tempfile.TemporaryDirectory(prefix="ntfsck-journal-tests-")
        cls.directory = Path(cls.temp.name)
        cls.base = cls.directory / "base.img"
        with cls.base.open("wb") as stream:
            stream.truncate(fixtures.IMAGE_SIZE)
        result = fixtures.command("mkntfs", "-F", "-Q", cls.base)
        fixtures.require(result.returncode == 0, result.stderr.decode())
        variables = {}
        for line in (BUILD_DIR / "Makefile").read_text().splitlines():
            for name in ("CC", "CFLAGS", "LDFLAGS"):
                if line.startswith(name + " = "):
                    variables[name] = shlex.split(line.split(" = ", 1)[1])
        cls.driver = cls.directory / "replay-driver"
        source = Path(__file__).resolve().parent / "ntfsck_replay_driver.c"
        command = variables.get("CC", ["cc"]) + variables.get("CFLAGS", [])
        command += ["-DHAVE_CONFIG_H", "-I" + str(BUILD_DIR),
                    "-I" + str(BUILD_DIR / "include"), "-I" + str(BUILD_DIR / "src"),
                    str(source), str(BUILD_DIR / "src" / "ntfsck_replay.o"),
                    str(BUILD_DIR / "libntfs" / ".libs" / "libntfs.a")]
        command += variables.get("LDFLAGS", []) + ["-o", str(cls.driver)]
        subprocess.run(command, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.path = self.directory / "case.img"
        shutil.copyfile(self.base, self.path)
        self.image = fixtures.Image(self.path)

    def result(self, code, mode="-a"):
        run = fixtures.command("ntfsck", mode, self.path)
        output = (run.stdout + run.stderr).decode(errors="replace")
        self.assertEqual(run.returncode, code, output)
        return output

    def sizes_fixture(self, *, undo=False, **kwargs):
        journal = Journal(self.image, kwargs.pop("major", 1), kwargs.pop("version", 1),
                          page_size=kwargs.pop("page_size", PAGE), minor=kwargs.pop("minor", None))
        record = self.image.record(10)
        offset = self.image.attr(record)
        original = bytes(record[offset + 40:offset + 64])
        stream_pos = 10 * self.image.record_size
        vcn, cluster_off = divmod(stream_pos, self.image.cluster_size)
        lcn = next(lcn + vcn - start for start, lcn, count in self.image.mft_runs
                   if start <= vcn < start + count)
        action = journal.log(0 if undo else 0xb, 0xb if undo else 0,
                             data=b"" if undo else original,
                             undo_data=original if undo else b"",
                             lcns=[lcn], record_off=offset,
                             cluster_off=cluster_off // 512, vcn=vcn)
        cp, page = journal.emit([action], target_vcn=vcn, target_lcns=[lcn], **kwargs)
        struct.pack_into("<QQ", record, offset + 48, 4096, 4096)
        self.image.write_record(10, record)
        return journal, cp, page, original

    def assert_sizes(self, original):
        current = fixtures.Image(self.path)
        record = current.record(10)
        offset = current.attr(record)
        self.assertEqual(record[offset + 40:offset + 64], original)

    def replay(self, code=0, **faults):
        environment = {**os.environ, "LC_ALL": "C"}
        environment.update({"NTFSCK_REPLAY_" + key.upper(): str(value)
                            for key, value in faults.items()})
        run = subprocess.run([str(self.driver), str(self.path)], capture_output=True,
                             env=environment, timeout=30)
        self.assertEqual(run.returncode, code, (run.stdout + run.stderr).decode())
        return (run.stdout + run.stderr).decode()

    def logfile_fixture_record(self):
        record = self.image.record(2)
        try:
            self.image.attr(record)
            return 2, record
        except StopIteration:
            attr = self.image.attr(record, 0x20)
            offset = attr + fixtures.u16(record, attr + 20)
            end = offset + fixtures.u32(record, attr + 16)
            while offset < end:
                if fixtures.u32(record, offset) == 0x80 and not record[offset + 6]:
                    number = fixtures.u64(record, offset + 16) & ((1 << 48) - 1)
                    return number, self.image.record(number)
                offset += fixtures.u16(record, offset + 4)
            self.fail("fixture has no LogFile data extent")

    def logfile_mapping_fixture(self, *, undo=True, partial=False, major=1, version=1,
                                extent=False):
        journal = Journal(self.image, major=major, checkpoint_version=version)
        if extent:
            self.fixture_operation("--extent", self.path, 2, "0x80")
        owner, record = self.logfile_fixture_record()
        final_runs, size = self.image.data_stream(record)
        self.assertEqual(len(final_runs), 1)
        start, old_lcn, count = final_runs[0]
        shared = 16 if partial else 0
        initial_runs = ([(start, old_lcn, shared)] if shared else [])
        initial_runs.append((shared, 7000 + shared, count - shared))
        attr = self.image.attr(record)
        mp = fixtures.u16(record, attr + 32)
        pairs = bytes(record[attr + mp:attr + fixtures.u32(record, attr + 4)])

        # A real $SDH relative undo makes a repeated transaction observable.
        secure = self.image.record(9)
        index = self.image.attr(secure, 0x90, "$SDH")
        value = index + fixtures.u16(secure, index + 20)
        first = value + 16 + fixtures.u32(secure, value + 16)
        field = first + fixtures.u16(secure, first)
        expected = fixtures.u32(secure, field)
        struct.pack_into("<I", secure, field, expected - 10)
        self.image.write_record(9, secure)

        def target(number):
            vcn, within = divmod(number * self.image.record_size, self.image.cluster_size)
            lcn = next(lcn + vcn - start for start, lcn, count in self.image.mft_runs
                       if start <= vcn < start + count)
            return {"vcn": vcn, "cluster_off": within // 512, "lcns": [lcn]}

        fixtures.RepairTests().set_bitmap_clusters(
            self.image, range(7000 + shared, 7000 + count))
        bitmap_runs, _ = self.image.data_stream(self.image.record(6))
        slot = 24 + (40 if version else 44)
        if version:
            entry = struct.pack("<IIIBBBBQQQ", 0xffffffff, 0, 0x80,
                                0, 0, 0, 0, (1 << 48) | 6, 0, 0)
        else:
            entry = struct.pack("<IIQQBB2xIB3xII", 0xffffffff, 0,
                                (1 << 48) | 6, 0, 0, 0, 0x80, 0, 0, 0)
        opened = journal.log(0x1c, attr=slot, data=entry)

        def operation(op, data, **kwargs):
            return journal.log(0 if undo else op, op if undo else 0,
                               data=b"" if undo else data,
                               undo_data=data if undo else b"", **kwargs)

        allocation = operation(0x16, struct.pack("<II", 7000 + shared, count - shared),
                               attr=slot, lcns=[bitmap_runs[0][1]])
        relative = operation(0x23, struct.pack("<I", 10), record_off=index,
                             attr_off=first - index, **target(9),
                             undo_next=journal.lsn(journal.first + 3))
        mapping = operation(9, pairs, record_off=attr, attr_off=mp, **target(owner),
                            undo_next=journal.lsn(journal.first + 4))
        mft_lcns = [target(number)["lcns"][0] for number in (0, 4, 8)]
        journal.emit([opened, allocation, relative, mapping], target_vcn=0,
                     target_lcns=mft_lcns, mref=1 << 48)
        self.image.write_stream(initial_runs, 0, self.image.read_stream(final_runs, 0, size))
        initial_pairs = fixtures.RepairTests.mapping_pairs(initial_runs)
        header = bytes(record[attr:attr + mp])
        length = (mp + len(initial_pairs) + 7) & ~7
        fixtures.RepairTests.resize_fixture_attr(record, attr, length)
        record[attr:attr + mp] = header
        struct.pack_into("<I", record, attr + 4, length)
        record[attr + mp:attr + mp + len(initial_pairs)] = initial_pairs
        self.image.write_record(owner, record)
        raw = self.image.read_stream(self.image.mft_runs, 2 * self.image.record_size,
                                     self.image.record_size)
        self.image.write(self.image.mirror_offset + 2 * self.image.record_size, raw)
        return journal, initial_runs, final_runs, field, expected

    def assert_logfile_mapping(self, fixture):
        journal, initial_runs, final_runs, field, expected = fixture
        self.image = fixtures.Image(self.path)
        self.assertEqual(self.image.data_stream(self.logfile_fixture_record()[1])[0], final_runs)
        self.assertEqual(fixtures.u32(self.image.record(9), field), expected)
        for copy in (0, 1):
            restart = unprotect(self.image.read_stream(final_runs, copy * PAGE, PAGE))
            self.assertTrue(fixtures.u16(restart, 48 + 14) & 2)
        bitmap_runs, bitmap_size = self.image.data_stream(self.image.record(6))
        bitmap = self.image.read_stream(bitmap_runs, 0, bitmap_size)
        for _, lcn, count in initial_runs:
            if lcn >= 7000 and lcn + count <= 7512:
                self.assertTrue(all(not bitmap[bit // 8] & (1 << (bit % 8))
                                    for bit in range(lcn, lcn + count)))

    def test_logfile_mapping_changes_use_the_final_stream(self):
        for major, version in ((1, 1), (1, 0), (2, 1)):
            for undo in (False, True):
                for partial in (False, True):
                    with self.subTest(major=major, version=version, undo=undo, partial=partial):
                        self.setUp()
                        fixture = self.logfile_mapping_fixture(
                            major=major, version=version, undo=undo, partial=partial)
                        self.replay()
                        self.assert_logfile_mapping(fixture)
                        self.replay()
                        self.assert_logfile_mapping(fixture)

    def test_logfile_mapping_retries_at_each_write_and_sync(self):
        fixture = self.logfile_mapping_fixture()
        saved = self.directory / "logfile-retry-base.img"
        shutil.copyfile(self.path, saved)
        for fault, code in (("fail_write", 1), ("torn_write", 1),
                            ("crash_write", 75), ("fail_sync", 1)):
            for nth in range(1, 100):
                with self.subTest(fault=fault, nth=nth):
                    shutil.copyfile(saved, self.path)
                    run = subprocess.run([str(self.driver), str(self.path)], capture_output=True,
                                         env={**os.environ, "NTFSCK_REPLAY_" + fault.upper(): str(nth)},
                                         timeout=30)
                    if run.returncode == 0:
                        self.assertGreater(nth, 1)
                        break
                    self.assertEqual(run.returncode, code, (run.stdout + run.stderr).decode())
                    self.replay()
                    self.assert_logfile_mapping(fixture)
                    self.replay()
                    self.assert_logfile_mapping(fixture)
            else:
                self.fail("fault sweep did not reach the end of commit")

    def test_logfile_mapping_redo_retries_with_shared_extents(self):
        for partial in (False, True):
            for fault in ("torn_target_at", "fail_clean"):
                with self.subTest(partial=partial, fault=fault):
                    self.setUp()
                    fixture = self.logfile_mapping_fixture(undo=False, partial=partial)
                    point = self.image.mft_offset + 2 * self.image.record_size
                    self.replay(1, **{fault: point if fault == "torn_target_at" else 1})
                    self.replay()
                    self.assert_logfile_mapping(fixture)
                    self.replay()
                    self.assert_logfile_mapping(fixture)

    def test_logfile_mapping_preparation_is_read_only(self):
        self.logfile_mapping_fixture()
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4, "-n")
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_logfile_extent_mapping_checkpoint_retries(self):
        for version in (0, 1):
            with self.subTest(version=version):
                self.setUp()
                fixture = self.logfile_mapping_fixture(extent=True, version=version)
                self.replay(1, fail_clean=1)
                self.replay()
                self.assert_logfile_mapping(fixture)
                self.replay()
                self.assert_logfile_mapping(fixture)

    def test_logfile_checkpoint_refreshes_the_native_stream(self):
        for version in (0, 1):
            with self.subTest(version=version):
                self.setUp()
                fixture = self.logfile_mapping_fixture(version=version)
                journal = fixture[0]
                self.replay(1, fail_clean=1)
                restart = unprotect(self.image.read_stream(journal.runs, 0, PAGE))
                _, checkpoint = journal.read_record(fixtures.u64(restart, 120))
                _, dirty = journal.read_record(fixtures.u64(checkpoint, 32))
                table = dirty[fixtures.u16(dirty, 4):]
                stride = fixtures.u16(table, 0)
                refresh = []
                for offset in range(24, len(table), stride):
                    item = table[offset:offset + stride]
                    header, payload = journal.read_record(fixtures.u64(item, 24 if version else 28))
                    if fixtures.u16(payload, 0) == 0xb:
                        refresh.append((header, payload))
                self.assertEqual(len(refresh), 1)
                header, payload = refresh[0]
                self.assertEqual(fixtures.u16(payload, 6), 24)
                position = (fixtures.u64(payload, 24) * self.image.cluster_size +
                            fixtures.u16(payload, 20) * 512)
                self.assertEqual(position, 2 * self.image.record_size)
                record = self.image.record(2)
                attr = self.image.attr(record)
                self.assertEqual(fixtures.u16(payload, 16), attr)
                sizes = payload[fixtures.u16(payload, 4):]
                self.assertEqual(sizes, struct.pack("<QQQ", fixtures.u64(record, attr + 40),
                                                   fixtures.u64(record, attr + 56),
                                                   fixtures.u64(record, attr + 48)))
                self.assertEqual(fixtures.u64(record, 8), fixtures.u64(header, 0))
                self.replay()
                self.assert_logfile_mapping(fixture)

    def test_full_fsck_does_not_repeat_logfile_mapping_undo(self):
        fixture = self.logfile_mapping_fixture()
        self.result(1)
        self.assert_logfile_mapping(fixture)
        self.result(0)
        self.assert_logfile_mapping(fixture)
        self.result(0, "-n")

    def large_index_volume(self):
        record = self.image.record(5)
        attr = self.image.attr(record, 0xa0, "$I30")
        old_runs = self.image.runs(record, attr)
        old = unprotect(self.image.read_stream(old_runs, 0, PAGE))
        first, end = 24 + fixtures.u32(old, 24), 24 + fixtures.u32(old, 28)
        block = bytearray(65536)
        block[:40] = old[:40]
        block[304:304 + end - first] = old[first:end]
        struct.pack_into("<HH", block, 4, 40, 129)
        struct.pack_into("<III", block, 24, 280, end - first + 280, 65536 - 24)
        mp = fixtures.u16(record, attr + 32)
        header = bytes(record[attr:attr + mp])
        runs = [(0, 5000, 16)]
        pairs = fixtures.RepairTests.mapping_pairs(runs)
        length = (mp + len(pairs) + 7) & ~7
        fixtures.RepairTests.resize_fixture_attr(record, attr, length)
        record[attr:attr + mp] = header
        struct.pack_into("<I", record, attr + 4, length)
        struct.pack_into("<Q", record, attr + 24, 15)
        struct.pack_into("<QQQ", record, attr + 40, 65536, 65536, 65536)
        record[attr + mp:attr + mp + len(pairs)] = pairs
        self.image.write_record(5, record)
        self.image.write_stream(runs, 0, protect(block, 40))
        for number in range(self.image.mft_size // self.image.record_size):
            try:
                current = self.image.record(number)
            except AssertionError:
                continue
            if not fixtures.u16(current, 22) & 1:
                continue
            changed = False
            for offset, typ, _ in self.image.attrs(current):
                self.assertFalse(typ == 0xa0 and number != 5, "fixture needs another large index")
                if typ != 0x90:
                    continue
                value = offset + fixtures.u16(current, offset + 20)
                struct.pack_into("<I", current, value + 8, 65536)
                current[value + 12] = 16
                changed = True
            if changed:
                self.image.write_record(number, current)
        boot = self.image.read(0, 512)
        for offset in (0, fixtures.u64(boot, 40) * self.image.sector_size):
            boot = bytearray(self.image.read(offset, 512))
            struct.pack_into("<b", boot, 68, -16)
            self.image.write(offset, boot)
        repairs = fixtures.RepairTests()
        repairs.set_bitmap_clusters(self.image, range(5000, 5016))
        for _, lcn, count in old_runs:
            repairs.set_bitmap_clusters(self.image, range(lcn, lcn + count), False)
        return runs, block

    def large_index_undo_fixture(self, *, undo=True, major=1, version=1, page_size=PAGE):
        runs, block = self.large_index_volume()
        self.result(0, "-n")
        entry = 304
        while entry < 24 + fixtures.u32(block, 28):
            value = entry + 16
            if not fixtures.u16(block, entry + 12) & 2:
                name = bytes(block[value + 66:value + 66 + block[value + 64] * 2])
                if name.decode("utf-16le") == "$UpCase":
                    break
            entry += fixtures.u16(block, entry + 8)
        else:
            self.fail("fixture has no UpCase entry")
        original = bytes(block[entry + 24:entry + 80])
        struct.pack_into("<Q", block, entry + 24, 0)
        self.image.write_stream(runs, 0, protect(block, 40))
        journal = Journal(self.image, major=major, checkpoint_version=version, page_size=page_size)
        mref = (fixtures.u16(self.image.record(5), 16) << 48) | 5
        name = "$I30".encode("utf-16le")
        if version:
            attr = struct.pack("<IIIBBBBQQQ", 0xffffffff, 65536, 0xa0,
                               0, 1, 4, 0, mref, 0, 0)
        else:
            attr = struct.pack("<IIQQBB2xIB3xII", 0xffffffff, 0, mref, 0,
                               0, 1, 0xa0, 4, 0, 65536)
        opened = journal.log(0x1c, data=attr, undo_data=name)
        action = journal.log(0 if undo else 0x14, 0x14 if undo else 0,
                             data=b"" if undo else original,
                             undo_data=original if undo else b"",
                             lcns=list(range(5000, 5016)), attr_off=entry)
        journal.emit([opened, action], target_vcn=0, target_lcns=list(range(5000, 5016)),
                     atype=0xa0, index_size=65536, mref=mref)
        return journal, entry, original

    def assert_large_index(self, fixture):
        _, entry, original = fixture
        block = unprotect(self.image.read(5000 * self.image.cluster_size, 65536))
        self.assertEqual(block[entry + 24:entry + 80], original)

    def test_64k_index_redo_and_undo(self):
        for major, version, page_size in ((1, 1, PAGE), (1, 0, PAGE), (2, 1, PAGE),
                                          (1, 1, 65536), (1, 0, 65536)):
            for undo in (False, True):
                with self.subTest(major=major, version=version, page_size=page_size, undo=undo):
                    self.setUp()
                    fixture = self.large_index_undo_fixture(
                        major=major, version=version, page_size=page_size, undo=undo)
                    self.replay()
                    self.assert_large_index(fixture)
                    self.replay()
                    self.assert_large_index(fixture)
                    self.result(0, "-n")

    def test_64k_index_checkpoint_uses_native_raw_chunks(self):
        for version in (0, 1):
            with self.subTest(version=version):
                self.setUp()
                fixture = self.large_index_undo_fixture(version=version)
                journal = fixture[0]
                self.replay(1, fail_target_at=5000 * self.image.cluster_size)
                restart = unprotect(self.image.read_stream(journal.runs, 0, PAGE))
                _, checkpoint = journal.read_record(fixtures.u64(restart, 120))
                _, attrs = journal.read_record(fixtures.u64(checkpoint, 16))
                dump = attrs[fixtures.u16(attrs, 4):]
                stride = fixtures.u16(dump, 0)
                slots = []
                for offset in range(24, len(dump), stride):
                    item = dump[offset:offset + stride]
                    typ = fixtures.u32(item, 8 if version else 28)
                    size = fixtures.u32(item, 4 if version else 40)
                    if typ == 0xa0 and not size:
                        slots.append(offset)
                self.assertEqual(len(slots), 1)
                _, dirty = journal.read_record(fixtures.u64(checkpoint, 32))
                dirty = dirty[fixtures.u16(dirty, 4):]
                stride = fixtures.u16(dirty, 0)
                records = []
                for offset in range(24, len(dirty), stride):
                    item = dirty[offset:offset + stride]
                    _, payload = journal.read_record(fixtures.u64(item, 24 if version else 28))
                    self.assertEqual(fixtures.u16(payload, 0), 8)
                    self.assertIn(fixtures.u16(payload, 12), slots)
                    self.assertEqual(fixtures.u16(payload, 6), 32768)
                    records.append(payload)
                self.assertEqual(len(records), 2)
                self.replay()
                self.assert_large_index(fixture)

    def test_64k_index_retries_after_partial_target_writes(self):
        for fault in ("fail_target_at", "torn_target_at", "fail_clean", "fail_sync"):
            points = (0, 512, 32768, 65024) if fault.endswith("target_at") else (1, 2)
            for offset in points:
                with self.subTest(fault=fault, offset=offset):
                    self.setUp()
                    fixture = self.large_index_undo_fixture()
                    point = 5000 * self.image.cluster_size + offset
                    self.replay(1, **{fault: point if fault.endswith("target_at") else offset})
                    self.replay()
                    self.assert_large_index(fixture)
                    self.replay()
                    self.assert_large_index(fixture)

    def test_64k_index_without_checkpoint_space_is_read_only(self):
        fixture = self.large_index_undo_fixture()
        journal = fixture[0]
        restart = unprotect(self.image.read_stream(journal.runs, 0, PAGE))
        current = fixtures.u64(restart, 48)
        for copy in (0, 1):
            journal.restart(copy, current, current, journal.lsn(journal.first + 5, sequence=0))
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay(1)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_redo_precedes_fsck_mount_and_scan(self):
        _, _, _, original = self.sizes_fixture()
        output = self.result(1)
        self.assertIn("1 redo, 0 undo", output)
        self.assertLess(output.index("Recover logfile"), output.index("Scan mft"))
        self.assert_sizes(original)
        self.result(0, "-n")

    def test_active_transaction_is_undone(self):
        _, _, _, original = self.sizes_fixture(undo=True)
        self.assertIn("0 redo, 1 undo", self.result(1))
        self.assert_sizes(original)
        self.result(0, "-n")

    def test_checkpoint_seeds_undo_chain(self):
        _, _, _, original = self.sizes_fixture(undo=True, seed_undo=True)
        self.assertIn("0 redo, 1 undo", self.result(1))
        self.assert_sizes(original)

    def test_empty_checkpoint_discovers_later_records(self):
        journal, _, page, original = self.sizes_fixture(empty_checkpoint=True)
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        # A complete tail record can have a different length from the checkpoint.
        struct.pack_into("<I", raw, 64 + 24, 72)
        struct.pack_into("<H", raw, 24, 64 + 48 + 72)
        journal.write_page(page, raw)
        self.assertIn("1 redo", self.result(1))
        self.assert_sizes(original)
        restart = self.image.read_stream(journal.runs, 0, PAGE)
        self.assertEqual(fixtures.u32(restart, 48 + 32), 72)

    def test_torn_restart_uses_older_durable_copy(self):
        _, _, _, original = self.sizes_fixture(torn_restart=True)
        self.assertIn("older durable", self.result(1))
        self.assert_sizes(original)

    def test_restart_fixup_uses_the_other_copy(self):
        journal, _, _, original = self.sizes_fixture()
        raw = bytearray(self.image.read_stream(journal.runs, 0, PAGE))
        raw[510] ^= 1
        journal.write_page(0, raw)
        self.replay()
        self.assert_sizes(original)

    def test_tail_copy_recovers_a_torn_record_page(self):
        for major in (1, 2):
            with self.subTest(major=major):
                self.setUp()
                journal, _, page, original = self.sizes_fixture(major=major)
                raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
                struct.pack_into("<Q", raw, 8, page * PAGE)
                journal.write_page(2, raw)
                journal.write_page(page, bytes(PAGE))
                self.replay()
                self.assert_sizes(original)

    def test_chkd_restart_is_clean(self):
        journal, _, _, original = self.sizes_fixture()
        record = self.image.record(10)
        offset = self.image.attr(record)
        record[offset + 40:offset + 64] = original
        self.image.write_record(10, record)
        for copy in (0, 1):
            raw = bytearray(self.image.read_stream(journal.runs, copy * PAGE, PAGE))
            raw[:4] = b"CHKD"
            journal.write_page(copy, raw)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_lfs_version_two(self):
        _, _, _, original = self.sizes_fixture(major=2)
        self.assertIn("1 redo", self.result(1))
        self.assert_sizes(original)

    def test_checkpoint_version_zero(self):
        _, _, _, original = self.sizes_fixture(version=0)
        self.assertIn("1 redo", self.result(1))
        self.assert_sizes(original)

    def test_lfs_version_one_zero_redo_and_undo(self):
        for undo in (False, True):
            with self.subTest(undo=undo):
                self.setUp()
                journal, _, _, original = self.sizes_fixture(version=0, minor=0, undo=undo)
                self.assertIn("1 undo" if undo else "1 redo", self.result(1))
                self.assert_sizes(original)
                self.result(0, "-n")
                restart = self.image.read_stream(journal.runs, 0, PAGE)
                self.assertEqual(struct.unpack_from("<HH", restart, 26), (0, 1))

    def test_lfs_version_one_zero_recovery_retry(self):
        _, _, _, original = self.sizes_fixture(version=0, minor=0, undo=True)
        self.replay(1, fail_clean=1)
        self.replay()
        self.assert_sizes(original)

    def test_lfs_version_one_two_stops_before_writing(self):
        self.sizes_fixture(minor=2)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay(1)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def boot_undo_fixture(self, *, mixed=False, major=1, version=1):
        journal = Journal(self.image, major=major, checkpoint_version=version)
        original = self.image.read(0, 2 * self.image.cluster_size)
        mref = (fixtures.u16(self.image.record(7), 16) << 48) | 7
        actions = []
        for cluster in range(2 if mixed else 1):
            start = cluster * self.image.cluster_size + 384
            data = original[start:start + 516]
            self.image.write(start, b"BAD!")
            self.image.write(start + 512, b"BAD!")
            actions.append(journal.log(0, 8, undo_data=data, lcns=[cluster],
                                       vcn=cluster, record_off=384,
                                       undo_next=journal.lsn(journal.first + 2) if cluster else 0))
        journal.emit(actions, target_vcn=0, target_lcns=[0, 1] if mixed else [0], mref=mref)
        return journal, original

    def test_boot_cluster_zero_undo(self):
        for major in (1, 2):
            for version in (0, 1):
                with self.subTest(major=major, version=version):
                    self.setUp()
                    _, original = self.boot_undo_fixture(major=major, version=version)
                    self.assertIn("1 undo", self.replay())
                    self.assertEqual(self.image.read(0, len(original)), original)
                    self.replay()

    def test_boot_cluster_zero_undo_retries(self):
        for mixed in (False, True):
            for fault in ("fail_target_at", "torn_target_at", "fail_clean"):
                with self.subTest(mixed=mixed, fault=fault):
                    self.setUp()
                    journal, original = self.boot_undo_fixture(mixed=mixed)
                    self.replay(1, **{fault: 1})
                    restart = unprotect(self.image.read_stream(journal.runs, 0, PAGE))
                    _, checkpoint = journal.read_record(fixtures.u64(restart, 120))
                    self.assertNotEqual(fixtures.u64(checkpoint, 40), 0)
                    self.replay()
                    self.assertEqual(self.image.read(0, len(original)), original)
                    self.replay()

    def test_boot_cluster_zero_retry_at_each_write_and_sync(self):
        _, original = self.boot_undo_fixture(mixed=True)
        saved = self.directory / "boot-retry-base.img"
        shutil.copyfile(self.path, saved)
        for fault, code in (("fail_write", 1), ("torn_write", 1),
                            ("crash_write", 75), ("fail_sync", 1)):
            for nth in range(1, 50):
                with self.subTest(fault=fault, nth=nth):
                    shutil.copyfile(saved, self.path)
                    run = subprocess.run([str(self.driver), str(self.path)], capture_output=True,
                                         env={**os.environ, "NTFSCK_REPLAY_" + fault.upper(): str(nth)},
                                         timeout=30)
                    if run.returncode == 0:
                        self.assertGreater(nth, 1)
                        break
                    self.assertEqual(run.returncode, code, (run.stdout + run.stderr).decode())
                    self.replay()
                    self.assertEqual(self.image.read(0, len(original)), original)
            else:
                self.fail("fault sweep did not reach the end of commit")

    def test_large_log_pages_redo_and_undo(self):
        for undo in (False, True):
            with self.subTest(undo=undo):
                self.setUp()
                _, _, _, original = self.sizes_fixture(page_size=65536, undo=undo)
                self.assertIn("1 undo" if undo else "1 redo", self.result(1))
                self.assert_sizes(original)
                self.result(0, "-n")

    def test_large_log_page_recovery_with_multi_page_dump(self):
        journal, _, page, original = self.sizes_fixture(page_size=65536, undo=True)
        _, action = journal.read_record(journal.lsn(page))
        entry = struct.pack("<IIIBBBBQQQ", 0xffffffff, 0, 0x80, 0, 0, 0, 0, 0, 0, 0)
        opened = journal.log(0x1c, attr=65504, data=entry)
        journal.emit([opened, (action, 0, 0, 24)], target_vcn=fixtures.u64(action, 24),
                     target_lcns=[fixtures.u64(action, 32)])
        target = next(self.image.spans(self.image.mft_runs,
                      10 * self.image.record_size, self.image.record_size))[0]
        self.replay(1, fail_target_at=target)
        restart = unprotect(self.image.read_stream(journal.runs, 0, PAGE))
        _, checkpoint = journal.read_record(fixtures.u64(restart, 120))
        attr_lsn = fixtures.u64(checkpoint, 16)
        header, dump = journal.read_record(attr_lsn)
        self.assertTrue(fixtures.u16(header, 40) & 1)
        self.assertGreater(fixtures.u32(checkpoint, 48), 65535)
        self.assertEqual(fixtures.u16(dump, 6), 65535)
        self.assertEqual(fixtures.u16(dump, 8), fixtures.u16(dump, 4))
        self.assertEqual(len(dump), 40 + fixtures.u32(checkpoint, 48))
        self.replay()
        self.assert_sizes(original)
        self.replay()

    def test_large_log_page_undo_retries(self):
        for fault in ("fail_target_at", "torn_target_at", "fail_clean", "fail_sync"):
            with self.subTest(fault=fault):
                self.setUp()
                _, _, _, original = self.sizes_fixture(page_size=65536, undo=True)
                target = next(self.image.spans(self.image.mft_runs,
                              10 * self.image.record_size, self.image.record_size))[0]
                self.replay(1, **{fault: target if fault.endswith("target_at") else 2})
                self.replay()
                self.assert_sizes(original)

    def test_read_only_preserves_pending_journal(self):
        self.sizes_fixture()
        before = hashlib.sha256(self.path.read_bytes()).digest()
        output = self.result(4, "-n")
        self.assertNotIn("Scan mft", output)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_bad_opcode_preserves_all_metadata(self):
        journal, _, page, _ = self.sizes_fixture()
        payload = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        # Change the first redo opcode; this is outside a sector tail.
        struct.pack_into("<H", payload, 112, 0x26)
        journal.write_page(page, payload)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.assertIn("stopping before", self.result(4))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_bad_log_page_fixup_preserves_image(self):
        journal, _, page, _ = self.sizes_fixture()
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        raw[510] ^= 1
        journal.write_page(page, raw)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_undo_chain_cycle_preserves_image(self):
        journal, _, page, _ = self.sizes_fixture(undo=True)
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        struct.pack_into("<Q", raw, 64 + 16, journal.lsn(page))
        journal.write_page(page, raw)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_target_outside_volume_preserves_image(self):
        journal, _, page, _ = self.sizes_fixture()
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        struct.pack_into("<Q", raw, 112 + 32, self.image.nr_clusters + 1)
        journal.write_page(page, raw)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_recovery_preserves_lsn_epoch(self):
        journal, _, _, original = self.sizes_fixture()
        self.result(1)
        first = self.image.read_stream(journal.runs, 0, PAGE)
        second = self.image.read_stream(journal.runs, PAGE, PAGE)
        self.assertEqual(first, second)
        self.assertTrue(fixtures.u16(first, 48 + 14) & 2)
        self.assertGreaterEqual(fixtures.u64(first, 48), 1 << journal.file_bits)
        self.assert_sizes(original)
        self.assertNotEqual(fixtures.u64(fixtures.Image(self.path).record(10), 8), 0)

    def test_distinct_valid_and_data_sizes(self):
        journal, _, page, original = self.sizes_fixture()
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        alloc, data, _ = struct.unpack("<QQQ", original)
        # SetNewAttributeSizes logs alloc/valid/data, unlike an ATTR_RECORD.
        struct.pack_into("<QQQ", raw, 152, alloc, 12345, data)
        journal.write_page(page, raw)
        self.replay()
        record = fixtures.Image(self.path).record(10)
        offset = self.image.attr(record)
        self.assertEqual(struct.unpack_from("<QQQ", record, offset + 40),
                         (alloc, data, 12345))

    def test_bitmap_redo_and_undo(self):
        for undo in (False, True):
            for set_bits in (False, True):
                with self.subTest(undo=undo, set_bits=set_bits):
                    self.setUp()
                    journal = Journal(self.image)
                    lcn = 5000
                    self.image.write(lcn * self.image.cluster_size, b"\xa5" * 4096)
                    payload = struct.pack("<II", 5, 10)
                    op = 0x15 if set_bits else 0x16
                    action = journal.log(0 if undo else op, op if undo else 0,
                                         data=b"" if undo else payload,
                                         undo_data=payload if undo else b"",
                                         lcns=[lcn])
                    journal.emit([action], target_vcn=0, target_lcns=[lcn], atype=0xb0)
                    self.replay()
                    actual = self.image.read(lcn * self.image.cluster_size, 3)
                    expected = int.from_bytes(b"\xa5" * 3, "little")
                    mask = ((1 << 10) - 1) << 5
                    expected = expected | mask if set_bits else expected & ~mask
                    self.assertEqual(actual, expected.to_bytes(3, "little"))

    def test_deleted_dirty_clusters_are_not_replayed(self):
        journal = Journal(self.image)
        lcn = 5000
        self.image.write(lcn * self.image.cluster_size, b"\xa5" * 4096)
        action = journal.log(8, data=b"must not be written", lcns=[lcn])
        delete = journal.log(0xa, attr=0, data=struct.pack("<QQ", lcn, 1))
        journal.emit([action, delete], target_vcn=0, target_lcns=[lcn])
        self.assertIn("0 redo", self.replay())
        self.assertEqual(self.image.read(lcn * self.image.cluster_size, 4096), b"\xa5" * 4096)

    def set_dirty_oldest(self, journal, lsn):
        page = journal.first + 1
        raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
        struct.pack_into("<Q", raw, 112 + 40 + 24 + (24 if journal.version else 28), lsn)
        journal.write_page(page, raw)

    def test_checkpoint_oldest_preserves_reallocated_file(self):
        source = self.directory / "owner.bin"
        contents = b"NEW OWNER MUST SURVIVE" * 500
        source.write_bytes(contents)
        copied = fixtures.command("ntfscp", self.path, source, "/owner.bin")
        self.assertEqual(copied.returncode, 0, copied.stderr)
        self.image = fixtures.Image(self.path)
        owner = self.image.find("owner.bin")
        runs, _ = self.image.data_stream(self.image.record(owner))
        old, current = runs[0][1], 5001
        self.assertFalse(any(lcn <= current < lcn + count for _, lcn, count in runs))
        journal = Journal(self.image)
        stale = journal.log(8, data=b"STALE JOURNAL OVERWRITE", lcns=[old])
        live = journal.log(8, data=b"LIVE", lcns=[current])
        _, first = journal.emit([stale, live], target_vcn=0, target_lcns=[current])
        self.set_dirty_oldest(journal, journal.lsn(first + 1))
        self.replay()
        read = fixtures.command("ntfscat", self.path, "/owner.bin")
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(read.stdout, contents)
        self.assertEqual(self.image.read(current * self.image.cluster_size, 4), b"LIVE")

    def test_transaction_first_lsn_replays_initialization(self):
        for version in (0, 1):
            with self.subTest(version=version):
                self.setUp()
                journal = Journal(self.image, checkpoint_version=version)
                record = self.image.record(10)
                position = 10 * self.image.record_size
                vcn, within = divmod(position, self.image.cluster_size)
                lcn = self.image.mft_runs[0][1] + vcn
                si = self.image.attr(record, 0x10)
                init = journal.log(2, data=bytes(record), lcns=[lcn], vcn=vcn,
                                   cluster_off=within // 512)
                edit = journal.log(7, data=bytes(record[si + 24:si + 32]), lcns=[lcn],
                                   vcn=vcn, cluster_off=within // 512,
                                   record_off=si, attr_off=24)
                cp, first = journal.emit([init, edit], target_vcn=vcn,
                                         target_lcns=[lcn], seed_undo=True)
                self.set_dirty_oldest(journal, journal.lsn(first + 1))
                raw = bytearray(self.image.read_stream(journal.runs, (cp - 1) * PAGE, PAGE))
                # Committed transactions still need their first redo record.
                entry = 112 + 40 + 24
                raw[entry + 4] = 3
                struct.pack_into("<QQQ", raw, entry + 8, journal.lsn(first),
                                 journal.lsn(first + 1), journal.lsn(first + 1))
                journal.write_page(cp - 1, raw)
                self.image.write_stream(self.image.mft_runs, position, bytes(self.image.record_size))
                self.replay()
                repaired = fixtures.Image(self.path).record(10)
                self.assertEqual(repaired[si + 24:si + 32], record[si + 24:si + 32])
                self.assertEqual(repaired[:4], b"FILE")

    def test_raw_redo_preserves_live_part_of_dirty_range(self):
        for freed in (5000, 5001):
            with self.subTest(freed=freed):
                self.setUp()
                journal = Journal(self.image)
                self.image.write(5000 * self.image.cluster_size, b"X" * 4096 + b"Y" * 4096)
                payload = b"A" * 4096 + b"B" * 1904
                action = journal.log(8, data=payload, lcns=[5000, 5001])
                delete = journal.log(0xa, attr=0, data=struct.pack("<QQ", freed, 1))
                journal.emit([journal.log(0), journal.log(0), delete],
                             target_vcn=0, target_lcns=[5000, 5001])
                journal.two_page_record(journal.first + 2, action)
                self.replay()
                expected = (b"X" * 4096 if freed == 5000 else b"A" * 4096)
                expected += b"Y" * 4096 if freed == 5001 else b"B" * 1904 + b"Y" * 2192
                self.assertEqual(self.image.read(5000 * self.image.cluster_size, 8192), expected)

    def test_bitmap_redo_preserves_live_part_of_dirty_range(self):
        for freed in (5000, 5001):
            with self.subTest(freed=freed):
                self.setUp()
                journal = Journal(self.image)
                self.image.write(5000 * self.image.cluster_size, b"\x55" * 8192)
                action = journal.log(0x15, data=struct.pack("<II", 4096 * 8 - 4, 16),
                                     lcns=[5000, 5001])
                delete = journal.log(0xa, attr=0, data=struct.pack("<QQ", freed, 1))
                journal.emit([action, delete], target_vcn=0,
                             target_lcns=[5000, 5001], atype=0xb0)
                self.replay()
                expected = bytearray(b"\x55" * 8192)
                if freed != 5000:
                    expected[4095] = 0xf5
                if freed != 5001:
                    expected[4096:4098] = b"\xff\x5f"
                self.assertEqual(self.image.read(5000 * self.image.cluster_size, 8192), expected)

    def relative_undo_fixture(self, *, major=1, version=1, mixed=False, block_size=PAGE):
        journal = Journal(self.image, major=major, checkpoint_version=version)
        first = 304 if block_size == 65536 else 64
        block = bytearray(block_size)
        struct.pack_into("<4sHHQQ4I", block, 0, b"INDX", 40, block_size // 512 + 1, 0, 0,
                         first - 24, first + 48 - 24, block_size - 24, 0)
        struct.pack_into("<HH", block, first, 24, 4)
        struct.pack_into("<HHHH", block, first + 8, 32, 8, 0, 0)
        struct.pack_into("<I", block, first + 24, 100)
        struct.pack_into("<HHHH", block, first + 40, 16, 0, 2, 0)
        self.image.write(5000 * self.image.cluster_size, protect(block, 40))
        lcns = list(range(5000, 5000 + block_size // self.image.cluster_size))
        action = journal.log(0x24, 0x24, data=struct.pack("<I", 0xfffffff6),
                             undo_data=struct.pack("<I", 10), lcns=lcns, attr_off=first)
        actions = [action]
        if mixed:
            # Two changed raw sectors in the same VCN exercise the new dirty table.
            slot = 24 + (40 if version else 44)
            if version:
                entry = struct.pack("<IIIBBBBQQQ", 0xffffffff, 0, 0xb0, 0, 0, 0, 0, 0, 0, 0)
            else:
                entry = struct.pack("<IIQQBB2xIB3xII", 0xffffffff, 0, 0, 0, 0, 0, 0xb0, 0, 0, 0)
            actions.append(journal.log(0x1c, attr=slot, data=entry))
            actions.append(journal.log(8, 8, data=b"\xbb" * 600, undo_data=b"\xcc" * 600,
                                       attr=slot, lcns=[5001],
                                       undo_next=journal.lsn(journal.first + 2)))
            self.image.write(5001 * self.image.cluster_size, b"\xbb" * 4096)
        journal.emit(actions, target_vcn=0, target_lcns=lcns, atype=0xa0, index_size=block_size)
        return journal

    def test_64k_index_relative_undo_retries_without_repeating_the_delta(self):
        for version in (0, 1):
            for fault in ("fail_clean", "torn_target_at"):
                with self.subTest(version=version, fault=fault):
                    self.setUp()
                    self.relative_undo_fixture(version=version, block_size=65536)
                    point = 5000 * self.image.cluster_size + 32768
                    self.replay(1, **{fault: point if fault == "torn_target_at" else 1})
                    for _ in range(2):
                        self.replay()
                        raw = unprotect(self.image.read(5000 * self.image.cluster_size, 65536))
                        self.assertEqual(fixtures.u32(raw, 328), 100)

    def assert_relative_undo(self, *, mixed=False):
        raw = self.image.read(5000 * self.image.cluster_size, PAGE)
        self.assertEqual(fixtures.u32(raw, 88), 100)
        for sector in range(1, 9):
            self.assertEqual(raw[sector * 512 - 2:sector * 512], raw[40:42])
        if mixed:
            self.assertEqual(self.image.read(5001 * self.image.cluster_size, 4096),
                             b"\xcc" * 600 + b"\xbb" * (4096 - 600))

    def test_relative_undo_retry_after_restart_write_failure(self):
        for major, version in ((1, 1), (1, 0), (2, 1)):
            for failure in ("fail_dirty", "fail_clean"):
                with self.subTest(major=major, version=version, failure=failure):
                    self.setUp()
                    journal = self.relative_undo_fixture(major=major, version=version, mixed=True)
                    self.replay(1, **{failure: 1})
                    if failure == "fail_clean":
                        self.assert_relative_undo(mixed=True)
                    restart = self.image.read_stream(journal.runs, 0, PAGE)
                    self.assertFalse(fixtures.u16(restart, 48 + 14) & 2)
                    self.replay()
                    self.assert_relative_undo(mixed=True)
                    self.replay()
                    self.assert_relative_undo(mixed=True)

    def test_relative_undo_retry_at_each_write_and_sync(self):
        self.relative_undo_fixture(mixed=True)
        saved = self.directory / "retry-base.img"
        shutil.copyfile(self.path, saved)
        for fault, code in (("fail_write", 1), ("torn_write", 1),
                            ("crash_write", 75), ("fail_sync", 1)):
            for nth in range(1, 80):
                with self.subTest(fault=fault, nth=nth):
                    shutil.copyfile(saved, self.path)
                    run = subprocess.run([str(self.driver), str(self.path)], capture_output=True,
                                         env={**os.environ, "NTFSCK_REPLAY_" + fault.upper(): str(nth)},
                                         timeout=30)
                    if run.returncode == 0:
                        self.assertGreater(nth, 1)
                        break
                    self.assertEqual(run.returncode, code, (run.stdout + run.stderr).decode())
                    self.replay()
                    self.assert_relative_undo(mixed=True)
            else:
                self.fail("fault sweep did not reach the end of commit")

    def test_mft_undo_retry_after_torn_writes(self):
        _, _, _, original = self.sizes_fixture(undo=True)
        saved = self.directory / "mft-retry-base.img"
        shutil.copyfile(self.path, saved)
        for nth in range(1, 40):
            with self.subTest(nth=nth):
                shutil.copyfile(saved, self.path)
                run = subprocess.run([str(self.driver), str(self.path)], capture_output=True,
                                     env={**os.environ, "NTFSCK_REPLAY_TORN_WRITE": str(nth)}, timeout=30)
                if run.returncode == 0:
                    break
                self.assertEqual(run.returncode, 1, (run.stdout + run.stderr).decode())
                self.replay()
                self.assert_sizes(original)
        else:
            self.fail("fault sweep did not reach the end of commit")

    def test_undo_without_free_log_pages_preserves_image(self):
        journal = self.relative_undo_fixture()
        cp = journal.first + 3
        for copy in (0, 1):
            journal.restart(copy, journal.lsn(cp), journal.lsn(cp),
                            journal.lsn(cp + 1, sequence=0))
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay(1)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_undo_retry_after_recovery_log_wraps(self):
        journal = self.relative_undo_fixture()
        last = journal.size // PAGE - 1
        oldest = journal.lsn(last - 3)
        for i in range(4):
            raw = bytearray(self.image.read_stream(journal.runs, (journal.first + i) * PAGE, PAGE))
            lsn = journal.lsn(last - 3 + i)
            for offset in (8, 32, 64):
                struct.pack_into("<Q", raw, offset, lsn)
            if i == 1:
                struct.pack_into("<Q", raw, 112 + 40 + 24 + 24, oldest)
            elif i == 3:
                struct.pack_into("<QQQQ", raw, 112 + 8, oldest, oldest, 0,
                                 journal.lsn(last - 2))
            journal.write_page(last - 3 + i, raw)
        for copy in (0, 1):
            journal.restart(copy, journal.lsn(last), journal.lsn(last), oldest)
        self.replay(1, fail_clean=1)
        self.replay()
        self.assert_relative_undo()
        restart = self.image.read_stream(journal.runs, 0, PAGE)
        self.assertEqual(fixtures.u64(restart, 48) >> journal.file_bits, 2)

    def test_undo_retry_retains_attribute_names(self):
        journal = self.relative_undo_fixture()
        first, cp = journal.first, journal.first + 3
        raw = bytearray(self.image.read_stream(journal.runs, first * PAGE, PAGE))
        entry = 112 + 40 + 24
        raw[entry + 13:entry + 15] = b"\x01\x04"
        journal.write_page(first, raw)
        name = struct.pack("<HH", 24, 8) + "$I30".encode("utf-16le") + bytes(2)
        journal.record(cp + 1, journal.log(0x1e, attr=0, data=name))
        raw = bytearray(self.image.read_stream(journal.runs, cp * PAGE, PAGE))
        struct.pack_into("<Q", raw, 112 + 24, journal.lsn(cp + 1))
        struct.pack_into("<I", raw, 112 + 52, len(name))
        journal.write_page(cp, raw)
        for copy in (0, 1):
            journal.restart(copy, journal.lsn(cp + 1), journal.lsn(cp), journal.lsn(first))
        self.replay(1, fail_clean=1)
        restart = self.image.read_stream(journal.runs, 0, PAGE)
        mask = (1 << journal.file_bits) - 1
        new_cp = (fixtures.u64(restart, 112 + 8) & mask) * 8
        checkpoint = self.image.read_stream(journal.runs, new_cp + 48, 64)
        names_lsn = fixtures.u64(checkpoint, 24)
        self.assertNotEqual(names_lsn, 0)
        dump = self.image.read_stream(journal.runs, (names_lsn & mask) * 8 + 48 + 40, len(name))
        self.assertEqual(dump, name)
        self.replay()
        self.assert_relative_undo()

    def test_undo_without_client_oldest_uses_referenced_records(self):
        journal = self.relative_undo_fixture()
        for copy in (0, 1):
            journal.restart(copy, journal.lsn(journal.first + 3),
                            journal.lsn(journal.first + 3), 0)
        self.replay(1, fail_clean=1)
        self.replay()
        self.assert_relative_undo()

    def test_undo_with_unchanged_targets_has_no_dirty_dump(self):
        journal = Journal(self.image)
        self.image.write(5000 * self.image.cluster_size, bytes(PAGE))
        action = journal.log(0, 0x16, undo_data=struct.pack("<II", 0, 8), lcns=[5000])
        journal.emit([action], target_vcn=0, target_lcns=[5000], atype=0xb0)
        self.replay(1, fail_clean=1)
        restart = self.image.read_stream(journal.runs, 0, PAGE)
        mask = (1 << journal.file_bits) - 1
        cp = (fixtures.u64(restart, 112 + 8) & mask) * 8
        checkpoint = self.image.read_stream(journal.runs, cp + 48, 64)
        self.assertEqual(fixtures.u64(checkpoint, 32), 0)
        self.assertEqual(fixtures.u32(checkpoint, 56), 0)
        self.replay()
        self.assertEqual(self.image.read(5000 * self.image.cluster_size, PAGE), bytes(PAGE))

    def test_log_read_errors_stop_before_changing_the_image(self):
        for major in (1, 2):
            for tail in (False, True):
                for fault in ("eio", "enomem", "short_read"):
                    with self.subTest(major=major, tail=tail, fault=fault):
                        self.setUp()
                        journal, _, page, original = self.sizes_fixture(
                            major=major, empty_checkpoint=tail)
                        physical = next(self.image.spans(journal.runs, page * PAGE, PAGE))[0]
                        options = {"fail_read_at": physical}
                        if fault == "enomem":
                            options["read_errno"] = errno.ENOMEM
                        elif fault == "short_read":
                            options = {"short_read_at": physical}
                        before = hashlib.sha256(self.path.read_bytes()).digest()
                        self.replay(1, **options)
                        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
                        self.replay()
                        self.assert_sizes(original)

    def move_mft_cluster(self, vcn, destination=9000, *, install=True):
        record = self.image.record(0)
        offset = self.image.attr(record)
        self.assertEqual(len(self.image.mft_runs), 1)
        _, base, count = self.image.mft_runs[0]
        old = base + vcn
        self.image.write(destination * self.image.cluster_size,
                         self.image.read(old * self.image.cluster_size, self.image.cluster_size))
        runs = [(0, base, vcn), (vcn, destination, 1)]
        if count > vcn + 1:
            runs.append((vcn + 1, base + vcn + 1, count - vcn - 1))
        pairs = fixtures.RepairTests.mapping_pairs(runs)
        if install:
            mp = fixtures.u16(record, offset + 32)
            header = bytes(record[offset:offset + mp])
            length = (mp + len(pairs) + 7) & ~7
            fixtures.RepairTests.resize_fixture_attr(record, offset, length)
            record[offset:offset + mp] = header
            struct.pack_into("<I", record, offset + 4, length)
            record[offset + mp:offset + mp + len(pairs)] = pairs
            self.image.write_record(0, record)
            raw = self.image.read(self.image.mft_offset, self.image.record_size)
            self.image.write(self.image.mirror_offset, raw)
            self.image = fixtures.Image(self.path)
            fixtures.RepairTests.set_bitmap_clusters(None, self.image, [destination])
            fixtures.RepairTests.set_bitmap_clusters(None, self.image, [old], used=False)
        return old, destination, pairs

    def test_overlapping_dirty_entries_keep_checkpoint_order(self):
        for version in (0, 1):
            for narrow_first in (False, True):
                with self.subTest(version=version, narrow_first=narrow_first):
                    self.setUp()
                    journal = Journal(self.image, checkpoint_version=version)
                    small = journal.log(8, data=b"SMAL", lcns=[5001], vcn=1, cluster_off=2)
                    wide = journal.log(8, data=b"WIDE", lcns=[5000, 5001],
                                       record_off=510, cluster_off=7)
                    cp, page = journal.emit([small, wide], target_vcn=1, target_lcns=[5001])
                    ranges = [(1, journal.lsn(page), [5001]),
                              (0, journal.lsn(page + 1), [5000, 5001])]
                    if not narrow_first:
                        # A contained dead slot must not erase a wider, live slot.
                        ranges = [(0, journal.lsn(page), [5000, 5001]),
                                  (1, journal.lsn(page + 1), [0])]
                    stride = (32 if version else 36) + 16
                    entries = []
                    for vcn, oldest, lcns in ranges:
                        entry = struct.pack("<IIII", 0xffffffff, 24,
                                            len(lcns) * self.image.cluster_size, len(lcns))
                        entry += b"" if version else bytes(4)
                        entry += struct.pack("<QQ", vcn, oldest)
                        entry += struct.pack("<" + "Q" * len(lcns), *lcns)
                        entries.append(entry.ljust(stride, b"\0"))
                    table = struct.pack("<6H3I", stride, 2, 2, 0, 0, 0, 0, 0, 0)
                    table += b"".join(entries)
                    journal.record(journal.first + 1, journal.log(0x1f, attr=0, data=table))
                    raw = bytearray(self.image.read_stream(journal.runs, cp * PAGE, PAGE))
                    struct.pack_into("<Q", raw, 112 + 8, journal.lsn(cp))
                    struct.pack_into("<I", raw, 112 + 56, len(table))
                    journal.write_page(cp, raw)
                    self.image.write(5000 * self.image.cluster_size, bytes(8192))
                    self.assertIn("2 redo", self.replay())
                    self.assertEqual(self.image.read(5001 * self.image.cluster_size + 1024, 4), b"SMAL")
                    self.assertEqual(self.image.read(5000 * self.image.cluster_size + 4094, 4), b"WIDE")

    def test_prepass_keeps_overlapping_dirty_ranges_in_log_order(self):
        journal = Journal(self.image)
        small = journal.log(8, data=b"SMAL", lcns=[5001], vcn=1, cluster_off=2)
        wide = journal.log(8, data=b"WIDE", lcns=[5000, 5001],
                           record_off=510, cluster_off=7)
        journal.emit([small, wide], target_vcn=1, target_lcns=[5001], empty_checkpoint=True)
        self.image.write(5000 * self.image.cluster_size, bytes(8192))
        self.assertIn("2 redo", self.replay())
        self.assertEqual(self.image.read(5001 * self.image.cluster_size + 1024, 4), b"SMAL")

    def test_tail_copy_read_errors_stop_before_writing(self):
        for major in (1, 2):
            for fault in ("eio", "enomem", "short_read"):
                with self.subTest(major=major, fault=fault):
                    self.setUp()
                    journal, _, page, original = self.sizes_fixture(major=major, empty_checkpoint=True)
                    tail = self.image.read_stream(journal.runs, page * PAGE, PAGE)
                    journal.write_page(2, tail)
                    journal.write_page(page, b"\xff" * PAGE)
                    physical = next(self.image.spans(journal.runs, 2 * PAGE, PAGE))[0]
                    options = {"fail_read_at": physical}
                    if fault == "enomem":
                        options["read_errno"] = errno.ENOMEM
                    elif fault == "short_read":
                        options = {"short_read_at": physical}
                    before = hashlib.sha256(self.path.read_bytes()).digest()
                    self.replay(1, **options)
                    self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
                    self.assertIn("1 redo", self.replay())
                    self.assert_sizes(original)

    def test_missing_undo_payload_stops_before_writing(self):
        for major in (1, 2):
            with self.subTest(major=major):
                self.setUp()
                journal, _, page, original = self.sizes_fixture(major=major, undo=True)
                valid = self.image.read_stream(journal.runs, page * PAGE, PAGE)
                raw = bytearray(valid)
                struct.pack_into("<I", raw, 64 + 24, 40)
                struct.pack_into("<H", raw, 24, 64 + 48 + 40)
                struct.pack_into("<H", raw, 64 + 40, 4)  # UNDO_NOT_INLINE
                struct.pack_into("<HH", raw, 112 + 8, 40, 24)
                journal.write_page(page, raw)
                before = hashlib.sha256(self.path.read_bytes()).digest()
                self.replay(1)
                self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
                journal.write_page(page, valid)
                self.assertIn("1 undo", self.replay())
                self.assert_sizes(original)

    def fixture_operation(self, *args):
        run = subprocess.run([str(self.driver), *map(str, args)], capture_output=True,
                             env={**os.environ, "LC_ALL": "C"}, timeout=30)
        self.assertEqual(run.returncode, 0, (run.stdout + run.stderr).decode())
        self.image = fixtures.Image(self.path)
        return run.stdout.decode().strip()

    def directory_filenames(self, parent, update=None):
        values = {}

        def scan(buffer, base):
            offset = base + fixtures.u32(buffer, base)
            end = base + fixtures.u32(buffer, base + 4)
            changed = False
            while offset + 16 <= end:
                length = fixtures.u16(buffer, offset + 8)
                self.assertGreaterEqual(length, 16)
                if not fixtures.u16(buffer, offset + 12) & 2:
                    value = offset + 16
                    size = buffer[value + 64]
                    name = bytes(buffer[value + 66:value + 66 + size * 2]).decode("utf-16le")
                    if update:
                        changed |= update(buffer, value, name)
                    values[name] = bytes(buffer[value:value + 66])
                offset += length
            return changed

        record = self.image.record(parent)
        root = self.image.attr(record, 0x90, "$I30")
        root_value = root + fixtures.u16(record, root + 20)
        block_size = fixtures.u32(record, root_value + 8)
        if scan(record, root_value + 16):
            self.image.write_record(parent, record)
        try:
            allocation = self.image.attr(record, 0xa0, "$I30")
        except StopIteration:
            return values
        runs = self.image.runs(record, allocation)
        size = fixtures.u64(record, allocation + 48)
        for offset in range(0, size, block_size):
            block = bytearray(self.image.read_stream(runs, offset, block_size))
            if block[:4] != b"INDX":
                continue
            usa, count = struct.unpack_from("<HH", block, 4)
            for sector in range(1, count):
                tail = sector * 512 - 2
                self.assertEqual(block[tail:tail + 2], block[usa:usa + 2])
                block[tail:tail + 2] = block[usa + sector * 2:usa + sector * 2 + 2]
            if scan(block, 24):
                self.image.write_stream(runs, offset, protect(block, usa))
        return values

    def directory_sizes(self, parent, updates=None):
        def update(buffer, value, name):
            if updates and name in updates:
                struct.pack_into("<QQ", buffer, value + 40, *updates[name])
                return True
            return False

        values = self.directory_filenames(parent, update if updates else None)
        return {name: struct.unpack_from("<QQ", value, 40) for name, value in values.items()}

    def filename_records(self, number):
        records = {number}
        base = self.image.record(number)
        try:
            attr = self.image.attr(base, 0x20)
        except StopIteration:
            return records
        self.assertEqual(base[attr + 8], 0)
        offset = attr + fixtures.u16(base, attr + 20)
        end = offset + fixtures.u32(base, attr + 16)
        while offset < end:
            if fixtures.u32(base, offset) == 0x30:
                records.add(fixtures.u64(base, offset + 16) & ((1 << 48) - 1))
            offset += fixtures.u16(base, offset + 4)
        return records

    def filename_fixture(self, *, undo=False, resident=False, resident_index=False,
                         hardlink=False, extent_type=None, stale_index=False,
                         already_applied=False, major=1, version=1, page_size=PAGE,
                         large_index=False):
        parent, prefix = 5, "/"
        if resident_index:
            parent = int(self.fixture_operation("--mkdir", self.path, 5, "names"))
            prefix = "/names/"
        contents = b"N" * (128 if resident else 8192)
        source = self.directory / "owner.bin"
        source.write_bytes(contents)
        copied = fixtures.command("ntfscp", self.path, source, prefix + "owner.bin")
        self.assertEqual(copied.returncode, 0, copied.stderr)
        self.image = fixtures.Image(self.path)
        number = self.image.find("owner.bin")
        names = ["owner.bin"]
        if hardlink:
            self.fixture_operation("--link", self.path, number, parent, "alias.bin")
            names.append("alias.bin")
        target = number
        if extent_type is not None:
            extent = int(self.fixture_operation("--extent", self.path, number, hex(extent_type)))
            if extent_type == 0x80:
                target = extent
        if large_index:
            self.large_index_volume()
        # Verify that the native directory and extent fixtures are consistent.
        self.result(0, "-n")
        stale = 32 if resident else 4096
        for owner in self.filename_records(number):
            record = self.image.record(owner)
            for offset, typ, _ in self.image.attrs(record):
                if typ == 0x30:
                    value = offset + fixtures.u16(record, offset + 20)
                    struct.pack_into("<QQ", record, value + 40, stale, stale)
            self.image.write_record(owner, record)
        if stale_index:
            self.directory_sizes(parent, {name: (stale, stale) for name in names})
        record = self.image.record(target)
        attr = self.image.attr(record)
        original = bytes(record[attr + 40:attr + 64])
        if resident:
            value = fixtures.u16(record, attr + 20)
            original = bytes(record[attr + value:attr + value + len(contents)])
            if not already_applied:
                prefix = bytes(record[attr:attr + value + stale])
                length = (value + stale + 7) & ~7
                fixtures.RepairTests.resize_fixture_attr(record, attr, length)
                record[attr:attr + len(prefix)] = prefix
                struct.pack_into("<I", record, attr + 4, length)
                struct.pack_into("<I", record, attr + 16, stale)
        elif not already_applied:
            struct.pack_into("<QQ", record, attr + 48, stale, stale)
        self.image.write_record(target, record)
        vcn, within = divmod(target * self.image.record_size, self.image.cluster_size)
        lcn = next(lcn + vcn - start for start, lcn, count in self.image.mft_runs
                   if start <= vcn < start + count)
        journal = Journal(self.image, major=major, checkpoint_version=version, page_size=page_size)
        op = 7 if resident else 0xb
        action = journal.log(0 if undo else op, op if undo else 0,
                             data=bytes(stale) if resident and undo else (b"" if undo else original),
                             undo_data=original if undo else (bytes(stale) if resident else b""),
                             lcns=[lcn], vcn=vcn, cluster_off=within // 512,
                             record_off=attr, attr_off=value if resident else 0)
        cp, _ = journal.emit([action], target_vcn=vcn, target_lcns=[lcn])
        if already_applied:
            self.set_dirty_oldest(journal, journal.lsn(cp))
        return number, parent, names, contents, prefix, journal

    def test_64k_index_filename_checkpoints_retry(self):
        for undo in (False, True):
            for fault in ("fail_clean", "torn_target_at"):
                with self.subTest(undo=undo, fault=fault):
                    self.setUp()
                    number, parent, names, contents, _, _ = self.filename_fixture(
                        undo=undo, stale_index=True, large_index=True, hardlink=True)
                    point = 5000 * self.image.cluster_size
                    self.replay(1, **{fault: point if fault == "torn_target_at" else 1})
                    self.replay()
                    self.assert_filename_sizes(number, parent, names, contents)
                    self.replay()
                    self.assert_filename_sizes(number, parent, names, contents)
                    self.result(0, "-n")

    def assert_filename_sizes(self, number, parent, names, contents):
        self.image = fixtures.Image(self.path)
        expected = (len(contents), len(contents))
        actual = []
        for owner in self.filename_records(number):
            record = self.image.record(owner)
            for offset, typ, _ in self.image.attrs(record):
                if typ == 0x30:
                    value = offset + fixtures.u16(record, offset + 20)
                    actual.append(struct.unpack_from("<QQ", record, value + 40))
        self.assertEqual(actual, [expected] * len(names))
        indexed = self.directory_sizes(parent)
        for name in names:
            self.assertEqual(indexed[name], expected)

    def filename_metadata_fixture(self, *, reparse=False, **kwargs):
        number, parent, names, contents, prefix, journal = self.filename_fixture(**kwargs)
        record = self.image.record(number)
        attr = self.image.attr(record, 0x10)
        value = attr + fixtures.u16(record, attr + 20)
        flags = fixtures.u32(record, value + 32) | 0x21 | (0x400 if reparse else 0)
        struct.pack_into("<I", record, value + 32, flags)
        tag = 0xa000000c if reparse else 0
        if reparse:
            target = "target".encode("utf-16le")
            data = struct.pack("<4HI", 0, len(target), len(target), len(target), 1) + target * 2
            data = struct.pack("<IHH", tag, len(data), 0) + data
            length = (24 + len(data) + 7) & ~7
            used = fixtures.u32(record, 24)
            end = used - 8
            self.assertLessEqual(used + length, len(record))
            record[end + length:end + length + 8] = record[end:end + 8]
            record[end:end + length] = bytes(length)
            instance = fixtures.u16(record, 40)
            struct.pack_into("<IIBBHHH", record, end, 0xc0, length, 0, 0, 0, 0, instance)
            struct.pack_into("<IHBB", record, end + 16, len(data), 24, 0, 0)
            record[end + 24:end + 24 + len(data)] = data
            struct.pack_into("<I", record, 24, used + length)
            struct.pack_into("<H", record, 40, instance + 1)
        self.image.write_record(number, record)
        expected = {}
        for owner in self.filename_records(number):
            record = self.image.record(owner)
            for offset, typ, _ in self.image.attrs(record):
                if typ != 0x30:
                    continue
                value = offset + fixtures.u16(record, offset + 20)
                times = tuple(t + 864000000000 for t in struct.unpack_from("<4Q", record, value + 8))
                struct.pack_into("<4Q", record, value + 8, *times)
                name = bytes(record[value + 66:value + 66 + record[value + 64] * 2]).decode("utf-16le")
                expected[name] = times, 0x8 | (flags & 0x47fb7), tag
            self.image.write_record(owner, record)

        def stale(buffer, value, name):
            if name not in expected:
                return False
            struct.pack_into("<II", buffer, value + 56, 0x8, 0xdeadbeef)
            return True

        self.directory_filenames(parent, stale)
        return number, parent, names, contents, prefix, journal, expected

    def assert_filename_metadata(self, parent, expected):
        values = self.directory_filenames(parent)
        for name, (times, flags, tag) in expected.items():
            self.assertEqual(struct.unpack_from("<4Q", values[name], 8), times)
            self.assertEqual(fixtures.u32(values[name], 56), flags)
            self.assertEqual(fixtures.u32(values[name], 60), tag)

    def test_filename_metadata_follows_redo_and_undo(self):
        for undo in (False, True):
            for resident_index in (False, True):
                with self.subTest(undo=undo, resident_index=resident_index):
                    self.setUp()
                    number, parent, names, contents, _, _, expected = self.filename_metadata_fixture(
                        undo=undo, resident_index=resident_index, hardlink=True, extent_type=0x30)
                    self.replay()
                    self.assert_filename_sizes(number, parent, names, contents)
                    self.assert_filename_metadata(parent, expected)
                    self.result(0, "-n")

    def test_filename_reparse_tags_are_copied_and_cleared(self):
        for reparse in (False, True):
            with self.subTest(reparse=reparse):
                self.setUp()
                _, parent, _, _, _, _, expected = self.filename_metadata_fixture(reparse=reparse)
                self.replay()
                self.assert_filename_metadata(parent, expected)

    def test_filename_metadata_only_changes_survive_retry(self):
        number, parent, _, contents, _, _, expected = self.filename_metadata_fixture(
            resident_index=True, already_applied=True)
        record = self.image.record(number)
        for offset, typ, _ in self.image.attrs(record):
            if typ == 0x30:
                value = offset + fixtures.u16(record, offset + 20)
                struct.pack_into("<QQ", record, value + 40, len(contents), len(contents))
        self.image.write_record(number, record)
        target = next(self.image.spans(self.image.mft_runs,
                      parent * self.image.record_size, self.image.record_size))[0]
        self.replay(1, torn_target_at=target)
        self.replay()
        self.assert_filename_metadata(parent, expected)

    def test_full_fsck_updates_filename_metadata(self):
        _, parent, _, _, _, _, expected = self.filename_metadata_fixture()
        self.result(1)
        self.assert_filename_metadata(parent, expected)
        self.result(0, "-n")

    def test_large_log_page_filename_checkpoint_retries(self):
        number, parent, names, contents, _, _, expected = self.filename_metadata_fixture(
            page_size=65536, resident_index=True)
        target = next(self.image.spans(self.image.mft_runs,
                      parent * self.image.record_size, self.image.record_size))[0]
        self.replay(1, torn_target_at=target)
        self.replay()
        self.assert_filename_sizes(number, parent, names, contents)
        self.assert_filename_metadata(parent, expected)

    def test_filename_sizes_follow_final_redo_and_undo(self):
        for undo in (False, True):
            for resident in (False, True):
                for stale_index in (False, True):
                    with self.subTest(undo=undo, resident=resident, stale_index=stale_index):
                        self.setUp()
                        number, parent, names, contents, _, _ = self.filename_fixture(
                            undo=undo, resident=resident, stale_index=stale_index)
                        self.replay()
                        self.assert_filename_sizes(number, parent, names, contents)
                        self.replay()

    def test_filename_sizes_sync_after_mft_redo_is_filtered(self):
        number, parent, names, contents, _, _ = self.filename_fixture(already_applied=True)
        self.assertIn("0 redo", self.replay())
        self.assert_filename_sizes(number, parent, names, contents)

    def test_filename_sizes_include_hardlinks_and_extent_records(self):
        for extent_type in (None, 0x80, 0x30):
            with self.subTest(extent_type=extent_type):
                self.setUp()
                number, parent, names, contents, _, _ = self.filename_fixture(
                    resident_index=True, hardlink=True, extent_type=extent_type, stale_index=True)
                self.replay()
                self.assert_filename_sizes(number, parent, names, contents)
                self.result(0, "-n")

    def test_filename_recovery_retries_after_target_and_restart_failures(self):
        for version, fault in ((0, "fail_clean"), (1, "fail_clean"),
                               (1, "fail_target_at"), (1, "torn_target_at")):
            with self.subTest(version=version, fault=fault):
                self.setUp()
                number, parent, names, contents, _, _ = self.filename_fixture(
                    major=2, version=version, stale_index=True)
                physical = next(self.image.spans(self.image.mft_runs,
                                number * self.image.record_size, self.image.record_size))[0]
                self.replay(1, **{fault: 1 if fault == "fail_clean" else physical})
                self.replay()
                self.assert_filename_sizes(number, parent, names, contents)

    def test_filename_read_errors_stop_before_writing(self):
        _, parent, _, _, _, _ = self.filename_fixture(stale_index=True)
        physical = next(self.image.spans(self.image.mft_runs,
                        parent * self.image.record_size, self.image.record_size))[0]
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay(1, fail_read_at=physical)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
        self.replay()

    def test_filename_preparation_is_read_only(self):
        self.filename_fixture(stale_index=True)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4, "-n")
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_missing_filename_link_is_deferred_to_the_scan(self):
        number, _, _, _, _, _ = self.filename_fixture()
        record = self.image.record(number)
        attr = self.image.attr(record, 0x30)
        value = attr + fixtures.u16(record, attr + 20)
        record[value + 66:value + 68] = "z".encode("utf-16le")
        self.image.write_record(number, record)
        self.assertIn("Filename recovery deferred", self.replay())

    def test_full_fsck_updates_mft_filename_when_index_sizes_match(self):
        number, parent, names, contents, prefix, _ = self.filename_fixture()
        self.result(1)
        self.assert_filename_sizes(number, parent, names, contents)
        read = fixtures.command("ntfscat", self.path, prefix + "owner.bin")
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(read.stdout, contents)
        self.result(0, "-n")

    def test_mft_replay_uses_current_mapping_for_redo_and_undo(self):
        for undo in (False, True):
            with self.subTest(undo=undo):
                self.setUp()
                vcn = 10 * self.image.record_size // self.image.cluster_size
                old, new, _ = self.move_mft_cluster(vcn)
                journal, cp, page, original = self.sizes_fixture(undo=undo, seed_undo=undo)
                raw = bytearray(self.image.read_stream(journal.runs, page * PAGE, PAGE))
                struct.pack_into("<Q", raw, 112 + 32, old)
                journal.write_page(page, raw)
                if not undo:
                    raw = bytearray(self.image.read_stream(journal.runs, cp * PAGE, PAGE))
                    struct.pack_into("<Q", raw, 112 + 8, journal.lsn(cp))
                    journal.write_page(cp, raw)
                old_cluster = self.image.read(old * self.image.cluster_size, self.image.cluster_size)
                if undo:
                    self.replay(1, fail_clean=1)
                self.replay()
                self.assert_sizes(original)
                self.assertEqual(self.image.read(old * self.image.cluster_size,
                                                 self.image.cluster_size), old_cluster)
                self.assertEqual(fixtures.Image(self.path).mft_runs[1][1], new)

    def test_mft_mapping_changes_are_available_to_later_records_and_retries(self):
        for fault, historical in (("fail_target_at", False), ("fail_clean", False),
                                  ("fail_target_at", True), ("fail_clean", True)):
            with self.subTest(fault=fault, historical=historical):
                self.setUp()
                zero = self.image.record(0)
                a0 = self.image.attr(zero)
                mp = fixtures.u16(zero, a0 + 32)
                record = self.image.record(10)
                offset = self.image.attr(record)
                original = bytes(record[offset + 40:offset + 64])
                vcn, within = divmod(10 * self.image.record_size, self.image.cluster_size)
                old, new, pairs = self.move_mft_cluster(vcn, install=False)
                damaged = bytearray(record)
                struct.pack_into("<QQ", damaged, offset + 48, 4096, 4096)
                self.image.write(new * self.image.cluster_size + within,
                                 protect(damaged, fixtures.u16(damaged, 4)))
                journal = Journal(self.image)
                first = journal.log(9, data=pairs, lcns=[self.image.mft_runs[0][1]],
                                    record_off=a0, attr_off=mp, transaction=64)
                commit = journal.log(0x1a, attr=0, transaction=64)
                small = struct.pack("<QQQ", fixtures.u64(record, offset + 40), 8192, 8192)
                second = journal.log(0xb, 0xb, data=small, undo_data=original,
                                     lcns=[old], record_off=offset,
                                     cluster_off=within // 512, vcn=vcn)
                actions = [first, commit, second]
                if historical:
                    previous = journal.log(0xb, data=struct.pack("<QQQ",
                                           fixtures.u64(record, offset + 40), 16384, 16384),
                                           lcns=[old], vcn=vcn, record_off=offset,
                                           cluster_off=within // 512, transaction=64)
                    actions.insert(0, previous)
                journal.emit(actions, target_vcn=0,
                             target_lcns=[self.image.mft_runs[0][1]])
                old_cluster = self.image.read(old * self.image.cluster_size, self.image.cluster_size)
                point = self.image.mft_offset if fault == "fail_target_at" else 1
                self.replay(1, **{fault: point})
                # The dirty checkpoint may be durable before MFT0 reaches its new mapping.
                self.replay()
                self.assert_sizes(original)
                self.assertEqual(fixtures.Image(self.path).mft_runs[1][1], new)
                if historical:
                    old_record = self.image.unprotect(self.image.read(
                        old * self.image.cluster_size + within, self.image.record_size))
                    self.assertEqual(fixtures.u64(old_record, offset + 48), 16384)
                else:
                    self.assertEqual(self.image.read(old * self.image.cluster_size,
                                                     self.image.cluster_size), old_cluster)

    def test_historical_mft_prefix_keeps_later_records_accessible(self):
        zero = self.image.record(0)
        a0 = self.image.attr(zero)
        mp = fixtures.u16(zero, a0 + 32)
        _, base, count = self.image.mft_runs[0]
        prefix = fixtures.RepairTests.mapping_pairs([(0, base, 2)])
        whole = fixtures.RepairTests.mapping_pairs([(0, base, count)])
        record = self.image.record(10)
        offset = self.image.attr(record)
        original = bytes(record[offset + 40:offset + 64])
        vcn, within = divmod(10 * self.image.record_size, self.image.cluster_size)
        journal = Journal(self.image)
        actions = [journal.log(9, data=prefix, lcns=[base], record_off=a0, attr_off=mp),
                   journal.log(0xb, data=original, lcns=[base + vcn], vcn=vcn,
                               record_off=offset, cluster_off=within // 512),
                   journal.log(9, data=whole, lcns=[base], record_off=a0, attr_off=mp)]
        journal.emit(actions, target_vcn=0, target_lcns=[base])
        struct.pack_into("<QQ", record, offset + 48, 4096, 4096)
        self.image.write_record(10, record)
        self.replay()
        self.assert_sizes(original)
        self.assertEqual(fixtures.Image(self.path).mft_runs, [(0, base, count)])

    def test_invalid_final_mft_stops_before_writing(self):
        for kind in ("size_order", "unaligned", "unmapped", "missing_data"):
            with self.subTest(kind=kind):
                self.setUp()
                record = self.image.record(0)
                offset = self.image.attr(record)
                alloc, data, valid = struct.unpack_from("<QQQ", record, offset + 40)
                new_alloc = {"size_order": alloc - self.image.cluster_size,
                             "unaligned": alloc - 1,
                             "unmapped": alloc + self.image.cluster_size}.get(kind, alloc)
                journal = Journal(self.image)
                action = journal.log(6 if kind == "missing_data" else 0xb,
                                     data=b"" if kind == "missing_data" else
                                     struct.pack("<QQQ", new_alloc, valid, data),
                                     lcns=[self.image.mft_runs[0][1]], record_off=offset)
                journal.emit([action], target_vcn=0, target_lcns=[self.image.mft_runs[0][1]])
                before = hashlib.sha256(self.path.read_bytes()).digest()
                self.assertIn("checking the recovered MFT", self.replay(1))
                self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_final_mft_validation_runs_after_undo(self):
        record = self.image.record(0)
        offset = self.image.attr(record)
        alloc, data, valid = struct.unpack_from("<QQQ", record, offset + 40)
        journal = Journal(self.image)
        action = journal.log(0xb, 0xb,
                             data=struct.pack("<QQQ", alloc - self.image.cluster_size, valid, data),
                             undo_data=struct.pack("<QQQ", alloc, valid, data),
                             lcns=[self.image.mft_runs[0][1]], record_off=offset)
        journal.emit([action], target_vcn=0, target_lcns=[self.image.mft_runs[0][1]])
        self.replay(1, fail_clean=1)
        self.replay()
        actual = fixtures.Image(self.path).record(0)
        self.assertEqual(struct.unpack_from("<QQQ", actual, offset + 40), (alloc, data, valid))

    def test_dead_dirty_pages_do_not_pin_discarded_history(self):
        for late_delete in (False, True):
            for version in (0, 1):
                with self.subTest(late_delete=late_delete, version=version):
                    self.setUp()
                    journal = Journal(self.image, checkpoint_version=version)
                    action = journal.log(8, data=b"LIVE", lcns=[5001], vcn=1)
                    cp, _ = journal.emit([action], target_vcn=1, target_lcns=[5001])
                    obsolete = journal.lsn(journal.size // PAGE - 1, sequence=0)
                    entries = []
                    for vcn, lsn, lcn in ((0, obsolete, 5000 if late_delete else 0),
                                          (1, journal.lsn(journal.first), 5001)):
                        entry = struct.pack("<IIII", 0xffffffff, 24, 4096, 1)
                        if not version:
                            entry += bytes(4)
                        entry += struct.pack("<QQQ", vcn, lsn, lcn)
                        entries.append(entry)
                    table = struct.pack("<6H3I", len(entries[0]), 2, 2, 0, 0, 0, 0, 0, 0)
                    table += b"".join(entries)
                    journal.record(journal.first + 1, journal.log(0x1f, attr=0, data=table))
                    raw = bytearray(self.image.read_stream(journal.runs, cp * PAGE, PAGE))
                    struct.pack_into("<I", raw, 112 + 56, len(table))
                    if late_delete:
                        struct.pack_into("<Q", raw, 112 + 8, journal.lsn(cp))
                    journal.write_page(cp, raw)
                    if late_delete:
                        journal.record(cp + 1, journal.log(0xa, attr=0,
                                       data=struct.pack("<QQ", 5000, 1)))
                        for copy in (0, 1):
                            journal.restart(copy, journal.lsn(cp + 1), journal.lsn(cp),
                                            journal.lsn(journal.first))
                    self.replay()
                    self.assertEqual(self.image.read(5001 * self.image.cluster_size, 4), b"LIVE")

    def test_delete_already_absent_attribute_is_noop(self):
        for undo in (False, True):
            with self.subTest(undo=undo):
                self.setUp()
                record = self.image.record(10)
                end = fixtures.u32(record, 24) - 8
                self.assertEqual(fixtures.u32(record, end), 0xffffffff)
                vcn, within = divmod(10 * self.image.record_size, self.image.cluster_size)
                lcn = self.image.mft_runs[0][1] + vcn
                before = self.image.read_stream(self.image.mft_runs, 10 * self.image.record_size,
                                                self.image.record_size)
                journal = Journal(self.image)
                action = journal.log(0 if undo else 6, 6 if undo else 0, lcns=[lcn],
                                     record_off=end, cluster_off=within // 512, vcn=vcn)
                journal.emit([action], target_vcn=vcn, target_lcns=[lcn])
                self.replay()
                self.assertEqual(self.image.read_stream(self.image.mft_runs,
                                 10 * self.image.record_size, self.image.record_size), before)

    def test_write_end_index_can_extend_past_old_used_length(self):
        for undo in (False, True):
            with self.subTest(undo=undo):
                self.setUp()
                block = bytearray(PAGE)
                struct.pack_into("<4sHHQQ4I", block, 0, b"INDX", 40, 9, 0, 0,
                                 40, 56, PAGE - 24, 0)
                struct.pack_into("<HHHH", block, 72, 32, 8, 0, 0)
                self.image.write(5000 * self.image.cluster_size, protect(block, 40))
                marker = struct.pack("<QHHHH", 0, 16, 0, 2, 0)
                journal = Journal(self.image)
                action = journal.log(0 if undo else 0x10, 0x10 if undo else 0,
                                     data=b"" if undo else marker,
                                     undo_data=marker if undo else b"", lcns=[5000], attr_off=96)
                journal.emit([action], target_vcn=0, target_lcns=[5000],
                             atype=0xa0, index_size=PAGE)
                self.replay()
                raw = self.image.read(5000 * self.image.cluster_size, PAGE)
                self.assertEqual(fixtures.u32(raw, 28), 88)
                self.assertEqual(raw[96:112], marker)
                self.replay()

    def test_write_end_index_stays_within_allocated_capacity(self):
        self.relative_undo_fixture()
        journal = Journal(self.image)
        marker = struct.pack("<QHHHH", 0, 16, 0, 2, 0)
        action = journal.log(0x10, data=marker, lcns=[5000], attr_off=PAGE - 8)
        journal.emit([action], target_vcn=0, target_lcns=[5000], atype=0xa0, index_size=PAGE)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.replay(1)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_new_index_logs_only_its_used_area(self):
        journal = Journal(self.image)
        block = bytearray(PAGE)
        struct.pack_into("<4sHHQQ4I", block, 0, b"INDX", 40, 9, 0, 0,
                         40, 56, PAGE - 24, 0)
        struct.pack_into("<HHHH", block, 64 + 8, 16, 0, 2, 0)
        lcn = 5000
        action = journal.log(8, data=block[:80], lcns=[lcn])
        journal.emit([action], target_vcn=0, target_lcns=[lcn],
                     atype=0xa0, index_size=PAGE)
        self.replay()
        raw = self.image.read(lcn * self.image.cluster_size, PAGE)
        self.assertEqual(raw[:4], b"INDX")
        for sector in range(1, 9):
            self.assertEqual(raw[sector * 512 - 2:sector * 512], raw[40:42])
        self.assertEqual(fixtures.u32(raw, 28), 56)

    def test_batch_commit_bitmap_excludes_completed_transaction(self):
        journal, cp, page, original = self.sizes_fixture()
        # Give the size update an undo value that must never be applied.
        old = struct.pack("<QQQ", 131072, 4096, 4096)
        vcn, remainder = divmod(10 * self.image.record_size, self.image.cluster_size)
        lcn = self.image.mft_runs[0][1] + vcn
        action = journal.log(0xb, 0xb, data=original, undo_data=old, lcns=[lcn],
                             record_off=self.image.attr(self.image.record(10)),
                             cluster_off=remainder // 512, vcn=vcn)
        slots = (65535 - 24 + 39) // 40
        bitmap = bytearray((slots + 7) // 8)
        bitmap[0] = 1
        magic = 0x54494d4d4f435442
        marker = struct.pack("<6QIHHHHI", magic, magic ^ ((1 << 64) - 1), 1,
                             (1 << 64) - 2, journal.lsn(page), journal.lsn(page),
                             1, 2, 1, len(bitmap), slots, 1) + bitmap
        fence = journal.log(0, attr=0, data=marker)
        journal.emit([action, fence], target_vcn=vcn, target_lcns=[lcn])
        self.assertIn("1 redo, 0 undo", self.replay())
        self.assert_sizes(original)

    def test_attribute_name_dump_allows_alignment_padding(self):
        journal, cp, _, original = self.sizes_fixture()
        names = struct.pack("<HH", 24, 8) + "$I30".encode("utf-16le") + bytes(6)
        payload, flags, undo_next, transaction = journal.log(0x1e, attr=0, data=names)
        payload += bytes((-len(payload)) % 8)
        journal.record(cp + 1, (payload, flags, undo_next, transaction))
        raw = bytearray(self.image.read_stream(journal.runs, cp * PAGE, PAGE))
        struct.pack_into("<Q", raw, 112 + 24, journal.lsn(cp + 1))
        struct.pack_into("<I", raw, 112 + 52, len(names))
        journal.write_page(cp, raw)
        for copy in (0, 1):
            journal.restart(copy, journal.lsn(cp + 1), journal.lsn(cp),
                            journal.lsn(journal.first))
        self.replay()
        self.assert_sizes(original)

    def test_circular_log_wrap_increments_sequence(self):
        journal, _, action_page, original = self.sizes_fixture()
        last = journal.size // PAGE - 1
        source_pages = [self.image.read_stream(journal.runs, p * PAGE, PAGE)
                        for p in (journal.first, journal.first + 1, action_page)]
        oldest = journal.lsn(last - 2)
        for i, raw in enumerate(source_pages):
            raw = bytearray(raw)
            lsn = journal.lsn(last - 2 + i)
            for offset in (8, 32, 64):
                struct.pack_into("<Q", raw, offset, lsn)
            if i == 1:
                struct.pack_into("<Q", raw, 112 + 40 + 24 + 24, oldest)
            journal.write_page(last - 2 + i, raw)
        checkpoint = journal.lsn(journal.first, sequence=2)
        cp = struct.pack("<II5Q4I", 1, 0, oldest, oldest, 0,
                         journal.lsn(last - 1), 0, 64, 0, 64, 0)
        journal.record(journal.first, (cp, 0, 0, 0), typ=2, lsn=checkpoint)
        for copy in (0, 1):
            journal.restart(copy, checkpoint, checkpoint, oldest)
        self.replay()
        self.assert_sizes(original)

    def multi_page_fixture(self):
        journal = Journal(self.image)
        payload = (bytes(range(251)) * 24)[:6000]
        lcns = [5000, 5001]
        self.image.write(5000 * self.image.cluster_size, b"\xa5" * 8192)
        action = journal.log(8, data=payload, lcns=lcns, record_off=77)
        # Reserve two action pages before the checkpoint, then replace them.
        journal.emit([journal.log(0), journal.log(0)], target_vcn=0, target_lcns=lcns)
        journal.two_page_record(journal.first + 2, action)
        return journal, payload

    def test_multi_page_nonresident_redo(self):
        _, payload = self.multi_page_fixture()
        self.replay()
        actual = self.image.read(5000 * self.image.cluster_size, 8192)
        self.assertEqual(actual, b"\xa5" * 77 + payload + b"\xa5" * (8192 - 77 - len(payload)))

    def test_torn_multi_page_record_preserves_image(self):
        journal, _ = self.multi_page_fixture()
        continuation = journal.first + 3
        raw = bytearray(self.image.read_stream(journal.runs, continuation * PAGE, PAGE))
        raw[510] ^= 1
        journal.write_page(continuation, raw)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        self.result(4)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_fragmented_logfile_mapping(self):
        record = self.image.record(2)
        offset = self.image.attr(record)
        runs, size = self.image.data_stream(record)
        self.assertEqual(len(runs), 1)
        _, lcn, count = runs[0]
        # Put every RCRD page in a second, physically distant extent.
        remainder = self.image.read((lcn + 4) * self.image.cluster_size,
                                    (count - 4) * self.image.cluster_size)
        self.image.write(9000 * self.image.cluster_size, remainder)
        pairs = fixtures.RepairTests.mapping_pairs([(0, lcn, 4), (4, 9000, count - 4)])
        mp = fixtures.u16(record, offset + 32)
        header = record[offset:offset + mp]
        length = (mp + len(pairs) + 7) & ~7
        fixtures.RepairTests.resize_fixture_attr(record, offset, length)
        record[offset:offset + mp] = header
        struct.pack_into("<I", record, offset + 4, length)
        record[offset + mp:offset + mp + len(pairs)] = pairs
        self.image.write_record(2, record)
        raw = self.image.read_stream(self.image.mft_runs, 2 * self.image.record_size,
                                     self.image.record_size)
        self.image.write(self.image.mirror_offset + 2 * self.image.record_size, raw)
        _, _, _, original = self.sizes_fixture()
        self.replay()
        self.assert_sizes(original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=BUILD_DIR)
    options, remaining = parser.parse_known_args()
    BUILD_DIR = options.build_dir.resolve()
    unittest.main(argv=[str(Path(__file__)), *remaining])
