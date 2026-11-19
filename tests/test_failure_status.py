#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exit status for failures before, during and after the repair passes.

An operational failure (open, read, allocation or write) exits 8 and prints
neither the errors-left summary nor the clean line. Damage that a check
recorded and left exits 4 through the common summary, with the dirty flag kept.

Each case works on its own regular-file image under --temp-dir. The allocation
shim is process-wide by design: once armed, it fails the next allocation of the
ntfsck process, whatever it is for.

python3 tests/test_failure_status.py --build-dir . --temp-dir DIR [--corpus DIR]

--corpus is the created_manually directory of the corrupted-image corpus.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest

BUILD_DIR = Path(__file__).resolve().parents[1]
TEMP_DIR = None
CORPUS = None

VOLUME_RECORD = 3           # $Volume
VOLUME_INFORMATION = 0x70   # unnamed, resident
FLAGS_OFFSET = 10           # reserved (8) + major (1) + minor (1)
VOLUME_IS_DIRTY = 0x0001
IMAGE_SIZE = 64 * 1024 * 1024
CLEAN = "Clean, No errors found or left"
SUMMARY = re.compile(r"^\d+ errors left \(errors:\d+, fixed:\d+\)", re.M)

# Fails the first malloc/calloc after the repair passes start printing
# "Check system files". The shim writes its own marker, not library text.
ALLOC_SHIM = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);

static int armed, fired;

static int fail_next(void)
{
    if (!armed || fired)
        return 0;
    fired = 1;
    (void)!write(2, "ALLOC_FAULT\n", 12);
    errno = ENOMEM;
    return 1;
}

/* Ubuntu builds use _FORTIFY_SOURCE, so the log text goes through the _chk variants. */
static void arm_on(const char *format)
{
    if (!armed && format && strstr(format, "Check system files"))
        armed = 1;
}

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap)
{
    static int (*real)(FILE *, int, const char *, va_list);

    if (!real)
        real = (int (*)(FILE *, int, const char *, va_list))dlsym(RTLD_NEXT, "__vfprintf_chk");
    arm_on(format);
    return real(stream, flag, format, ap);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
    va_list ap;
    int n;

    va_start(ap, format);
    n = __vfprintf_chk(stream, flag, format, ap);
    va_end(ap);
    return n;
}

void *malloc(size_t n)
{
    return fail_next() ? NULL : __libc_malloc(n);
}

void *calloc(size_t n, size_t m)
{
    return fail_next() ? NULL : __libc_calloc(n, m);
}
'''


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(command, env=None):
    p = subprocess.run([str(x) for x in command], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env, timeout=120)
    return p.returncode, p.stdout.decode(errors="replace")


def geometry(image):
    """Return (sector, cluster, record, MFT offset, MFTMirr offset) of an NTFS image."""
    with image.open("rb") as f:
        boot = f.read(512)
    require(boot[3:11] == b"NTFS    ", "missing NTFS signature")
    sector = struct.unpack_from("<H", boot, 11)[0]
    cluster = sector * boot[13]
    code = struct.unpack_from("<b", boot, 64)[0]
    record = 1 << -code if code < 0 else code * cluster
    mft = struct.unpack_from("<Q", boot, 48)[0] * cluster
    mirror = struct.unpack_from("<Q", boot, 56)[0] * cluster
    return sector, cluster, record, mft, mirror


def flag_offsets(image):
    """Absolute file offsets of the $Volume flags, one per MFT copy of record 3."""
    sector, _, size, mft, mirror = geometry(image)
    found = []
    for start in (mft, mirror):
        base = start + VOLUME_RECORD * size
        with image.open("rb") as f:
            f.seek(base)
            raw = f.read(size)
        require(raw[:4] == b"FILE", "missing $Volume FILE record")
        usa, count = struct.unpack_from("<HH", raw, 4)
        require(count == size // sector + 1 and usa + count * 2 <= size,
                "invalid update sequence bounds")
        rec = bytearray(raw)
        for i in range(1, count):
            tail = i * sector - 2
            require(raw[tail:tail + 2] == raw[usa:usa + 2], "bad update sequence tail")
            rec[tail:tail + 2] = raw[usa + 2 * i:usa + 2 * i + 2]
        pos = struct.unpack_from("<H", rec, 20)[0]
        used = struct.unpack_from("<I", rec, 24)[0]
        require(48 <= pos < used <= size, "invalid attribute bounds")
        while pos + 24 <= used:
            kind, length = struct.unpack_from("<II", rec, pos)
            if kind == 0xffffffff:
                break
            require(24 <= length <= used - pos, "bad attribute length")
            if kind == VOLUME_INFORMATION:
                require(rec[pos + 8] == 0, "nonresident volume information")
                value = struct.unpack_from("<H", rec, pos + 20)[0]
                require(24 <= value <= length - 12, "bad volume value bounds")
                at = pos + value + FLAGS_OFFSET
                require((at % sector) not in (sector - 2, sector - 1),
                        "flags field sits on a sector tail")
                found.append(base + at)
                break
            pos += length
        else:
            raise AssertionError("missing volume information")
    require(len(found) == 2, "missing volume flags")
    return found


def volume_flags(image):
    result = []
    with image.open("rb") as f:
        for at in flag_offsets(image):
            f.seek(at)
            result.append(struct.unpack("<H", f.read(2))[0])
    return result


def set_dirty(image):
    with image.open("r+b") as f:
        for at in flag_offsets(image):
            f.seek(at)
            (value,) = struct.unpack("<H", f.read(2))
            f.seek(at)
            f.write(struct.pack("<H", value | VOLUME_IS_DIRTY))


def damage_record(image, number):
    """Overwrite record `number` of the primary MFT with a bad signature."""
    _, _, record, mft, _ = geometry(image)
    with image.open("r+b") as f:
        f.seek(mft + number * record)
        f.write(b"FAIL")


def assert_operational(test, out):
    test.assertNotIn("errors left", out, "errors-left summary for an operational failure:\n" + out)
    test.assertNotIn(CLEAN, out, "clean line for an operational failure:\n" + out)


class FailureStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require(TEMP_DIR is not None, "--temp-dir is required")
        require((BUILD_DIR / "src/ntfsck").is_file(), "no ntfsck in " + str(BUILD_DIR))
        require((BUILD_DIR / "src/mkntfs").is_file(), "no mkntfs in " + str(BUILD_DIR))
        cls.workspace = tempfile.TemporaryDirectory(prefix="failure-status-", dir=TEMP_DIR)
        cls.directory = Path(cls.workspace.name)
        cls.pristine = cls.directory / "pristine.img"
        with cls.pristine.open("wb") as f:
            f.truncate(IMAGE_SIZE)
        rc, out = run([BUILD_DIR / "src/mkntfs", "-F", "-Q", "-s", "512", cls.pristine])
        require(rc == 0, "mkntfs failed:\n" + out)
        require(volume_flags(cls.pristine) == [0, 0], "fresh fixture is not clean")

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def clone(self, name):
        image = self.directory / name
        rc, out = run(["cp", "--sparse=always", self.pristine, image])
        require(rc == 0, out)
        return image

    def build_shim(self, source, name):
        c = self.directory / (name + ".c")
        so = self.directory / (name + ".so")
        c.write_text(source)
        rc, out = run(["cc", "-shared", "-fPIC", "-O2", "-U_FORTIFY_SOURCE", "-Wall", "-Wextra",
                       "-Werror", "-o", so, c, "-ldl"])
        require(rc == 0, "shim compilation failed:\n" + out)
        return so

    def corpus_image(self, name):
        require(CORPUS is not None, "--corpus is required for corpus cases")
        archive = CORPUS / name / "ntfs.img.tar.xz"
        require(archive.is_file(), "missing corpus archive: " + str(archive))
        target = self.directory / name
        target.mkdir()
        with tarfile.open(archive, "r:xz") as tar:
            members = [m for m in tar.getmembers() if m.isreg() and m.name.endswith(".img")]
            require(len(members) == 1, "expected one .img member in " + str(archive))
            kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extract(members[0], path=target, **kwargs)
        image = target / "case.img"
        shutil.move(str(target / members[0].name), image)
        return image

    def ntfsck(self, *args, env=None):
        return run([BUILD_DIR / "src/ntfsck", *args], env=env)

    # Operational failures: exit 8, no summary, no clean line.

    def test_permission_denied_with_n_is_operational(self):
        require(os.geteuid() != 0, "run as a normal user: root ignores mode 0000")
        image = self.clone("perm-n.img")
        image.chmod(0)
        try:
            rc, out = self.ntfsck("-n", image)
        finally:
            image.chmod(0o600)
        self.assertEqual(rc, 8, out)
        assert_operational(self, out)

    def test_permission_denied_with_forced_repair_is_operational(self):
        require(os.geteuid() != 0, "run as a normal user: root ignores mode 0000")
        image = self.clone("perm-af.img")
        image.chmod(0)
        try:
            rc, out = self.ntfsck("-a", "-f", image)
        finally:
            image.chmod(0o600)
        self.assertEqual(rc, 8, out)
        assert_operational(self, out)

    def test_failed_allocation_in_repair_passes_is_operational(self):
        image = self.clone("alloc.img")
        set_dirty(image)
        so = self.build_shim(ALLOC_SHIM, "alloc")
        env = dict(os.environ, LC_ALL="C", LD_PRELOAD=str(so))
        rc, out = self.ntfsck("-y", image, env=env)
        self.assertIn("ALLOC_FAULT", out, "allocation fault was not reached:\n" + out)
        self.assertEqual(rc, 8, out)
        assert_operational(self, out)
        self.assertEqual(volume_flags(image), [VOLUME_IS_DIRTY] * 2,
                         "dirty flag was cleared after an incomplete check")

    def test_missing_image_is_operational(self):
        image = self.directory / "no-such-image.img"
        for mode in ("-n", "-a"):
            rc, out = self.ntfsck(mode, image)
            self.assertEqual(rc, 8, mode + ":\n" + out)
            assert_operational(self, out)

    def test_image_locked_by_another_process_is_operational(self):
        image = self.clone("locked.img")
        holder = subprocess.Popen(
            ["python3", "-c",
             "import fcntl,sys,time\n"
             "f=open(sys.argv[1],'r+b'); fcntl.lockf(f, fcntl.LOCK_EX)\n"
             "print('locked', flush=True); time.sleep(30)", str(image)],
            stdout=subprocess.PIPE, text=True)
        try:
            require(holder.stdout.readline().strip() == "locked", "lock holder did not start")
            for mode in ("-n", "-a"):
                rc, out = self.ntfsck(mode, image)
                self.assertEqual(rc, 8, mode + ":\n" + out)
                assert_operational(self, out)
        finally:
            holder.kill()
            holder.wait()
            holder.stdout.close()

    def test_repair_of_read_only_image_is_refused(self):
        require(os.geteuid() != 0, "run as a normal user: root ignores mode 0444")
        image = self.clone("readonly.img")
        set_dirty(image)
        before = image.read_bytes()
        image.chmod(0o444)
        try:
            rc, out = self.ntfsck("-a", image)
        finally:
            image.chmod(0o600)
        self.assertEqual(rc, 8, out)
        assert_operational(self, out)
        self.assertNotIn("fixed:1", out, out)
        self.assertEqual(image.read_bytes(), before, "read-only image changed")

    # Damage that is recorded and left: exit 4 through the summary.

    def test_zero_link_count_of_mft_is_left_with_n_and_repaired_with_a(self):
        image = self.corpus_image("mft_file_bad_link_count")
        rc, out = self.ntfsck("-n", image)
        self.assertEqual(rc, 4, out)
        self.assertIsNotNone(SUMMARY.search(out), "no errors-left summary:\n" + out)
        self.assertNotIn(CLEAN, out, out)
        rc, out = self.ntfsck("-a", image)
        self.assertEqual(rc, 1, out)
        rc, out = self.ntfsck("-n", image)
        self.assertEqual(rc, 0, "recheck after the repair:\n" + out)

    def test_damaged_boot_sector_with_n_reports_errors_left(self):
        image = self.corpus_image("bs_total_sectors")
        rc, out = self.ntfsck("-n", image)
        self.assertEqual(rc, 4, out)
        self.assertIsNotNone(SUMMARY.search(out), "no errors-left summary:\n" + out)
        self.assertNotIn(CLEAN, out, out)

    def test_preserved_journal_with_n_reports_errors_left(self):
        image = self.clone("journal-n.img")
        damage_record(image, 2)
        rc, out = self.ntfsck("-n", image)
        self.assertIn("Journal preserved", out, "journal scenario was not reached:\n" + out)
        self.assertEqual(rc, 4, out)
        self.assertIsNotNone(SUMMARY.search(out), "no errors-left summary:\n" + out)
        self.assertNotIn(CLEAN, out, out)

    def test_preserved_journal_with_forced_repair_reports_errors_left(self):
        image = self.clone("journal-af.img")
        damage_record(image, 2)
        rc, out = self.ntfsck("-a", "-f", image)
        self.assertIn("Journal preserved", out, "journal scenario was not reached:\n" + out)
        self.assertEqual(rc, 4, out)
        self.assertIsNotNone(SUMMARY.search(out), "no errors-left summary:\n" + out)
        self.assertNotIn(CLEAN, out, out)


def main():
    global BUILD_DIR, TEMP_DIR, CORPUS
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", type=Path, default=BUILD_DIR)
    parser.add_argument("--temp-dir", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=None)
    options, remaining = parser.parse_known_args()
    BUILD_DIR = options.build_dir.resolve()
    TEMP_DIR = options.temp_dir
    CORPUS = options.corpus.resolve() if options.corpus else None
    unittest.main(argv=[str(Path(__file__)), *remaining], verbosity=2)


if __name__ == "__main__":
    main()
