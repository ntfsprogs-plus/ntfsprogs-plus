#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""End-to-end $Secure descriptor-layout regression tests (Python stdlib only).

Run after building on Linux; see README.md for invocation. An out-of-tree
build root (containing src/mkntfs and src/ntfsck), or the binary directory
itself, is accepted. Add --expect-unsupported with an old build to demonstrate
the layout-check gap.

All images are newly formatted 64 MiB regular files in TemporaryDirectory;
--temp-dir selects its parent. No existing image, device, mount, privilege,
network access, or third-party Python package is used. Read-only cases invoke
ntfsck -n and verify a whole-image SHA-256 before and after, even on failure.
An unsupported baseline must accept ALL malformed fixtures with exit status 0;
the default requires exit status 4 and the exact new layout diagnostic.
The default also checks three ntfsck -a repair-safety cases: an invalid primary
descriptor (layout, revision, or hash) must not overwrite a valid backup. Each
repair case starts from a separate pristine-image copy; these cases are skipped
in --expect-unsupported mode, which only demonstrates the layout-check gap.
A positive repair control checks that a valid primary still repairs its backup.

This covers generic descriptor/SID/ACL/ACE framing, not ACE-type-specific
semantics or Windows behavior. Layout offsets follow include/layout.h and the
fresh fixture emitted by src/sd.c:init_secure_sds; the hash follows
src/ntfsck.c:ntfsck_security_hash. Unexpected fixture formats fail closed.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile


IMAGE_SIZE = 64 * 1024 * 1024
SDS_BACKUP = 0x40000
SDS_HEADER_SIZE = 20
SD_HEADER_SIZE = 20
DIAGNOSTIC = "$Secure $SDS: descriptor structure invalid at offset 0"
MASK32 = 0xffffffff


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def put16(data, offset, value):
    struct.pack_into("<H", data, offset, value)


def put32(data, offset, value):
    struct.pack_into("<I", data, offset, value)


def rol3(value):
    return ((value << 3) | (value >> 29)) & MASK32


def security_hash(descriptor):
    value = 0
    # Match ntfsck: consume complete little-endian DWORDs only.
    for offset in range(0, len(descriptor) & ~3, 4):
        value = (rol3(value) + u32(descriptor, offset)) & MASK32
    return value


def preserve_hash(descriptor, original_hash):
    require(len(descriptor) % 4 == 0, "fixture descriptor is not DWORD-sized")
    # The fixture's final DWORD is a SID subauthority (asserted below), not a
    # length/count/offset/header field. Arbitrary RID values preserve SID layout.
    # Solve the last step h = rol32(prefix_hash, 3) + last_dword mod 2^32.
    # Thus $SDS's stored hash and every $SII/$SDH entry remain unchanged. Both
    # $SDS copies receive identical bytes. A matching hash is NOT proof of valid
    # layout: these cases must be caught by structural validation, not hashing.
    prefix_hash = security_hash(descriptor[:-4])
    put32(descriptor, len(descriptor) - 4,
          (original_hash - rol3(prefix_hash)) & MASK32)
    require(security_hash(descriptor) == original_hash, "hash compensation failed")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command, timeout):
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run([str(arg) for arg in command],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, env=env, check=False)
    return result.returncode, result.stdout.decode("utf-8", errors="replace")


class FreshImage:
    """Read-only parser for a fresh mkntfs image, never an arbitrary volume."""

    def __init__(self, path):
        self.path = path
        require(stat.S_ISREG(path.lstat().st_mode), "image is not a regular file")
        self.size = path.stat().st_size
        require(self.size == IMAGE_SIZE, "unexpected image size")
        boot = self.read(0, 512)
        require(boot[3:11] == b"NTFS    " and boot[510:512] == b"\x55\xaa",
                "not an NTFS boot sector")
        self.sector_size = u16(boot, 11)
        sectors_per_cluster = boot[13]
        require(self.sector_size in (512, 1024, 2048, 4096), "invalid sector size")
        require(0 < sectors_per_cluster <= 128 and
                sectors_per_cluster & (sectors_per_cluster - 1) == 0,
                "invalid sectors per cluster")
        self.cluster_size = self.sector_size * sectors_per_cluster
        sectors = u64(boot, 40)
        require(0 < sectors * self.sector_size <= self.size,
                "volume length exceeds image")
        self.volume_size = sectors * self.sector_size
        self.mft_offset = u64(boot, 48) * self.cluster_size
        record_code = struct.unpack_from("<b", boot, 64)[0]
        require(-16 <= record_code < 0 or 0 < record_code <= 64,
                "invalid MFT record size code")
        self.record_size = ((1 << -record_code) if record_code < 0 else
                            record_code * self.cluster_size)
        require(self.sector_size <= self.record_size <= 65536 and
                self.record_size % self.sector_size == 0, "invalid MFT record size")
        # Bootstrap the unnamed $MFT DATA runlist from record 0; do not assume
        # record 9 is contiguous with the boot sector's initial MFT extent.
        record0 = self.fixup(self.read(self.mft_offset, self.record_size))
        mft_runs, mft_size = self.data_stream(record0, "")
        require(mft_size >= 10 * self.record_size, "$MFT does not contain record 9")
        record9_raw = self.read_stream(mft_runs, mft_size,
                                       9 * self.record_size, self.record_size)
        record9 = self.fixup(record9_raw)
        self.sds_runs, self.sds_size = self.data_stream(record9, "$SDS")
        require(SDS_BACKUP + SDS_HEADER_SIZE <= self.sds_size <= IMAGE_SIZE,
                "missing or oversized $SDS backup")
        self.header = self.sds_read(0, SDS_HEADER_SIZE)
        self.original_hash, self.security_id, offset, length = struct.unpack(
            "<IIQI", self.header)
        require(offset == 0 and self.security_id == 0x100,
                "unexpected first live mkntfs security descriptor")
        require(SDS_HEADER_SIZE + SD_HEADER_SIZE <= length <= 4096 and
                length <= SDS_BACKUP and SDS_BACKUP + length <= self.sds_size,
                "invalid first $SDS entry length")
        primary = self.sds_read(0, length)
        backup = self.sds_read(SDS_BACKUP, length)
        require(primary == backup, "fresh $SDS primary/backup differ")
        self.descriptor = primary[SDS_HEADER_SIZE:]
        sd = self.descriptor
        require(len(sd) % 4 == 0 and sd[0] == 1 and u16(sd, 2) == 0x8004,
                "unexpected fresh descriptor header")
        self.owner, self.group, sacl, self.dacl = struct.unpack_from("<IIII", sd, 4)
        require(sacl == 0 and self.dacl == SD_HEADER_SIZE,
                "unexpected fresh ACL placement")
        require(self.dacl + 8 <= len(sd), "fresh ACL header is truncated")
        self.acl_size = u16(sd, self.dacl + 2)
        require(u16(sd, self.dacl + 4) == 2 and self.acl_size >= 8 and
                self.dacl + self.acl_size == self.owner,
                "unexpected fresh ACL layout")
        for sid in (self.owner, self.group):
            require(SD_HEADER_SIZE <= sid <= len(sd) - 8 and sd[sid] == 1,
                    "invalid fresh owner/group SID")
            require(sd[sid + 1] == 2 and sid + 8 + 4 * sd[sid + 1] <= len(sd),
                    "unexpected fresh SID subauthority count")
        require(self.group + 8 + 4 * sd[self.group + 1] == len(sd),
                "final DWORD must be the last group SID subauthority")
        self.first_ace = self.dacl + 8
        self.first_ace_size = u16(sd, self.first_ace + 2)
        require(self.first_ace_size >= 4 and
                self.first_ace + self.first_ace_size + 4 <= self.dacl + self.acl_size,
                "unexpected fresh ACE framing")
        require(security_hash(sd) == self.original_hash, "fresh descriptor hash differs")

    def read(self, offset, length):
        require(0 <= offset <= self.size and 0 <= length <= self.size - offset,
                "image read out of bounds")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(length)
        require(len(data) == length, "short image read")
        return data

    def fixup(self, raw):
        require(raw[:4] == b"FILE", "missing MFT FILE signature")
        record = bytearray(raw)
        usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
        require(usa_count == len(record) // self.sector_size + 1 and
                8 <= usa_offset and usa_offset + 2 * usa_count <= len(record),
                "invalid MFT update sequence array")
        sequence = raw[usa_offset:usa_offset + 2]
        for sector in range(1, usa_count):
            tail = sector * self.sector_size - 2
            require(raw[tail:tail + 2] == sequence, "MFT update sequence mismatch")
            record[tail:tail + 2] = raw[usa_offset + 2 * sector:usa_offset + 2 * sector + 2]
        # Fixed-up records are used only for parsing; never write them back.
        return record

    def data_stream(self, record, wanted_name):
        used = u32(record, 24)
        offset = u16(record, 20)
        require(48 <= offset <= used <= len(record), "invalid MFT attribute bounds")
        while offset + 4 <= used:
            attr_type = u32(record, offset)
            if attr_type == 0xffffffff:
                break
            require(offset + 16 <= used, "truncated attribute header")
            length = u32(record, offset + 4)
            require(length >= 24 and length % 8 == 0 and length <= used - offset,
                    "invalid attribute length")
            attr = record[offset:offset + length]
            name_length, name_offset = attr[9], u16(attr, 10)
            require(not name_length or 16 <= name_offset <= length - 2 * name_length,
                    "attribute name out of bounds")
            name = bytes(attr[name_offset:name_offset + 2 * name_length]).decode("utf-16le")
            if attr_type == 0x80 and name == wanted_name:
                require(attr[8] == 1 and length >= 64, "expected nonresident DATA")
                require(u16(attr, 12) == 0 and u16(attr, 34) == 0,
                        "compressed/encrypted/sparse DATA not supported")
                lowest, highest = u64(attr, 16), u64(attr, 24)
                run_offset = u16(attr, 32)
                data_size = u64(attr, 48)
                require(lowest == 0 and 64 <= run_offset < length and
                        0 < data_size <= self.size, "invalid DATA extent")
                runs = self.runlist(attr, run_offset)
                require(runs[-1][0] + runs[-1][2] == highest + 1 and
                        data_size <= (highest + 1) * self.cluster_size,
                        "DATA extent/runlist disagreement")
                return runs, data_size
            offset += length
        raise AssertionError("nonresident DATA stream not found: " + repr(wanted_name))

    def runlist(self, attr, offset):
        runs = []
        vcn = lcn = 0
        while offset < len(attr):
            header = attr[offset]
            offset += 1
            if header == 0:
                require(bool(runs), "empty runlist")
                return runs
            count_size, delta_size = header & 15, header >> 4
            require(1 <= count_size <= 8 and 1 <= delta_size <= 8 and
                    offset + count_size + delta_size <= len(attr),
                    "invalid or sparse DATA run")
            count = int.from_bytes(attr[offset:offset + count_size], "little")
            offset += count_size
            delta = int.from_bytes(attr[offset:offset + delta_size], "little", signed=True)
            offset += delta_size
            lcn += delta
            require(count > 0 and lcn >= 0 and
                    (lcn + count) * self.cluster_size <= self.volume_size,
                    "DATA run outside volume")
            runs.append((vcn, lcn, count))
            vcn += count
        raise AssertionError("unterminated DATA runlist")

    def spans(self, runs, data_size, offset, length):
        require(0 <= offset <= data_size and 0 <= length <= data_size - offset,
                "stream access out of bounds")
        end = offset + length
        for vcn, lcn, count in runs:
            start = vcn * self.cluster_size
            run_end = start + count * self.cluster_size
            if start <= offset < run_end:
                size = min(end, run_end) - offset
                yield lcn * self.cluster_size + offset - start, size
                offset += size
                if offset == end:
                    return
        require(offset == end, "stream range not covered by runlist")

    def read_stream(self, runs, data_size, offset, length):
        return b"".join(self.read(physical, size) for physical, size in
                        self.spans(runs, data_size, offset, length))

    def sds_read(self, offset, length):
        return self.read_stream(self.sds_runs, self.sds_size, offset, length)

    def install(self, descriptor, backup=None):
        require(len(descriptor) == len(self.descriptor), "descriptor length changed")
        if backup is None:
            backup = descriptor
        require(len(backup) == len(descriptor), "backup descriptor length changed")
        with self.path.open("r+b") as stream:
            for base, body in ((0, descriptor), (SDS_BACKUP, backup)):
                entry = self.header + body
                consumed = 0
                for physical, size in self.spans(self.sds_runs, self.sds_size, base, len(entry)):
                    stream.seek(physical)
                    require(stream.write(entry[consumed:consumed + size]) == size,
                            "short image write")
                    consumed += size
        require(self.sds_read(0, len(entry)) == self.header + descriptor and
                self.sds_read(SDS_BACKUP, len(entry)) == self.header + backup,
                "$SDS primary/backup write verification failed")


def cases(fixture):
    """Each tuple is (name, invalid, (byte offset, struct format, value)...)."""
    dacl, owner, group = fixture.dacl, fixture.owner, fixture.group
    length = len(fixture.descriptor)
    ace = fixture.first_ace
    return [
        ("clean", False, []),
        ("absent-dacl", False, [(2, "H", 0x8000), (16, "I", 0)]),
        ("null-dacl", False, [(16, "I", 0)]),
        ("null-sacl", False, [(2, "H", 0x8014)]),
        ("absent-owner", False, [(4, "I", 0)]),
        ("absent-group", False, [(8, "I", 0)]),
        # Offsets of inactive ACLs are not interpreted, even if nonzero/bogus.
        ("inactive-dacl-offset", False, [(2, "H", 0x8000), (16, "I", length + 1)]),
        ("inactive-sacl-offset", False, [(12, "I", length + 1)]),
        # ACL free space is permitted after exactly ace_count framed entries.
        ("acl-free-space", False, [(dacl + 4, "H", 1)]),
        # Generic framing must not impose ACCESS_ALLOWED_ACE-specific rules.
        ("unknown-ace-type", False, [(ace, "B", 255)]),
        ("owner-inside-header", True, [(4, "I", 4)]),
        ("owner-misaligned", True, [(4, "I", owner + 1)]),
        ("owner-truncated-sid", True, [(4, "I", length - 4)]),
        ("owner-subauthority-overrun", True, [(owner + 1, "B", 255)]),
        ("group-inside-header", True, [(8, "I", 8)]),
        ("group-misaligned", True, [(8, "I", group + 1)]),
        ("group-truncated-sid", True, [(8, "I", length - 4)]),
        ("group-subauthority-overrun", True, [(group + 1, "B", 255)]),
        ("dacl-past-descriptor", True, [(16, "I", length + 4)]),
        ("dacl-inside-header", True, [(16, "I", 16)]),
        ("dacl-misaligned", True, [(16, "I", dacl + 1)]),
        ("dacl-truncated-header", True, [(16, "I", length - 4)]),
        # Change ACL.size, NOT the descriptor's dacl pointer or $SDS length.
        ("dacl-size-oversized", True, [(dacl + 2, "H", length - dacl + 4)]),
        ("dacl-size-undersized", True, [(dacl + 2, "H", 4)]),
        ("ace-count-overrun", True, [(dacl + 4, "H", 255)]),
        ("ace-size-undersized", True, [(ace + 2, "H", 2)]),
        ("ace-size-misaligned", True, [(ace + 2, "H", 5)]),
        ("ace-size-overrun", True, [(ace + 2, "H", fixture.acl_size)]),
        ("missing-self-relative", True, [(2, "H", 0x0004)]),
        ("sacl-past-descriptor", True, [(2, "H", 0x8014), (12, "I", length + 4)]),
        # Reuse the valid DACL bytes as SACL, disable DACL, then alter ACL.size.
        ("sacl-size-oversized", True, [(2, "H", 0x8010), (12, "I", dacl),
                                       (16, "I", 0), (dacl + 2, "H", length - dacl + 4)]),
        ("sacl-size-undersized", True, [(2, "H", 0x8010), (12, "I", dacl),
                                        (16, "I", 0), (dacl + 2, "H", 4)]),
    ]


def check_case(fixture, checker, timeout, name, invalid, changes, baseline):
    descriptor = bytearray(fixture.descriptor)
    for offset, fmt, value in changes:
        require(offset + struct.calcsize("<" + fmt) <= len(descriptor) - 4,
                name + ": mutation touches compensation DWORD")
        struct.pack_into("<" + fmt, descriptor, offset, value)
    if changes:
        preserve_hash(descriptor, fixture.original_hash)
    fixture.install(descriptor)
    before = sha256(fixture.path)
    try:
        code, output = run([checker, "-n", fixture.path], timeout)
    finally:
        require(sha256(fixture.path) == before, name + ": ntfsck -n changed image bytes")
    expected_code = 4 if invalid and not baseline else 0
    require(code == expected_code,
            "{}: expected exit {}, got {}\n{}".format(name, expected_code, code, output))
    # Progress text can precede a diagnostic on the same output line.
    hits = sum(line.endswith(DIAGNOSTIC) for line in output.splitlines())
    require(hits == (1 if invalid and not baseline else 0),
            name + ": unexpected layout diagnostic count\n" + output)
    # Reject collateral hash, mirror and index findings. The generic problem
    # explanation for layout corruption may also mention $SDS, so do not ban
    # all $Secure lines indiscriminately.
    for line in output.splitlines():
        lower = line.lower()
        collateral = (("hash" in lower and ("mismatch" in lower or "invalid" in lower)) or
                      "backup copy differs" in lower or "mirror mismatch" in lower or
                      (("$SII" in line or "$SDH" in line) and
                       any(word in lower for word in
                           ("mismatch", "missing", "no index entry", "does not match",
                            "corrupt", "invalid", "truncated", "disagree"))))
        require(not collateral, name + ": collateral hash/mirror/index finding\n" + output)
    # Corrupt fixtures are always written from the original descriptor; a clean
    # case must never inherit the preceding case's damage.
    require(fixture.sds_read(0, SDS_HEADER_SIZE) == fixture.header,
            name + ": original $SDS header changed")
    print("PASS " + name, flush=True)


def check_repair_safety(fixture, pristine, checker, timeout, kind):
    # Reset the entire regular-file image: -a may legitimately update unrelated
    # volume metadata. The assertion here is specifically about $SDS evidence.
    shutil.copyfile(pristine, fixture.path)
    descriptor = bytearray(fixture.descriptor)
    if kind == "layout":
        put32(descriptor, 4, 4)  # Owner SID illegally points into SD header.
        preserve_hash(descriptor, fixture.original_hash)
        expected = DIAGNOSTIC
    elif kind == "revision":
        descriptor[0] = 2
        preserve_hash(descriptor, fixture.original_hash)
        expected = "$Secure $SDS: descriptor at offset 0 is invalid"
    else:
        require(kind == "hash", "unknown repair-safety case")
        put32(descriptor, len(descriptor) - 4, u32(descriptor, len(descriptor) - 4) ^ 1)
        require(security_hash(descriptor) != fixture.original_hash,
                "repair-safety fixture should have mismatching hash")
        expected = "$Secure $SDS: hash mismatch at offset 0 (id=256)"
    fixture.install(descriptor, backup=fixture.descriptor)
    entry_size = SDS_HEADER_SIZE + len(descriptor)
    primary_before = fixture.sds_read(0, entry_size)
    backup_before = fixture.sds_read(SDS_BACKUP, entry_size)
    require(primary_before != backup_before, "repair fixture copies must differ")
    code, output = run([checker, "-a", fixture.path], timeout)
    name = "repair-preserves-backup-invalid-" + kind
    require(fixture.sds_read(SDS_BACKUP, entry_size) == backup_before,
            name + ": invalid primary overwrote valid backup\n" + output)
    require(fixture.sds_read(0, entry_size) == primary_before,
            name + ": checker unexpectedly rewrote invalid primary\n" + output)
    require(code == 4, name + ": expected uncorrected-error exit 4, got {}\n{}".format(code, output))
    require(any(line.endswith(expected) for line in output.splitlines()),
            name + ": missing primary diagnostic\n" + output)
    require(any(line.endswith("$Secure $SDS: backup copy differs at offset 0")
                for line in output.splitlines()),
            name + ": mirror mismatch must still be reported\n" + output)
    print("PASS " + name, flush=True)


def check_valid_primary_repair(fixture, pristine, checker, timeout):
    shutil.copyfile(pristine, fixture.path)
    backup = bytearray(fixture.descriptor)
    backup[-1] ^= 1
    fixture.install(fixture.descriptor, backup=backup)
    entry_size = SDS_HEADER_SIZE + len(backup)
    primary = fixture.sds_read(0, entry_size)
    code, output = run([checker, "-a", fixture.path], timeout)
    require(code == 1, "valid-primary mirror repair: expected exit 1\n" + output)
    require(fixture.sds_read(0, entry_size) == primary and
            fixture.sds_read(SDS_BACKUP, entry_size) == primary,
            "valid-primary mirror repair did not preserve/restore copies\n" + output)
    before = sha256(fixture.path)
    code, output = run([checker, "-n", fixture.path], timeout)
    require(code == 0, "repaired image does not recheck clean\n" + output)
    require(sha256(fixture.path) == before, "recheck changed repaired image")
    print("PASS valid-primary-repairs-backup", flush=True)


def binary(build_dir, name):
    for path in (build_dir / "src" / name, build_dir / name):
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    raise AssertionError("built executable not found: {} (looked in {} and its src/)".format(
        name, build_dir))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", type=Path,
                        default=Path(__file__).resolve().parents[1],
                        help="build root or directory containing mkntfs and ntfsck")
    parser.add_argument("--temp-dir", type=Path,
                        help="existing parent for temporary regular-file images")
    parser.add_argument("--timeout", type=int, default=60,
                        help="per-process timeout in seconds (1..300; default: 60)")
    parser.add_argument("--expect-unsupported", action="store_true",
                        help="require an old baseline to accept every malformed fixture")
    args = parser.parse_args()
    require(1 <= args.timeout <= 300, "timeout must be in 1..300 seconds")
    mkntfs = binary(args.build_dir, "mkntfs")
    checker = binary(args.build_dir, "ntfsck")
    with tempfile.TemporaryDirectory(prefix="ntfsck-secure-", dir=args.temp_dir) as directory:
        image = Path(directory) / "fresh.img"
        with image.open("xb") as stream:
            stream.truncate(IMAGE_SIZE)
        code, output = run([mkntfs, "-F", "-Q", "-s", "512", "-c", "4096",
                            "-p", "0", "-H", "255", "-S", "63", image], args.timeout)
        require(code == 0, "mkntfs failed (exit {}):\n{}".format(code, output))
        fixture = FreshImage(image)
        pristine = Path(directory) / "pristine.img"
        if not args.expect_unsupported:
            shutil.copyfile(image, pristine)
        all_cases = cases(fixture)
        require(len({case[0] for case in all_cases}) == len(all_cases), "duplicate case name")
        for name, invalid, changes in all_cases:
            check_case(fixture, checker, args.timeout, name, invalid, changes,
                       args.expect_unsupported)
        invalid_count = sum(case[1] for case in all_cases)
        repair_count = 0
        if not args.expect_unsupported:
            for kind in ("layout", "revision", "hash"):
                check_repair_safety(fixture, pristine, checker, args.timeout, kind)
                repair_count += 1
            check_valid_primary_repair(fixture, pristine, checker, args.timeout)
            repair_count += 1
        mode = "baseline accepts malformed layouts" if args.expect_unsupported else "layout validation"
        print("{} cases passed: {} valid and {} malformed read-only, {} repair-safety; "
              "{}; -n preserved every image".format(
                  len(all_cases) + repair_count, len(all_cases) - invalid_count,
                  invalid_count, repair_count, mode))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, UnicodeError, struct.error, subprocess.TimeoutExpired) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
