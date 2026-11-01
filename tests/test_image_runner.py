#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the external image runner without network access or mounts."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).resolve().with_name("test_all_images.sh")


class ImageRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ntfsck image runner ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.arguments = self.root / "arguments.jsonl"
        self.suite = self.root / "suite.sh"
        self.suite.write_text("""#!/bin/bash
set -eu
"${FSCK_PATH}ntfsck" -a "fixture with spaces.img"
"${FSCK_PATH}ntfsck" -n -v "fixture with spaces.img"
if [ "${NTFSCK_TEST_SUITE_EXIT:-0}" != 0 ]; then
    mkdir -p test_results
    echo 'fixture failure details' > test_results/manual_images_test_fixture.log
fi
exit "${NTFSCK_TEST_SUITE_EXIT:-0}"
""")
        self.suite.chmod(0o755)
        git = self.bin / "git"
        git.write_text("""#!/usr/bin/env python3
from pathlib import Path
import os
import shutil
import sys
args = sys.argv[1:]
if args[:1] == ['-C']:
    args = args[2:]
if args[0] == os.environ.get('NTFSCK_TEST_GIT_FAILURE'):
    sys.exit(73)
if args[0] == 'clone':
    destination = Path(args[-1])
    destination.mkdir()
    shutil.copy(os.environ['NTFSCK_TEST_SUITE'], destination / 'test_all.sh')
""")
        git.chmod(0o755)
        checker = self.bin / "checker"
        checker.write_text("""#!/usr/bin/env python3
import json
import os
import sys
with open(os.environ['NTFSCK_TEST_ARGUMENTS'], 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
sys.exit(int(os.environ.get('NTFSCK_TEST_CHECKER_EXIT', '0')))
""")
        checker.chmod(0o755)
        self.env = {**os.environ, "LC_ALL": "C", "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "NTFSCK_IMAGE_TEST_BINARY": str(checker), "NTFSCK_TEST_SUITE": str(self.suite),
                    "NTFSCK_TEST_ARGUMENTS": str(self.arguments)}

    def run_suite(self, *args, **environment):
        return subprocess.run(["bash", str(RUNNER), *args], cwd=self.root,
                              env={**self.env, **environment}, capture_output=True,
                              text=True, timeout=15)

    def assert_setup_failure(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.arguments.exists(), "checker ran after setup failed")

    def test_forces_repairs_and_keeps_read_only_arguments(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        repair, check = map(json.loads, self.arguments.read_text().splitlines())
        self.assertEqual(set(repair[:-1]), {"-a", "-f"})
        self.assertEqual(repair[-1], "fixture with spaces.img")
        self.assertEqual(check, ["-n", "-v", "fixture with spaces.img"])

    def test_clone_failure_is_reported(self):
        self.assert_setup_failure(self.run_suite(NTFSCK_TEST_GIT_FAILURE="clone"))

    def test_fetch_failure_is_reported(self):
        corpus = self.root / "ntfs_corrupted_images"
        corpus.mkdir()
        shutil.copy(self.suite, corpus / "test_all.sh")
        self.assert_setup_failure(self.run_suite(NTFSCK_TEST_GIT_FAILURE="fetch"))

    def test_checkout_failure_is_reported(self):
        for branch in ("main", "topic"):
            with self.subTest(branch=branch):
                self.assert_setup_failure(self.run_suite(branch, NTFSCK_TEST_GIT_FAILURE="checkout"))

    def test_rebase_failure_is_reported(self):
        self.assert_setup_failure(self.run_suite(NTFSCK_TEST_GIT_FAILURE="rebase"))

    def test_suite_failure_is_reported(self):
        result = self.run_suite(NTFSCK_TEST_SUITE_EXIT="17")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fixture failure details", result.stdout + result.stderr)

    def test_checker_failure_is_reported(self):
        result = self.run_suite(NTFSCK_TEST_CHECKER_EXIT="23")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.arguments.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
