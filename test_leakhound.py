#!/usr/bin/env python3
"""Tests for leakhound.py — stdlib unittest only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "leakhound.py")
sys.path.insert(0, HERE)
import leakhound  # noqa: E402

CANARY_AWS = "AKIA" + "CANARYTEST1234"[:16].ljust(16, "X")[:16]
CANARY_GH = "ghp_" + "Ab3dEf6hIjKlMnOpQrStUvWxYz0123456789"[:36]
CANARY_KEY = "-----BEGIN PRIVATE KEY-----"


def run_tool(*argv, cwd=None):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True, cwd=cwd)


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self._clean)

    def _clean(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, content, binary=False):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if binary else "w"
        with open(path, mode) as fh:
            fh.write(content)
        return path


class TestDetection(TreeCase):
    def test_aws_key_found_without_leaking_value(self):
        self.write("app.py", f'KEY = "{CANARY_AWS}"\n')
        r = run_tool(self.tmp)
        self.assertEqual(r.returncode, 1)
        self.assertIn("aws-access-key", r.stdout)
        self.assertNotIn(CANARY_AWS, r.stdout)
        self.assertNotIn(CANARY_AWS, r.stderr)

    def test_github_token_json_mode(self):
        self.write("cfg.txt", f"token={CANARY_GH}\n")
        r = run_tool(self.tmp, "--format", "json")
        data = json.loads(r.stdout)
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("github-token", rules)
        self.assertNotIn(CANARY_GH, r.stdout)

    def test_private_key_header(self):
        self.write("k.pem", CANARY_KEY + "\n")
        r = run_tool(self.tmp)
        self.assertEqual(r.returncode, 1)
        self.assertIn("private-key", r.stdout)
        self.assertNotIn("PRIVATE KEY-----", r.stdout.replace("private-key", ""))

    def test_clean_tree_exits_zero(self):
        self.write("hello.py", "print('hello world')\n")
        r = run_tool(self.tmp)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("finding", r.stdout)

    def test_binary_skipped(self):
        self.write("blob.bin", b"\x00\x01" + CANARY_AWS.encode(), binary=True)
        r = run_tool(self.tmp, "--format", "json")
        data = json.loads(r.stdout)
        self.assertEqual(data["findings"], [])
        self.assertTrue(any(s["reason"] == "binary" for s in data["skipped"]))

    def test_generic_assignment_diversity_gate(self):
        self.write("a.py", "token_type = 'address-list'\n")
        self.write("b.py", "api_key = 'X9kQ2mZ8pL4wR7tY3nB6'\n")
        r = run_tool(self.tmp, "--format", "json")
        data = json.loads(r.stdout)
        paths = {f["path"] for f in data["findings"]}
        self.assertIn("b.py", paths)

    def test_allowlist_by_fingerprint(self):
        self.write("app.py", f'KEY = "{CANARY_AWS}"\n')
        fp = leakhound.fingerprint(CANARY_AWS)
        allow = self.write("allow.txt", fp + "\n")
        r = run_tool(self.tmp, "--allow", allow)
        self.assertEqual(r.returncode, 0)

    def test_allowlist_by_path_rule(self):
        self.write("app.py", f'KEY = "{CANARY_AWS}"\n')
        allow = self.write("allow.txt", "app.py:aws-access-key\n")
        r = run_tool(self.tmp, "--allow", allow)
        self.assertEqual(r.returncode, 0)

    def test_deterministic_output(self):
        self.write("app.py", f'KEY = "{CANARY_AWS}"\nX = "{CANARY_GH}"\n')
        a = run_tool(self.tmp, "--format", "json")
        b = run_tool(self.tmp, "--format", "json")
        self.assertEqual(a.stdout, b.stdout)

    def test_missing_dir_is_usage_error(self):
        r = run_tool(os.path.join(self.tmp, "nope"))
        self.assertEqual(r.returncode, 2)

    def test_git_dir_skipped(self):
        self.write(".git/config", f'KEY = "{CANARY_AWS}"\n')
        r = run_tool(self.tmp)
        self.assertEqual(r.returncode, 0)

    def test_fingerprint_stable_and_short(self):
        fp = leakhound.fingerprint("some-value")
        self.assertEqual(len(fp), 12)
        self.assertEqual(fp, leakhound.fingerprint("some-value"))
        self.assertNotEqual(fp, leakhound.fingerprint("other-value"))


if __name__ == "__main__":
    unittest.main()
