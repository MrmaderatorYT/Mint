"""CLI contracts for the batch orchestrator; no Android SDK required."""
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import time
import unittest

RUNNER = Path(__file__).resolve().parents[2] / "tools" / "mint_batch.py"


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mint batch ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.tool = self.root / "fake headless"
        self.tool.write_text(f"#!{sys.executable}\n" + '''import json, sys, time
from pathlib import Path
name = Path(sys.argv[1]).name
if name == 'slow':
    print('partial', flush=True)
    time.sleep(30)
if name == 'crashslow':
    time.sleep(2)
if name == 'flaky' and not Path(sys.argv[1]).with_name('ready').exists():
    sys.exit(1)
if name == 'largeerr':
    sys.stderr.write('e' * 100000)
    sys.stderr.flush()
if name == 'large':
    sys.stdout.write('x' * 100000)
    sys.stdout.flush()
if name == 'bad':
    print('invalid input', file=sys.stderr)
    sys.exit(1)
print(json.dumps({'input': sys.argv[1], 'args': sys.argv[2:]}))
''')
        self.tool.chmod(0o700)
        self.output = self.root / "results"

    def run_batch(self, *inputs, options=()):
        return subprocess.run([sys.executable, str(RUNNER),
                               *[str(self.root / name) for name in inputs],
                               "--tool", str(self.tool), "--output", str(self.output),
                               *options], capture_output=True, text=True, timeout=15)

    def report(self):
        return json.loads((self.output / "report.json").read_text())["results"]

    def test_failure_isolated_ordered_and_shell_characters_literal(self):
        result = self.run_batch("first", "bad", "$(touch injected); file", "first",
                                options=("--jobs", "2"))
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = self.report()
        self.assertEqual([r["status"] for r in rows], ["ok", "failed", "ok", "ok"])
        self.assertEqual(len({r["output"] for r in rows}), 4)
        self.assertTrue(rows[1]["output"].endswith(".partial"))
        self.assertIn("invalid input", (self.output / rows[1]["stderr"]).read_text())
        data = json.loads((self.output / rows[2]["output"]).read_text())
        self.assertEqual(data["input"], str((self.root / "$(touch injected); file").resolve()))

    def test_timeout_preserves_partial_and_continues(self):
        result = self.run_batch("slow", "next", options=("--timeout", "2"))
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = self.report()
        self.assertEqual([r["status"] for r in rows], ["timeout", "ok"])
        self.assertEqual((self.output / rows[0]["output"]).read_text().strip(), "partial")

    def test_output_limit_preserves_bounded_partial(self):
        result = self.run_batch("large", options=("--max-output-bytes", "1024"))
        self.assertEqual(result.returncode, 1, result.stderr)
        row = self.report()[0]
        self.assertEqual(row["status"], "output_limit")
        self.assertTrue(row["output"].endswith(".partial"))
        self.assertEqual((self.output / row["output"]).stat().st_size, 1024)

    def test_stderr_limit(self):
        result = self.run_batch("largeerr", options=("--max-output-bytes", "2048"))
        self.assertEqual(result.returncode, 1, result.stderr)
        row = self.report()[0]
        self.assertEqual(row["status"], "output_limit")
        self.assertEqual((self.output / row["stderr"]).stat().st_size, 2048)

    def test_mapping_and_output_reuse_guard(self):
        result = self.run_batch("raw file", options=("--raw", "aarch64", "0x1000", "0x1000"))
        self.assertEqual(result.returncode, 0, result.stderr)
        before = (self.output / "report.json").read_bytes()
        row = self.report()[0]
        data = json.loads((self.output / row["output"]).read_text())
        self.assertEqual(data["args"], ["--raw", "aarch64", "0x1000", "0x1000", "json"])
        self.assertEqual(self.run_batch("other").returncode, 2)
        self.assertEqual((self.output / "report.json").read_bytes(), before)

    def test_raw_big_endian_is_forwarded(self):
        result = self.run_batch("raw file", options=("--raw", "aarch64", "0x1000", "0x1000", "--raw-endian", "big"))
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.report()[0]
        data = json.loads((self.output / row["output"]).read_text())
        self.assertEqual(data["args"], ["--raw", "aarch64", "0x1000", "0x1000", "--raw-endian", "big", "json"])

    def test_address_command_forwarding_and_resume_identity(self):
        (self.root / "first").write_text("input")
        options = ("--command", "ir", "--address", "18446744073709551615")
        result = self.run_batch("first", options=options)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.report()[0]
        data = json.loads((self.output / row["output"]).read_text())
        self.assertEqual(data["args"], ["ir", "0xffffffffffffffff"])
        self.assertEqual(json.loads((self.output / "report.json").read_text())["address"], "0xffffffffffffffff")
        same = self.run_batch("first", options=("--resume", "--command", "ir", "--address", "0xFFFFFFFFFFFFFFFF"))
        self.assertEqual(same.returncode, 0, same.stderr)
        self.assertEqual(self.report()[0]["output"], row["output"])
        changed = self.run_batch("first", options=("--resume", "--command", "ir", "--address", "0x1"))
        self.assertEqual(changed.returncode, 2)
        self.assertEqual(self.report()[0]["output"], row["output"])

    def test_command_address_validation(self):
        for options in (("--command", "ir"), ("--command", "json", "--address", "1"),
                        ("--command", "cfg", "--address", "-1"), ("--command", "cfg", "--address", "0x10000000000000000"),
                        ("--command", "cfg", "--address", "1; touch injected"), ("--command", "cfg", "--address", "1" * 5000)):
            with self.subTest(options=options):
                self.assertEqual(self.run_batch("first", options=options).returncode, 2)
                self.assertFalse(self.output.exists())

    def test_all_additional_read_only_commands_are_forwarded(self):
        for command in ("types", "types-c", "prototypes", "signatures", "cxx", "dwarf"):
            with self.subTest(command=command):
                self.output = self.root / command
                result = self.run_batch("first", options=("--command", command))
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads((self.output / self.report()[0]["output"]).read_text())
                self.assertEqual(data["args"], [command])
        for command in ("listing", "decompile", "ir", "cfg", "refs", "provenance", "abi", "locals", "source"):
            with self.subTest(command=command):
                self.output = self.root / ("at-" + command)
                result = self.run_batch("first", options=("--command", command, "--address", "0"))
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads((self.output / self.report()[0]["output"]).read_text())
                self.assertEqual(data["args"], [command, "0x0"])

    def test_input_list_paths_relative_to_list_and_spaces_preserved(self):
        folder = self.root / "list directory"
        folder.mkdir()
        manifest = folder / "inputs.txt"
        manifest.write_text("one\n\n space \n", encoding="utf-8")
        result = self.run_batch(options=("--input-list", str(manifest)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r["input"] for r in self.report()],
                         [str((folder / "one").resolve()), str((folder / " space ").resolve())])

    def test_invalid_resource_limits_rejected_before_output(self):
        for option, value in (("--jobs", "0"), ("--jobs", "65"),
                              ("--timeout", "nan"), ("--timeout", "inf"), ("--timeout", "-1")):
            with self.subTest(option=option, value=value):
                self.assertEqual(self.run_batch("input", options=(option, value)).returncode, 2)
                self.assertFalse(self.output.exists())

    def test_cancellation_publishes_report(self):
        process = subprocess.Popen([sys.executable, str(RUNNER), str(self.root / "slow"),
                                    str(self.root / "queued"), "--tool", str(self.tool),
                                    "--output", str(self.output)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                partials = list(self.output.glob("*.partial"))
                if partials and partials[0].stat().st_size:
                    break
                time.sleep(0.05)
            else:
                self.fail("worker did not start")
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130, stderr)
            rows = self.report()
            self.assertEqual([r["status"] for r in rows], ["cancelled", "cancelled"])
            self.assertIsNone(rows[1]["output"])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_resume_retries_failed_and_changed_inputs(self):
        for name, content in (("first", "one"), ("second", "two"), ("flaky", "fail")):
            (self.root / name).write_text(content)
        self.assertEqual(self.run_batch("first", "second", "flaky").returncode, 1)
        before = self.report()
        (self.root / "second").write_text("changed")
        (self.root / "ready").write_text("ready")
        result = self.run_batch("first", "second", "flaky", options=("--resume",))
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.report()
        self.assertEqual(before[0]["output"], after[0]["output"])
        self.assertNotEqual(before[1]["output"], after[1]["output"])
        self.assertNotEqual(before[2]["output"], after[2]["output"])
        self.assertEqual([r["status"] for r in after], ["ok", "ok", "ok"])

    def test_resume_after_kill_preserves_completed_job(self):
        for name in ("first", "crashslow"):
            (self.root / name).write_text(name)
        command = [sys.executable, str(RUNNER), str(self.root / "first"), str(self.root / "crashslow"),
                   "--tool", str(self.tool), "--output", str(self.output)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    with sqlite3.connect(self.output / "checkpoint.sqlite3") as db:
                        row = db.execute("SELECT result FROM jobs WHERE idx=0").fetchone()
                    if row:
                        break
                except sqlite3.Error:
                    pass
                time.sleep(0.05)
            else:
                self.fail("first job did not checkpoint")
            original = json.loads(row[0])["output"]
            process.kill()
            process.wait(timeout=5)
            resumed = subprocess.run(command + ["--resume"], capture_output=True, text=True, timeout=10)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(self.report()[0]["output"], original)
            self.assertEqual([r["status"] for r in self.report()], ["ok", "ok"])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_changed_input_during_job_is_not_published(self):
        source = self.root / "crashslow"
        source.write_text("before")
        command = [sys.executable, str(RUNNER), str(source), "--tool", str(self.tool), "--output", str(self.output)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not list(self.output.glob("*.partial")):
                time.sleep(0.05)
            self.assertTrue(list(self.output.glob("*.partial")))
            source.write_text("after")
            _, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 1, stderr)
            self.assertEqual(self.report()[0]["status"], "failed")
            self.assertTrue(self.report()[0]["output"].endswith(".partial"))
            resumed = subprocess.run(command + ["--resume"], capture_output=True, text=True, timeout=10)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(self.report()[0]["status"], "ok")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_changed_tool_and_artifact_invalidate_reuse(self):
        (self.root / "first").write_text("one")
        self.assertEqual(self.run_batch("first").returncode, 0)
        first = self.report()[0]["output"]
        (self.output / first).write_text("damaged")
        self.assertEqual(self.run_batch("first", options=("--resume",)).returncode, 0)
        second = self.report()[0]["output"]
        self.assertNotEqual(first, second)
        self.tool.write_text(self.tool.read_text() + "\n# new engine\n")
        self.assertEqual(self.run_batch("first", options=("--resume",)).returncode, 0)
        self.assertNotEqual(second, self.report()[0]["output"])

    def test_corrupt_checkpoint_and_parameter_mismatch_rejected(self):
        (self.root / "first").write_text("one")
        self.assertEqual(self.run_batch("first").returncode, 0)
        before = (self.output / "report.json").read_bytes()
        self.assertEqual(self.run_batch("first", options=("--resume", "--command", "summary")).returncode, 2)
        (self.output / "checkpoint.sqlite3").write_bytes(b"broken")
        self.assertEqual(self.run_batch("first", options=("--resume",)).returncode, 2)
        self.assertEqual((self.output / "report.json").read_bytes(), before)

    @unittest.skipUnless(os.environ.get("MINT_BATCH_TOOL"), "requires built mint_headless")
    def test_real_engine_address_commands(self):
        source = self.root / "function.bin"
        source.write_bytes(b"\xb8\x2a\x00\x00\x00\xc3")  # mov eax,42; ret
        for command in ("listing", "decompile", "ir", "cfg"):
            with self.subTest(command=command):
                output = self.root / ("real-" + command)
                result = subprocess.run([sys.executable, str(RUNNER), str(source),
                                         "--tool", os.environ["MINT_BATCH_TOOL"], "--output", str(output),
                                         "--raw", "x86-64", "0x1000", "0x1000",
                                         "--command", command, "--address", "0x1000"],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["results"][0]["status"], "ok")
                self.assertTrue((output / report["results"][0]["output"]).read_text().strip())

    @unittest.skipUnless(os.environ.get("MINT_BATCH_TOOL"), "requires built mint_headless")
    def test_real_engine_success_and_missing_input(self):
        result = subprocess.run([sys.executable, str(RUNNER),
                                 str(RUNNER.parent.parent / "app/src/main/assets/libmintdemo.so"),
                                 str(self.root / "missing.so"),
                                 "--tool", os.environ.get("MINT_BATCH_TOOL", ""),
                                 "--output", str(self.output), "--jobs", "2"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = self.report()
        self.assertEqual([r["status"] for r in rows], ["ok", "failed"])
        data = json.loads((self.output / rows[0]["output"]).read_text())
        self.assertTrue(data["functions"])


if __name__ == "__main__":
    unittest.main()
