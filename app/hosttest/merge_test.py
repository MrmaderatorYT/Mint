"""Three-way merge conflict/publication contracts, plus a real engine reopen."""
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/mint_merge.py"
API = runpy.run_path(str(TOOL))


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mint merge ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.base = {(0, "source"): "ELF64:aarch64:sha256:example", (0x1000, "comment"): "baseline"}
        self.ours, self.theirs = dict(self.base), dict(self.base)

    def write(self, name, records):
        path = self.root / name
        path.write_bytes(API["encode_program"](records))
        return path

    def invoke(self, output=False):
        inputs = [self.write(name, records) for name, records in
                  (("base", self.base), ("ours", self.ours), ("theirs", self.theirs))]
        before = [path.read_bytes() for path in inputs]
        args = [sys.executable, str(TOOL), *map(str, inputs)]
        if output:
            args += ["--output", str(self.root / "merged.mint")]
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual([path.read_bytes() for path in inputs], before)
        return result

    def test_merge_independent_changes_and_deletions(self):
        self.ours[0x1000, "name"] = "local_name"
        self.theirs.pop((0x1000, "comment"))
        self.theirs[0xfedcba9876543210, "comment"] = "notes\nКоманда ✓"
        result = self.invoke(output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["published"])
        merged = API["read_program"](self.root / "merged.mint")
        self.assertEqual(merged[0x1000, "name"], "local_name")
        self.assertNotIn((0x1000, "comment"), merged)
        self.assertEqual(merged[0xfedcba9876543210, "comment"], "notes\nКоманда ✓")

    def test_conflicts_include_three_values_and_publish_nothing(self):
        self.ours[0x1000, "comment"] = "ours"
        self.theirs[0x1000, "comment"] = "theirs"
        result = self.invoke(output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        row = json.loads(result.stdout)["conflicts"][0]
        self.assertEqual([row[key] for key in ("base", "ours", "theirs")], ["baseline", "ours", "theirs"])
        self.assertFalse((self.root / "merged.mint").exists())

    def test_same_concurrent_change_is_not_conflict_and_preview_is_read_only(self):
        self.ours[0x1000, "comment"] = self.theirs[0x1000, "comment"] = "agreed"
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["changes"], [])
        self.assertFalse(json.loads(result.stdout)["published"])
        self.assertFalse((self.root / "merged.mint").exists())

    def test_structural_divergence_and_different_identity_rejected(self):
        self.ours[0x1000, "patch"] = "90"
        self.assertEqual(self.invoke(output=True).returncode, 1)
        self.ours.pop((0x1000, "patch"))
        self.theirs[0, "source"] = "other binary"
        self.assertEqual(self.invoke(output=True).returncode, 2)
        self.assertFalse((self.root / "merged.mint").exists())

    def test_independent_renames_cannot_create_duplicate_symbol(self):
        self.ours[0x1000, "name"] = "same_name"
        self.theirs[0x2000, "name"] = "same_name"
        result = self.invoke(output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["conflicts"][0]["reason"], "merged symbols collide")

    def test_existing_file_or_symlink_never_overwritten(self):
        destination = self.root / "merged.mint"
        destination.write_bytes(b"keep")
        self.assertEqual(self.invoke(output=True).returncode, 2)
        self.assertEqual(destination.read_bytes(), b"keep")
        destination.unlink()
        target = self.root / "target"
        target.write_bytes(b"private")
        destination.symlink_to(target)
        self.assertEqual(self.invoke(output=True).returncode, 2)
        self.assertEqual(target.read_bytes(), b"private")
        self.assertFalse(list(self.root.glob(".mint-merge-*")))

    def test_corrupt_snapshots_rejected(self):
        valid = API["encode_program"](self.base)
        for contents in (b"MINTPR99" + valid[8:], valid + b"trailing", valid[:-1],
                         b"MINTPR04\xff\xff\xff\xff", valid[:12] + valid[12:] + valid[12:]):
            path = self.root / "corrupt"
            path.write_bytes(contents)
            with self.assertRaises(ValueError):
                API["read_program"](path)

    @unittest.skipUnless(os.environ.get("MINT_MERGE_TOOL"), "requires built mint_headless")
    def test_native_program_roundtrip(self):
        native = os.environ["MINT_MERGE_TOOL"]
        binary = ROOT / "app/src/main/assets/libmintdemo.so"
        def run(path, *commands):
            result = subprocess.run([native, str(binary), "--project", str(path), *commands],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        base = self.root / "base"
        exported = json.loads(run(base, "json"))
        address = str(exported["functions"][0]["entry"])
        ours, theirs = self.root / "ours", self.root / "theirs"
        shutil.copyfile(base, ours)
        shutil.copyfile(base, theirs)
        run(ours, "edit", address, "name", "team_name")
        run(theirs, "edit", address, "comment", "team note")
        merged, report = API["merge"](*(API["read_program"](path) for path in (base, ours, theirs)))
        self.assertTrue(report["ready"])
        destination = self.root / "merged.mint"
        API["publish_new"](destination, API["encode_program"](merged))
        reopened = json.loads(run(destination, "json"))
        self.assertEqual(reopened["functions"][0]["name"], "team_name")
        self.assertEqual(API["read_program"](destination)[int(address), "comment"], "team note")


if __name__ == "__main__":
    unittest.main()
