from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile


TOOL = Path(__file__).resolve().parents[1] / "mint_release.py"
spec = importlib.util.spec_from_file_location("mint_release", TOOL)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
TAG = "0.8-preview"
COMMIT = "1" * 40
CERTIFICATE = "a" * 64
VERSION = (release.PACKAGE, 8, "0.8 Preview")


def archive(path, member, revision=COMMIT):
    with zipfile.ZipFile(path, "w") as zipped:
        zipped.writestr(member, f'repositories {{\n  revision: "{revision}"\n}}\n')
        zipped.writestr("payload", "fixture")


class ReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.apk = self.root / "mint.apk"
        self.aab = self.root / "mint.aab"
        archive(self.apk, release.VCS)
        archive(self.aab, f"base/root/{release.VCS}")
        self.args = SimpleNamespace(
            tag=TAG, version_code=8, version_name="0.8 Preview", certificate_sha256=CERTIFICATE,
            bundletool=self.root / "bundletool.jar", build_tools=self.root,
        )
        for name, value in (("apk_identity", VERSION), ("aab_identity", VERSION),
                            ("apk_signer", CERTIFICATE), ("aab_signer", CERTIFICATE)):
            override = patch.object(release, name, return_value=value)
            setattr(self, name, override.start())
            self.addCleanup(override.stop)

    def test_records_exact_tag_and_both_archive_digests(self):
        report = release.inspect(self.root, COMMIT, self.args)
        self.assertEqual(report["commit"], COMMIT)
        self.assertEqual(report["tag"], TAG)
        for path in (self.apk, self.aab):
            data = path.read_bytes()
            self.assertEqual(report["files"][path.name], dict(
                sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)
            ))

    def test_rejects_stale_revision_in_either_artifact(self):
        for path, member in [(self.apk, release.VCS), (self.aab, f"base/root/{release.VCS}")]:
            with self.subTest(path=path.name):
                archive(path, member, "2" * 40)
                with self.assertRaisesRegex(release.ReleaseError, "does not match tag commit"):
                    release.inspect(self.root, COMMIT, self.args)
                archive(path, member)

    def test_rejects_missing_duplicate_and_ambiguous_revision_metadata(self):
        for contents in ("missing", "duplicate", "ambiguous"):
            with self.subTest(contents=contents):
                if contents == "missing":
                    archive(self.apk, "unrelated")
                else:
                    archive(self.apk, release.VCS)
                    with warnings.catch_warnings(), zipfile.ZipFile(self.apk, "a") as zipped:
                        warnings.simplefilter("ignore", UserWarning)
                        if contents == "duplicate":
                            zipped.writestr(release.VCS, f'revision: "{COMMIT}"\n')
                        else:
                            with zipfile.ZipFile(self.aab, "w") as bundle:
                                bundle.writestr(f"base/root/{release.VCS}", f'revision: "{COMMIT}"\n' * 2)
                with self.assertRaises(release.ReleaseError):
                    release.inspect(self.root, COMMIT, self.args)
                archive(self.aab, f"base/root/{release.VCS}")

    def test_rejects_version_or_signer_mismatch_in_either_artifact(self):
        for tool in (self.apk_identity, self.aab_identity, self.apk_signer, self.aab_signer):
            with self.subTest(tool=tool):
                identity = tool.return_value
                tool.return_value = (release.PACKAGE, 7, "0.7 Preview") if identity == VERSION else "b" * 64
                with self.assertRaisesRegex(release.ReleaseError, "unexpected package or version|signer does not match"):
                    release.inspect(self.root, COMMIT, self.args)
                tool.return_value = identity

    def test_verify_rejects_artifact_changed_after_build(self):
        expected = release.inspect(self.root, COMMIT, self.args)
        (self.root / release.MANIFEST).write_text(json.dumps(expected), encoding="utf-8")
        arguments = [
            "verify", "--tag", TAG, "--version-code", "8", "--version-name", "0.8 Preview",
            "--certificate-sha256", CERTIFICATE, "--bundletool", "bundletool.jar",
            "--build-tools", "tools", "--output", str(self.root),
        ]
        with patch.object(release, "tagged_commit", return_value=COMMIT), redirect_stdout(io.StringIO()):
            self.assertEqual(release.main(arguments), 0)
            with zipfile.ZipFile(self.aab, "a") as zipped:
                zipped.writestr("later-payload", "repacked")
            with redirect_stderr(io.StringIO()) as error:
                self.assertEqual(release.main(arguments), 1)
                self.assertIn("checksums", error.getvalue())

    def test_build_rejects_wrong_head_and_dirty_checkout_before_gradle(self):
        opts = SimpleNamespace(repo=self.root, output=self.root / "output", tag=TAG)
        with patch.object(release, "git", return_value="2" * 40), patch.object(subprocess, "run") as gradle:
            with self.assertRaisesRegex(release.ReleaseError, "HEAD does not match"):
                release.build(opts, COMMIT)
            gradle.assert_not_called()
        with patch.object(release, "git", side_effect=[COMMIT, " M tracked-file"]), patch.object(subprocess, "run") as gradle:
            with self.assertRaisesRegex(release.ReleaseError, "clean checkout"):
                release.build(opts, COMMIT)
            gradle.assert_not_called()

    def test_build_forces_fresh_gradle_tasks_and_writes_verified_manifest(self):
        opts = SimpleNamespace(**vars(self.args), repo=self.root, output=self.root / "output", offline=True)
        for filename, relative in release.ARTIFACTS.items():
            path = self.root / relative
            path.parent.mkdir(parents=True)
            shutil.copyfile(self.root / filename, path)
        with patch.object(release, "require_release_checkout") as checkout, \
             patch.object(release, "tagged_commit", return_value=COMMIT), \
             patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0)) as gradle:
            report = release.build(opts, COMMIT)
        self.assertEqual(checkout.call_count, 2)
        gradle.assert_called_once_with(
            ["./gradlew", "--no-build-cache", "--no-configuration-cache", "--rerun-tasks", "--offline",
             ":app:assembleRelease", ":app:bundleRelease"], cwd=self.root, check=False
        )
        self.assertEqual(release.read_manifest(opts.output), report)
        self.assertEqual(report["files"], release.inspect(opts.output, COMMIT, opts)["files"])

    def test_remote_tag_uses_peeled_commit_and_rejects_stale_remote_tag(self):
        ref = f"refs/tags/{TAG}"
        annotated = f'{"3" * 40}\t{ref}\n{COMMIT}\t{ref}^{{}}'
        for output in (f"{COMMIT}\t{ref}", annotated):
            with patch.object(release, "git", return_value=output):
                release.verify_remote_tag(self.root, "example/Mint", TAG, COMMIT)
        with patch.object(release, "git", return_value=f'{"2" * 40}\t{ref}'):
            with self.assertRaisesRegex(release.ReleaseError, "remote release tag"):
                release.verify_remote_tag(self.root, "example/Mint", TAG, COMMIT)

    def test_publish_uploads_only_verified_apk_and_checksum(self):
        note = self.root / "notes.md"
        note.write_text("Fixture notes", encoding="utf-8")
        opts = SimpleNamespace(**vars(self.args), output=self.root, repo=self.root, repository="example/Mint",
                               notes_file=note)
        report = release.inspect(self.root, COMMIT, self.args)
        (self.root / release.MANIFEST).write_text(json.dumps(report), encoding="utf-8")
        with patch.object(release, "tagged_commit", return_value=COMMIT), \
             patch.object(release, "verify_remote_tag", side_effect=release.ReleaseError("stale remote")), \
             patch.object(release, "command") as transport:
            with self.assertRaisesRegex(release.ReleaseError, "stale remote"):
                release.publish(opts, COMMIT)
            transport.assert_not_called()

        def gh(argv, cwd):
            self.assertEqual(argv[:4], ("gh", "release", "create", TAG))
            self.assertEqual(Path(argv[4]).read_bytes(), self.apk.read_bytes())
            self.assertEqual(Path(argv[5]).read_text(), report["files"]["mint.apk"]["sha256"] + "  mint.apk\n")
            self.assertNotIn("mint.aab", str(argv))
            self.assertIn("--verify-tag", argv)
            self.assertEqual(cwd, self.root)
            return "https://example.invalid/mint"

        with patch.object(release, "tagged_commit", return_value=COMMIT), \
             patch.object(release, "verify_remote_tag") as remote, \
             patch.object(release, "command", side_effect=gh) as transport, redirect_stdout(io.StringIO()):
            self.assertEqual(release.publish(opts, COMMIT), report)
        remote.assert_called_once_with(self.root, "example/Mint", TAG, COMMIT)
        transport.assert_called_once()


class ApkSignatureTests(unittest.TestCase):
    def test_apk_needs_a_signature_that_covers_the_provenance_entry(self):
        certificate = f"Signer #1 certificate SHA-256 digest: {CERTIFICATE}\n"
        result = "Verified using v1 scheme (JAR signing): true\n" + certificate
        with patch.object(release, "command", return_value=result):
            with self.assertRaisesRegex(release.ReleaseError, "v2 or v3"):
                release.apk_signer(Path("mint.apk"), Path("tools"))
        result += "Verified using v2 scheme (APK Signature Scheme v2): true\n"
        with patch.object(release, "command", return_value=result):
            self.assertEqual(release.apk_signer(Path("mint.apk"), Path("tools")), CERTIFICATE)


@unittest.skipUnless(all(shutil.which(command) for command in ("java", "keytool", "jarsigner")), "requires a JDK")
class RealBundleSignatureTests(unittest.TestCase):
    def test_detects_unsigned_entries_even_if_the_bundle_contains_a_valid_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "mint.aab"
            keystore = root / "fixture.p12"
            archive(bundle, f"base/root/{release.VCS}")
            subprocess.run([
                "keytool", "-genkeypair", "-keystore", str(keystore), "-storepass", "fixturepassword",
                "-alias", "fixture", "-dname", "CN=Mint release test fixture",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
            ], check=True, capture_output=True)
            certificate = subprocess.check_output([
                "keytool", "-exportcert", "-keystore", str(keystore), "-storepass", "fixturepassword",
                "-alias", "fixture",
            ])
            with self.assertRaises(release.ReleaseError):
                release.aab_signer(bundle)
            subprocess.run(["jarsigner", "-keystore", str(keystore), "-storepass", "fixturepassword",
                            str(bundle), "fixture"], check=True, capture_output=True)
            self.assertEqual(release.aab_signer(bundle), hashlib.sha256(certificate).hexdigest())
            with zipfile.ZipFile(bundle, "a") as zipped:
                zipped.writestr("base/unsigned-extra", "tampered payload")
            with self.assertRaises(release.ReleaseError):
                release.aab_signer(bundle)


if __name__ == "__main__":
    unittest.main()
