#!/usr/bin/env python3
"""Build, verify, or publish a signed Mint preview from an exact Git tag."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


PACKAGE = "com.ccs.mint"
VCS = "META-INF/version-control-info.textproto"
ARTIFACTS = {
    "mint.apk": Path("app/build/outputs/apk/release/app-release.apk"),
    "mint.aab": Path("app/build/outputs/bundle/release/app-release.aab"),
}
MANIFEST = "release.json"
ANDROID = "{http://schemas.android.com/apk/res/android}"
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class ReleaseError(Exception):
    pass


def command(argv, cwd=None):
    result = subprocess.run(
        argv, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode:
        # Tool output can include paths and other build settings. Only report
        # the executable and failure code here.
        raise ReleaseError(f"{Path(argv[0]).name} failed with exit code {result.returncode}")
    return result.stdout


def git(repo, *args):
    return command(("git", *args), cwd=repo).strip()


def tagged_commit(repo, tag):
    ref = f"refs/tags/{tag}"
    git(repo, "check-ref-format", ref)
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    if not REVISION.fullmatch(commit):
        raise ReleaseError("Git did not resolve the tag to a full commit ID")
    return commit


def require_release_checkout(repo, commit):
    if git(repo, "rev-parse", "HEAD") != commit:
        raise ReleaseError("HEAD does not match the release tag")
    if git(repo, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        raise ReleaseError("Release builds require a clean checkout of the release tag")


def normalize_digest(value):
    value = value.lower().replace(":", "")
    if not SHA256.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a SHA-256 fingerprint")
    return value


def digest(path):
    with path.open("rb") as source:
        checksum = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(block)
        return checksum.hexdigest()


def vcs_revision(archive, member):
    with zipfile.ZipFile(archive) as zipped:
        entries = [entry for entry in zipped.infolist() if entry.filename == member]
        if len(entries) != 1 or entries[0].file_size > 65536:
            raise ReleaseError(f"{archive.name}: missing, duplicate, or oversized revision metadata")
        raw = zipped.read(entries[0]).decode("utf-8")
    lines = re.findall(r'^\s*revision\s*:\s*"([0-9a-f]+)"[ \t]*$', raw, re.MULTILINE)
    if len(lines) != 1 or not REVISION.fullmatch(lines[0]):
        raise ReleaseError(f"{archive.name}: missing or ambiguous Git revision")
    return lines[0]


def apk_identity(artifact, sdk_tools):
    badging = command((str(sdk_tools / "aapt"), "dump", "badging", str(artifact)))
    package = re.findall(
        r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'", badging, re.MULTILINE
    )
    if len(package) != 1 or re.search(r"^application-debuggable\b", badging, re.MULTILINE):
        raise ReleaseError(f"{artifact.name}: invalid or debuggable APK manifest")
    name, code, version = package[0]
    return name, int(code), version


def aab_identity(artifact, bundletool):
    manifest = command(("java", "-jar", str(bundletool), "dump", "manifest", f"--bundle={artifact}", "--module=base"))
    root = ET.fromstring(manifest)
    application = root.find("application")
    if root.tag != "manifest" or application is None or application.get(ANDROID + "debuggable", "false") != "false":
        raise ReleaseError(f"{artifact.name}: invalid or debuggable bundle manifest")
    code = root.get(ANDROID + "versionCode", "")
    if not re.fullmatch(r"[0-9]+", code):
        raise ReleaseError(f"{artifact.name}: invalid bundle version code")
    return root.get("package"), int(code), root.get(ANDROID + "versionName")


def apk_signer(artifact, sdk_tools):
    result = command((str(sdk_tools / "apksigner"), "verify", "--verbose", "--print-certs", str(artifact)))
    if not re.search(r"^Verified using v(?:2|3(?:\.1)?) scheme .*: true$", result, re.MULTILINE):
        # The revision is under META-INF. APK signing must cover the whole
        # archive rather than only the entries covered by JAR signing.
        raise ReleaseError("APK requires a verified v2 or v3 signature")
    digests = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([A-Fa-f0-9]{64})$", result, re.MULTILINE)
    if len(digests) != 1:
        raise ReleaseError(f"{artifact.name}: expected one verified APK signer")
    return digests[0].lower()


def aab_signer(artifact):
    helper = Path(__file__).with_name("MintBundleSigner.java").resolve()
    result = command(("java", str(helper), str(artifact))).strip()
    if not SHA256.fullmatch(result):
        raise ReleaseError(f"{artifact.name}: expected one verified bundle signer")
    return result


def inspect(directory, commit, args):
    report = {
        "schema_version": 1,
        "tag": args.tag,
        "commit": commit,
        "package": PACKAGE,
        "version_code": args.version_code,
        "version_name": args.version_name,
        "certificate_sha256": args.certificate_sha256,
        "files": {},
    }
    for filename in ARTIFACTS:
        artifact = directory / filename
        if not artifact.is_file() or artifact.is_symlink():
            raise ReleaseError(f"{filename}: expected a regular release artifact")
        checksum = digest(artifact)
        is_apk = artifact.suffix == ".apk"
        embedded = vcs_revision(artifact, VCS if is_apk else f"base/root/{VCS}")
        if embedded != commit:
            raise ReleaseError(f"{filename}: embedded Git revision {embedded} does not match tag commit {commit}")
        try:
            identity = apk_identity(artifact, args.build_tools) if is_apk else aab_identity(artifact, args.bundletool)
            signer = apk_signer(artifact, args.build_tools) if is_apk else aab_signer(artifact)
        except ReleaseError as error:
            raise ReleaseError(f"{filename}: {error}") from error
        if identity != (PACKAGE, args.version_code, args.version_name):
            raise ReleaseError(f"{filename}: unexpected package or version ({identity!r})")
        if signer != args.certificate_sha256:
            raise ReleaseError(f"{filename}: signer does not match the expected certificate")
        if digest(artifact) != checksum:
            raise ReleaseError(f"{filename}: artifact changed during verification")
        report["files"][filename] = {"sha256": checksum, "bytes": artifact.stat().st_size}
    return report


def read_manifest(directory):
    manifest = directory / MANIFEST
    if not manifest.is_file() or manifest.is_symlink() or manifest.stat().st_size > 65536:
        raise ReleaseError("expected a regular release.json manifest no larger than 64 KiB")
    try:
        return json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ReleaseError("invalid release.json manifest") from error


def build(args, commit):
    require_release_checkout(args.repo, commit)
    if os.path.lexists(args.output):
        raise ReleaseError("release output directory already exists")
    gradle = ["./gradlew", "--no-build-cache", "--no-configuration-cache", "--rerun-tasks"]
    if args.offline:
        gradle.append("--offline")
    gradle.extend((":app:assembleRelease", ":app:bundleRelease"))
    if subprocess.run(gradle, cwd=args.repo, check=False).returncode:
        raise ReleaseError("Gradle could not build signed release artifacts")
    if tagged_commit(args.repo, args.tag) != commit:
        raise ReleaseError("release tag moved during the build")
    require_release_checkout(args.repo, commit)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mint-release-", dir=args.output.parent) as temp:
        staging = Path(temp) / "verified"
        staging.mkdir()
        for filename, source in ARTIFACTS.items():
            shutil.copyfile(args.repo / source, staging / filename)
        report = inspect(staging, commit, args)
        (staging / MANIFEST).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if os.path.lexists(args.output):
            raise ReleaseError("release output directory appeared during the build")
        staging.rename(args.output)
    return report


def verify(args, commit, directory):
    expected = read_manifest(directory)
    report = inspect(directory, commit, args)
    if json.dumps(report, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ReleaseError("artifact checksums or release identity do not match release.json")
    if tagged_commit(args.repo, args.tag) != commit:
        raise ReleaseError("release tag moved during verification")
    return report


def verify_remote_tag(repo, repository, tag, commit):
    ref = f"refs/tags/{tag}"
    peeled = ref + "^{}"
    output = git(repo, "ls-remote", "--exit-code", f"https://github.com/{repository}.git", ref, peeled)
    refs = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[1] not in (ref, peeled) or fields[1] in refs:
            raise ReleaseError("unexpected remote tag response")
        refs[fields[1]] = fields[0]
    if ref not in refs or refs.get(peeled, refs[ref]) != commit:
        raise ReleaseError("remote release tag does not match the verified commit")


def publish(args, commit):
    # Publish the exact APK bytes that were verified, even if the caller later
    # replaces their local candidate directory. The AAB stays local for Play.
    with tempfile.TemporaryDirectory(prefix="mint-publish-") as temp:
        staged = Path(temp)
        for filename in (*ARTIFACTS, MANIFEST):
            source = args.output / filename
            if not source.is_file() or source.is_symlink():
                raise ReleaseError(f"{filename}: expected a regular release file")
            shutil.copyfile(source, staged / filename)
        report = verify(args, commit, staged)
        verify_remote_tag(args.repo, args.repository, args.tag, commit)
        checksum = staged / "mint.apk.sha256"
        checksum.write_text(f'{report["files"]["mint.apk"]["sha256"]}  mint.apk\n', encoding="ascii")
        url = command((
            "gh", "release", "create", args.tag, str(staged / "mint.apk"), str(checksum),
            "--repo", args.repository, "--verify-tag", "--prerelease",
            "--title", f"Mint {args.version_name}", "--notes-file", str(args.notes_file),
        ), cwd=args.repo)
    print(url.strip())
    return report


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("build", "verify", "publish"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag", required=True, help="existing local version tag")
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--certificate-sha256", required=True, type=normalize_digest)
    parser.add_argument("--bundletool", required=True, type=Path, help="path to the standalone bundletool JAR")
    parser.add_argument("--build-tools", type=Path, help="Android SDK build-tools directory (defaults to 36.0.0)")
    parser.add_argument("--output", required=True, type=Path, help="directory for mint.apk, mint.aab and release.json")
    parser.add_argument("--offline", action="store_true", help="run the Gradle release build offline")
    parser.add_argument("--repository", help="GitHub owner/repository for publish")
    parser.add_argument("--notes-file", type=Path, help="release notes for publish")
    args = parser.parse_args(argv)
    if args.version_code <= 0:
        parser.error("--version-code must be positive")
    if args.offline and args.operation != "build":
        parser.error("--offline applies to build only")
    if args.operation == "publish":
        if not args.repository or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            parser.error("publish requires --repository OWNER/REPO")
        if args.notes_file is None or not args.notes_file.is_file():
            parser.error("publish requires an existing --notes-file")
        args.notes_file = args.notes_file.resolve()
    elif args.repository is not None or args.notes_file is not None:
        parser.error("--repository and --notes-file apply to publish only")
    if args.build_tools is None:
        sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk:
            parser.error("set ANDROID_HOME or pass --build-tools")
        args.build_tools = Path(sdk) / "build-tools" / "36.0.0"
    args.output = args.output.absolute()
    args.repo = args.repo.resolve()
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        commit = tagged_commit(args.repo, args.tag)
        if args.operation == "build":
            report = build(args, commit)
        elif args.operation == "publish":
            report = publish(args, commit)
        else:
            report = verify(args, commit, args.output)
        print(json.dumps(report, indent=2))
        return 0
    except (ReleaseError, OSError, ValueError, zipfile.BadZipFile, ET.ParseError) as error:
        print(f"mint_release: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
