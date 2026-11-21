#!/usr/bin/env sh
# Run against an already installed Mint debug and instrumentation APK.
# ANDROID_SERIAL selects the device and MINT_TEST_PACKAGE selects the test APK.
set -eu

runner="${MINT_TEST_PACKAGE:-com.ccs.mint.test}/androidx.test.runner.AndroidJUnitRunner"
test_class=com.ccs.mint.ProgramProcessDeathTest
token=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
dir=$(mktemp -d "${TMPDIR:-/tmp}/mint-process-death-XXXXXX")
trap 'rm -rf -- "$dir"' EXIT

adb shell am instrument -w -r -e mintRecoveryToken "$token" -e mintRecoveryPhase write \
    -e class "$test_class#commitAndKill" "$runner" >"$dir/write.log" 2>&1 || true
cat "$dir/write.log"
if ! grep -Fqi 'Process crashed' "$dir/write.log"; then
    printf '%s\n' 'Expected the first instrumentation process to die after saving.' >&2
    exit 1
fi

adb shell am instrument -w -r -e mintRecoveryToken "$token" -e mintRecoveryPhase read \
    -e class "$test_class#reopenInNewProcess" "$runner" >"$dir/read.log" 2>&1
cat "$dir/read.log"
grep -Fq 'OK (1 test)' "$dir/read.log"
