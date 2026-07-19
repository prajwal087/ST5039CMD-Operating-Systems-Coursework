#!/bin/sh
set -e

LOGDIR="test_runs"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/*.log

cleanup() {
    echo "=== cleaning up stray children ==="
    for p in loop spray weasel sandbox; do
        pkill -9 "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "============================================"
echo "  Sandbox Test Suite"
echo "============================================"
echo ""

echo "--- Test 1: infinite loop (wall clock) ---"
SANDBOX_WALL=3 SANDBOX_CPU=100 SANDBOX_RSS=512000 \
    ./sandbox ./test_binaries/loop > "$LOGDIR/test1.out" 2>&1 || true
cat "$LOGDIR/test1.out"
echo ""

echo "--- Test 2: memory spray (RSS limit) ---"
SANDBOX_WALL=10 SANDBOX_CPU=100 SANDBOX_RSS=204800 \
    ./sandbox ./test_binaries/spray > "$LOGDIR/test2.out" 2>&1 || true
cat "$LOGDIR/test2.out"
echo ""

echo "--- Test 3: evasive binary (weasel) ---"
SANDBOX_WALL=6 SANDBOX_CPU=70 SANDBOX_RSS=256000 \
    ./sandbox ./test_binaries/weasel > "$LOGDIR/test3.out" 2>&1 || true
cat "$LOGDIR/test3.out"
echo ""

echo "--- Test 4: clean exit ---"
SANDBOX_WALL=10 SANDBOX_CPU=100 SANDBOX_RSS=512000 \
    ./sandbox /bin/true > "$LOGDIR/test4.out" 2>&1 || true
cat "$LOGDIR/test4.out"
echo ""

echo "============================================"
echo "  Results"
echo "============================================"
echo "sandbox.log from test 1:"
head -20 sandbox.log 2>/dev/null || echo "(no sandbox.log)"
echo ""
echo "=== ALL TESTS COMPLETE ==="
