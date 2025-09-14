#!/bin/bash

# run_network_test.sh - Standalone network test for Hybrid TLS

set -e

echo "=== Hybrid TLS Network Test ==="

# Check if we're in the right directory
if [ ! -f "stage.c" ] || [ ! -d "src" ]; then
    echo "Error: Please run this script from the TLS_Approach directory"
    exit 1
fi

# Check if binaries exist
if [ ! -f "bin/stage" ] || [ ! -f "bin/bob_server" ] || [ ! -f "bin/alice_client" ]; then
    echo "Error: Binaries not found. Please run 'make all' first"
    exit 1
fi

echo "Step 1: Generating QKD keys..."
./bin/stage --non-blocking
if [ $? -ne 0 ]; then
    echo "QKD key generation failed"
    exit 1
fi

echo ""
echo "Step 2: Checking for existing processes..."
pkill -f bob_server >/dev/null 2>&1 || true
pkill -f alice_client >/dev/null 2>&1 || true
sleep 2

echo ""
echo "Step 3: Starting Bob server..."
# Start Bob server in background and capture its PID
./bin/bob_server > /tmp/hybrid_tls_bob.log 2>&1 &
BOB_PID=$!

echo "Bob server started with PID $BOB_PID"
echo "Waiting for Bob server to initialize..."
sleep 4

# Check if Bob server is still running
if ! kill -0 $BOB_PID 2>/dev/null; then
    echo "Bob server failed to start. Log:"
    cat /tmp/hybrid_tls_bob.log
    exit 1
fi

echo ""
echo "Step 4: Starting Alice client..."
# Run Alice client and capture output
if ./bin/alice_client > /tmp/hybrid_tls_alice.log 2>&1; then
    echo "Alice client completed successfully"
    TEST_RESULT=0
else
    echo "Alice client failed"
    TEST_RESULT=1
fi

echo ""
echo "Step 5: Stopping Bob server..."
kill $BOB_PID >/dev/null 2>&1 || true
sleep 1
pkill -f bob_server >/dev/null 2>&1 || true

echo ""
echo "=== Test Results ==="
if [ $TEST_RESULT -eq 0 ]; then
    echo "✓ Network Test PASSED"
    echo ""
    echo "Bob server output (last 20 lines):"
    echo "-----------------------------------"
    tail -20 /tmp/hybrid_tls_bob.log 2>/dev/null || echo "No Bob log available"
    echo ""
    echo "Alice client output (last 20 lines):"
    echo "------------------------------------"
    tail -20 /tmp/hybrid_tls_alice.log 2>/dev/null || echo "No Alice log available"
else
    echo "✗ Network Test FAILED"
    echo ""
    echo "Bob server output:"
    echo "-----------------"
    cat /tmp/hybrid_tls_bob.log 2>/dev/null || echo "No Bob log available"
    echo ""
    echo "Alice client output:"
    echo "-------------------"
    cat /tmp/hybrid_tls_alice.log 2>/dev/null || echo "No Alice log available"
fi

echo ""
echo "Cleaning up temporary files..."
rm -f /tmp/hybrid_tls_bob.log /tmp/hybrid_tls_alice.log

exit $TEST_RESULT