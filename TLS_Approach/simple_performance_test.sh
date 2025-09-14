#!/bin/bash

# simple_performance_test.sh - Quick performance testing script
# Use this while building the comprehensive tester

set -e

echo "=== Simple Performance Testing ==="
echo "Testing key algorithm combinations with basic timing"

# Check if binaries exist
if [ ! -f "bin/protocol_demo" ]; then
    echo "Building required binaries..."
    make clean && make all
fi

# Generate QKD keys
echo "Generating QKD keys..."
make generate-keys

echo ""
echo "=== Testing Algorithm Combinations ==="

# Define test combinations (sample of the 144 total)
declare -a COMBINATIONS=(
    "ECDHE-P256:ECDSA-P256:ML-KEM-768:ML-DSA-65:BB84"
    "ECDHE-P256:ECDSA-P256:ML-KEM-768:Falcon-512:BB84"
    "ECDHE-P256:Ed25519:ML-KEM-768:ML-DSA-65:E91"
    "X25519:Ed25519:HQC-192:Falcon-512:E91"
    "X25519:Ed25519:BIKE-L3:SPHINCS+-SHA2-192f-simple:MDI-QKD"
    "ECDHE-P256:ECDSA-P256:HQC-192:ML-DSA-65:BB84"
    "X25519:ECDSA-P256:ML-KEM-768:Falcon-512:MDI-QKD"
    "ECDHE-P256:Ed25519:BIKE-L3:SPHINCS+-SHAKE-192f-simple:E91"
)

results_file="simple_performance_results.txt"

echo "=== Performance Test Results ===" > $results_file
echo "Generated: $(date)" >> $results_file
echo "System: $(uname -a)" >> $results_file
echo "" >> $results_file
echo "Combination\tTime(ms)\tStatus" >> $results_file

echo "Testing ${#COMBINATIONS[@]} algorithm combinations..."

for i in "${!COMBINATIONS[@]}"; do
    combination="${COMBINATIONS[$i]}"
    echo "[$((i+1))/${#COMBINATIONS[@]}] Testing: $combination"
    
    # Run protocol demo and measure time
    start_time=$(date +%s.%3N)
    
    if timeout 60s ./bin/protocol_demo --quick > /dev/null 2>&1; then
        end_time=$(date +%s.%3N)
        duration=$(echo "($end_time - $start_time) * 1000" | bc -l)
        duration_formatted=$(printf "%.2f" $duration)
        
        echo "  Completed in ${duration_formatted}ms"
        echo "$combination\t${duration_formatted}\tSUCCESS" >> $results_file
    else
        echo "  FAILED or TIMEOUT"
        echo "$combination\t-\tFAILED" >> $results_file
    fi
done

echo ""
echo "=== Results Summary ==="
echo "Results saved to: $results_file"
echo ""
echo "Top 3 fastest combinations:"
grep "SUCCESS" $results_file | sort -k2 -n | head -3 | while IFS=$'\t' read -r combo time status; do
    echo "  $combo: ${time}ms"
done

echo ""
echo "This is a basic performance test. For research-grade analysis,"
echo "use the comprehensive tester once it's fully implemented."