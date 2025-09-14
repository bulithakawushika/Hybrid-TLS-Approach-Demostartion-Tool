#!/bin/bash

# test.sh - Helper script for Hybrid TLS testing

set -e  # Exit on any error

echo "=== Hybrid TLS Test Helper ==="

# Function to display help
show_help() {
    echo "Usage: ./test.sh [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build        - Clean build everything"
    echo "  keys         - Generate QKD keys"
    echo "  test         - Run basic tests"
    echo "  demo         - Run protocol demo"
    echo "  network      - Run network test (Alice + Bob)"
    echo "  bob          - Start Bob server (for manual testing)"
    echo "  alice        - Start Alice client (for manual testing)"
    echo "  clean        - Clean build artifacts"
    echo "  setup        - Complete setup (build + keys)"
    echo "  all          - Run all tests"
    echo "  help         - Show this help"
}

# Function to check if files exist
check_files() {
    if [ ! -f "stage.c" ]; then
        echo "Error: stage.c not found. Are you in the TLS_Approach directory?"
        exit 1
    fi
    
    if [ ! -f "Makefile" ]; then
        echo "Error: Makefile not found."
        exit 1
    fi
}

# Function to build everything
build_all() {
    echo "Building all components..."
    make clean
    make all
    echo "Build completed successfully!"
}

# Function to generate keys
generate_keys() {
    echo "Generating QKD keys..."
    make generate-keys
    
    # Check if keys were generated
    if [ -f "/tmp/qkd_keys.dat" ]; then
        echo "✓ QKD keys generated successfully"
    else
        echo "✗ QKD key generation failed"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    echo "Running basic cryptographic tests..."
    make test-basic
    echo "Basic tests completed!"
}

# Function to run demo
run_demo() {
    echo "Running protocol demonstration..."
    make demo-quick
    echo "Demo completed!"
}

# Function to run network test
run_network_test() {
    echo "Running network test..."
    chmod +x run_network_test.sh 2>/dev/null || true
    ./run_network_test.sh
    echo "Network test completed!"
}

# Function to start Bob server
start_bob() {
    echo "Starting Bob server..."
    echo "Press Ctrl+C to stop"
    make run-bob
}

# Function to start Alice client
start_alice() {
    echo "Starting Alice client..."
    make run-alice
}

# Function to clean
clean_all() {
    echo "Cleaning build artifacts..."
    make clean
    rm -f /tmp/qkd_keys.dat
    echo "Clean completed!"
}

# Function to setup everything
setup_all() {
    echo "Setting up everything..."
    build_all
    generate_keys
    echo "Setup completed successfully!"
}

# Function to run all tests
run_all_tests() {
    echo "Running complete test suite..."
    setup_all
    run_tests
    run_demo
    run_network_test
    echo "All tests completed successfully!"
}

# Main script logic
check_files

case "${1:-help}" in
    build)
        build_all
        ;;
    keys)
        generate_keys
        ;;
    test)
        run_tests
        ;;
    demo)
        run_demo
        ;;
    network)
        run_network_test
        ;;
    bob)
        start_bob
        ;;
    alice)
        start_alice
        ;;
    clean)
        clean_all
        ;;
    setup)
        setup_all
        ;;
    all)
        run_all_tests
        ;;
    help|*)
        show_help
        ;;
esac