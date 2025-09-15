# Hybrid TLS Implementation - Production Makefile
# Supports comprehensive testing of all 144 algorithm combinations

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -g -pthread -fstack-protector-strong
LDFLAGS = -loqs -lssl -lcrypto -lcjson -lm -pthread

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Create directories if they don't exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# Source files
COMMON_SOURCES = $(SRC_DIR)/config.c $(SRC_DIR)/qkd_data.c $(SRC_DIR)/qkd_interface.c \
                 $(SRC_DIR)/classical_crypto.c $(SRC_DIR)/pqc_crypto.c $(SRC_DIR)/mac_ops.c

PROTOCOL_SOURCES = $(SRC_DIR)/hybrid_tls_protocol.c $(SRC_DIR)/network_protocol.c

# Object files
COMMON_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(COMMON_SOURCES))
PROTOCOL_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PROTOCOL_SOURCES))

# Main executables
EXECUTABLES = $(BIN_DIR)/stage $(BIN_DIR)/test_runner $(BIN_DIR)/protocol_demo \
              $(BIN_DIR)/alice_client $(BIN_DIR)/bob_server $(BIN_DIR)/comprehensive_tester

# Default target
all: directories $(EXECUTABLES)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Common object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Stage executable (QKD key generation)
$(BIN_DIR)/stage: stage.c $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(LDFLAGS)

# Test runner
$(BIN_DIR)/test_runner: $(SRC_DIR)/test_runner.c $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(LDFLAGS)

# Protocol demo
$(BIN_DIR)/protocol_demo: $(SRC_DIR)/protocol_demo.c $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS) $(LDFLAGS)

# Network components
$(BIN_DIR)/alice_client: $(SRC_DIR)/alice_client.c $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS) $(LDFLAGS)

$(BIN_DIR)/bob_server: $(SRC_DIR)/bob_server.c $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(PROTOCOL_OBJECTS) $(LDFLAGS)

# Production comprehensive tester
$(BIN_DIR)/comprehensive_tester: $(SRC_DIR)/comprehensive_tester.c $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJECTS) $(LDFLAGS)

# Debug comprehensive tester (keep the working debug version)
$(BIN_DIR)/debug_tester: $(SRC_DIR)/debug_tester.c $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -DDEBUG -o $@ $< $(COMMON_OBJECTS) $(LDFLAGS)

# Individual test components
test-classical: $(BIN_DIR)/test_runner
	@echo "Testing classical cryptography..."
	@$(BIN_DIR)/test_runner --classical-only

test-pqc: $(BIN_DIR)/test_runner
	@echo "Testing post-quantum cryptography..."
	@$(BIN_DIR)/test_runner --pqc-only

test-qkd: $(BIN_DIR)/stage
	@echo "Testing QKD key generation..."
	@$(BIN_DIR)/stage --non-blocking

test-basic: $(BIN_DIR)/test_runner generate-keys
	@echo "Running basic test suite..."
	@$(BIN_DIR)/test_runner

test-full: $(BIN_DIR)/test_runner generate-keys
	@echo "Running full test suite (all 144 combinations)..."
	@$(BIN_DIR)/test_runner --full

# QKD key generation
generate-keys: $(BIN_DIR)/stage
	@echo "Generating QKD keys for all protocols..."
	@$(BIN_DIR)/stage --non-blocking
	@echo "QKD keys generated successfully"

# Network testing
test-network: $(BIN_DIR)/alice_client $(BIN_DIR)/bob_server generate-keys
	@echo "Running network test..."
	@chmod +x run_network_test.sh
	@./run_network_test.sh

# Protocol demonstration
demo: $(BIN_DIR)/protocol_demo generate-keys
	@echo "Running protocol demonstration..."
	@$(BIN_DIR)/protocol_demo

demo-quick: $(BIN_DIR)/protocol_demo generate-keys
	@echo "Running quick protocol demo..."
	@$(BIN_DIR)/protocol_demo --quick

demo-suite: $(BIN_DIR)/protocol_demo generate-keys
	@echo "Running protocol test suite..."
	@$(BIN_DIR)/protocol_demo --suite

# Performance testing
perf-simple: generate-keys
	@echo "Running simple performance test..."
	@chmod +x simple_performance_test.sh
	@./simple_performance_test.sh

perf-comprehensive: $(BIN_DIR)/comprehensive_tester generate-keys
	@echo "Running comprehensive performance analysis..."
	@echo "This will test all 144 algorithm combinations (15-30 minutes)"
	@echo "Use 'make perf-comprehensive-force' to run without confirmation"
	@$(BIN_DIR)/comprehensive_tester

perf-comprehensive-force: $(BIN_DIR)/comprehensive_tester generate-keys
	@echo "Running comprehensive performance analysis (forced)..."
	@$(BIN_DIR)/comprehensive_tester --force

perf-debug: $(BIN_DIR)/debug_tester generate-keys
	@echo "Running debug performance test..."
	@$(BIN_DIR)/debug_tester

# Research paper data generation
research-data: perf-comprehensive-force
	@echo "Generating research paper data..."
	@chmod +x comprehensive_test_runner.sh
	@./comprehensive_test_runner.sh

# Individual server/client runs (for manual testing)
run-bob: $(BIN_DIR)/bob_server generate-keys
	@echo "Starting Bob server..."
	@$(BIN_DIR)/bob_server

run-alice: $(BIN_DIR)/alice_client
	@echo "Starting Alice client..."
	@$(BIN_DIR)/alice_client

# Setup and maintenance
setup:
	@echo "Setting up hybrid TLS environment..."
	@chmod +x setup.sh
	@./setup.sh

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OBJ_DIR)/* $(BIN_DIR)/*
	@rm -f cpu_performance_results.txt tls_handshake_results.txt
	@rm -f research_appendix.txt
	@rm -f /tmp/qkd_keys.dat

clean-all: clean
	@echo "Cleaning all generated files..."
	@rm -f *.txt *.log
	@rm -f QKD_Scripts/__pycache__/*

# Development helpers
rebuild: clean all

check-deps:
	@echo "Checking dependencies..."
	@echo -n "LibOQS: "
	@pkg-config --exists oqs && echo "OK" || echo "MISSING"
	@echo -n "OpenSSL: "
	@pkg-config --exists openssl && echo "OK" || echo "MISSING"
	@echo -n "cJSON: "
	@pkg-config --exists libcjson && echo "OK" || echo "MISSING"
	@echo -n "Python3: "
	@python3 --version 2>/dev/null && echo "OK" || echo "MISSING"

install-deps:
	@echo "Installing dependencies..."
	@chmod +x setup.sh
	@./setup.sh

# Help target
help:
	@echo "Hybrid TLS Implementation - Build System"
	@echo "======================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  all                 - Build all components"
	@echo "  clean               - Clean build artifacts"
	@echo "  rebuild             - Clean and rebuild everything"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test-basic          - Run basic algorithm tests"
	@echo "  test-full           - Run full test suite (144 combinations)"
	@echo "  test-network        - Test Alice-Bob network communication"
	@echo "  demo                - Interactive protocol demonstration"
	@echo "  demo-quick          - Quick protocol demo"
	@echo ""
	@echo "Performance Targets:"
	@echo "  perf-simple         - Simple performance test"
	@echo "  perf-debug          - Debug performance test (6 combinations)"
	@echo "  perf-comprehensive  - Full performance analysis (144 combinations)"
	@echo "  research-data       - Generate IEEE publication data"
	@echo ""
	@echo "Individual Components:"
	@echo "  generate-keys       - Generate QKD keys"
	@echo "  run-bob             - Start Bob server"
	@echo "  run-alice           - Start Alice client"
	@echo ""
	@echo "Setup:"
	@echo "  setup               - Initial environment setup"
	@echo "  check-deps          - Check dependencies"
	@echo "  install-deps        - Install dependencies"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup          - First time setup"
	@echo "  make demo-quick     - Quick demonstration"
	@echo "  make test-network   - Test networking"
	@echo "  make perf-debug     - Debug performance test"

# Phony targets
.PHONY: all clean clean-all rebuild setup help check-deps install-deps
.PHONY: test-basic test-full test-network test-classical test-pqc test-qkd
.PHONY: demo demo-quick demo-suite generate-keys run-bob run-alice
.PHONY: perf-simple perf-comprehensive perf-comprehensive-force perf-debug
.PHONY: research-data directories