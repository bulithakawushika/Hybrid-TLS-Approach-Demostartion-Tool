# Hybrid TLS Protocol Implementation Makefile

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g -Isrc
LDFLAGS = -lssl -lcrypto -loqs -lcjson -lm

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
QKD_DIR = QKD_Scripts

# Source files
COMMON_SOURCES = $(SRC_DIR)/config.c \
                 $(SRC_DIR)/classical_crypto.c \
                 $(SRC_DIR)/pqc_crypto.c \
                 $(SRC_DIR)/qkd_interface.c \
                 $(SRC_DIR)/qkd_data.c \
                 $(SRC_DIR)/mac_ops.c \
                 $(SRC_DIR)/hybrid_tls_protocol.c \
                 $(SRC_DIR)/network_protocol.c

STAGE_SOURCES = stage.c $(SRC_DIR)/qkd_data.c
TEST_SOURCES = $(SRC_DIR)/test_runner.c $(COMMON_SOURCES)
DEMO_SOURCES = $(SRC_DIR)/protocol_demo.c $(COMMON_SOURCES)
ALICE_SOURCES = $(SRC_DIR)/alice_client.c $(COMMON_SOURCES)
BOB_SOURCES = $(SRC_DIR)/bob_server.c $(COMMON_SOURCES)
COMPREHENSIVE_SOURCES = $(SRC_DIR)/comprehensive_tester.c $(COMMON_SOURCES)

# Object files
COMMON_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(COMMON_SOURCES))
STAGE_OBJECTS = $(OBJ_DIR)/stage.o $(OBJ_DIR)/qkd_data.o
TEST_OBJECTS = $(OBJ_DIR)/test_runner.o $(COMMON_OBJECTS)
DEMO_OBJECTS = $(OBJ_DIR)/protocol_demo.o $(COMMON_OBJECTS)
ALICE_OBJECTS = $(OBJ_DIR)/alice_client.o $(COMMON_OBJECTS)
BOB_OBJECTS = $(OBJ_DIR)/bob_server.o $(COMMON_OBJECTS)
COMPREHENSIVE_OBJECTS = $(OBJ_DIR)/comprehensive_tester.o $(COMMON_OBJECTS)

# Target executables
TARGETS = $(BIN_DIR)/stage \
          $(BIN_DIR)/test_runner \
          $(BIN_DIR)/protocol_demo \
          $(BIN_DIR)/alice_client \
          $(BIN_DIR)/bob_server \
          $(BIN_DIR)/comprehensive_tester

# Default target
all: directories $(TARGETS)

# Create directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Stage executable (QKD key generation)
$(BIN_DIR)/stage: $(STAGE_OBJECTS)
	@echo "Linking stage..."
	$(CC) $(STAGE_OBJECTS) -o $@ $(LDFLAGS)

# Test runner executable
$(BIN_DIR)/test_runner: $(TEST_OBJECTS)
	@echo "Linking test_runner..."
	$(CC) $(TEST_OBJECTS) -o $@ $(LDFLAGS)

# Protocol demo executable
$(BIN_DIR)/protocol_demo: $(DEMO_OBJECTS)
	@echo "Linking protocol_demo..."
	$(CC) $(DEMO_OBJECTS) -o $@ $(LDFLAGS)

# Alice client executable
$(BIN_DIR)/alice_client: $(ALICE_OBJECTS)
	@echo "Linking alice_client..."
	$(CC) $(ALICE_OBJECTS) -o $@ $(LDFLAGS)

# Bob server executable  
$(BIN_DIR)/bob_server: $(BOB_OBJECTS)
	@echo "Linking bob_server..."
	$(CC) $(BOB_OBJECTS) -o $@ $(LDFLAGS)

# Comprehensive performance tester executable
$(BIN_DIR)/comprehensive_tester: $(COMPREHENSIVE_OBJECTS)
	@echo "Linking comprehensive_tester..."
	$(CC) $(COMPREHENSIVE_OBJECTS) -o $@ $(LDFLAGS)

# Object file compilation rules
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/stage.o: stage.c
	@echo "Compiling stage.c..."
	$(CC) $(CFLAGS) -c stage.c -o $@

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	rm -f cpu_performance_results.txt tls_handshake_results.txt research_appendix.txt

# Individual targets
stage: directories $(BIN_DIR)/stage
test: directories $(BIN_DIR)/test_runner
demo: directories $(BIN_DIR)/protocol_demo
alice: directories $(BIN_DIR)/alice_client  
bob: directories $(BIN_DIR)/bob_server
comprehensive: directories $(BIN_DIR)/comprehensive_tester

# Test targets
test-basic: $(BIN_DIR)/test_runner
	@echo "Running basic tests..."
	./$(BIN_DIR)/test_runner

test-full: $(BIN_DIR)/test_runner
	@echo "Running full test suite..."
	./$(BIN_DIR)/test_runner --full

# Demo targets
demo-quick: $(BIN_DIR)/protocol_demo
	@echo "Running quick demo..."
	./$(BIN_DIR)/protocol_demo --quick

demo-suite: $(BIN_DIR)/protocol_demo
	@echo "Running demo suite..."
	./$(BIN_DIR)/protocol_demo --suite

# QKD key generation
generate-keys: $(BIN_DIR)/stage
	@echo "=== Generating QKD keys ==="
	@echo "This will generate BB84, E91, and MDI-QKD keys..."
	./$(BIN_DIR)/stage --non-blocking

# Network demo (requires two terminals)
run-bob: $(BIN_DIR)/bob_server generate-keys
	@echo "Starting Bob server..."
	./$(BIN_DIR)/bob_server

run-alice: $(BIN_DIR)/alice_client
	@echo "Starting Alice client..."
	./$(BIN_DIR)/alice_client

# Full network test with proper setup
network-test: $(BIN_DIR)/bob_server $(BIN_DIR)/alice_client
	@echo "Running network test using dedicated script..."
	@chmod +x run_network_test.sh 2>/dev/null || true
	@./run_network_test.sh

# Research-grade performance testing
research-test: $(BIN_DIR)/comprehensive_tester generate-keys
	@echo "=== Running Research-Grade Performance Testing ==="
	@chmod +x comprehensive_test_runner.sh 2>/dev/null || true
	@if [ -f comprehensive_test_runner.sh ]; then \
		./comprehensive_test_runner.sh; \
	else \
		echo "comprehensive_test_runner.sh not found. Running comprehensive tester directly..."; \
		./$(BIN_DIR)/comprehensive_tester; \
	fi

# Quick performance sample (subset for development)
quick-performance: $(BIN_DIR)/comprehensive_tester generate-keys
	@echo "=== Running Quick Performance Sample ==="
	@echo "Testing subset of combinations for development validation..."
	@./$(BIN_DIR)/comprehensive_tester 2>/dev/null || echo "Note: comprehensive_tester needs to be implemented with --quick option"

# Full research suite (all 144 combinations × 10 iterations)
full-research: $(BIN_DIR)/comprehensive_tester generate-keys
	@echo "=== Running Full Research Suite ==="
	@echo "WARNING: This will take several hours to complete"
	@echo "Running 144 combinations × 10 iterations each"
	@read -p "Continue? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@if [ -f comprehensive_test_runner.sh ]; then \
		chmod +x comprehensive_test_runner.sh; \
		./comprehensive_test_runner.sh; \
	else \
		./$(BIN_DIR)/comprehensive_tester; \
	fi

# Quick test to verify QKD key generation works
test-qkd: $(BIN_DIR)/stage
	@echo "=== Testing QKD Key Generation ==="
	./$(BIN_DIR)/stage --non-blocking

# Complete test suite
test-all: test-basic demo-quick network-test
	@echo "=== All Tests Completed ==="

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential cmake git
	sudo apt-get install -y libssl-dev libcjson-dev
	sudo apt-get install -y python3 python3-pip python3-dev
	pip3 install numpy --user

# Quick setup for first-time users
setup: install-deps all generate-keys
	@echo "=== Setup Complete ==="
	@echo "You can now run:"
	@echo "  make network-test    # Full network test"
	@echo "  make demo-quick      # Protocol demonstration"
	@echo "  make test-basic      # Basic crypto tests"
	@echo "  make research-test   # Research-grade performance testing"

# Help target
help:
	@echo "Hybrid TLS Protocol Build System"
	@echo "Available targets:"
	@echo ""
	@echo "Build Targets:"
	@echo "  all          - Build all executables"
	@echo "  stage        - Build QKD key generation stage"
	@echo "  test_runner  - Build test framework"  
	@echo "  protocol_demo- Build protocol demonstration"
	@echo "  alice_client - Build Alice client"
	@echo "  bob_server   - Build Bob server"
	@echo "  comprehensive- Build comprehensive performance tester"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Basic Testing:"
	@echo "  generate-keys- Generate QKD keys (required first step)"
	@echo "  test-basic   - Run basic cryptographic tests"
	@echo "  demo-quick   - Run quick protocol demo"
	@echo "  network-test - Run complete network test (Alice + Bob)"
	@echo ""
	@echo "Research-Grade Performance Testing:"
	@echo "  research-test - Run comprehensive performance analysis (IEEE quality)"
	@echo "  full-research - Run complete 144×10 test suite (several hours)"
	@echo "  quick-performance - Run performance sample (subset of combinations)"
	@echo ""
	@echo "Manual Operations:"
	@echo "  run-bob      - Start Bob server (separate terminal)"
	@echo "  run-alice    - Start Alice client (separate terminal)"
	@echo "  setup        - Complete first-time setup"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Research Notes:"
	@echo "  • research-test generates IEEE publication-quality data"
	@echo "  • Results saved to cpu_performance_results.txt and tls_handshake_results.txt"
	@echo "  • 144 algorithm combinations with 10 iterations each"
	@echo "  • Statistical analysis with mean and standard deviation"
	@echo "  • Ranked results from best to worst performance"

# Phony targets
.PHONY: all clean help directories stage test demo alice bob comprehensive
.PHONY: test-basic test-full demo-quick demo-suite generate-keys
.PHONY: run-bob run-alice network-test test-qkd test-all setup install-deps
.PHONY: research-test full-research quick-performance