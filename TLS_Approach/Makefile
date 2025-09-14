# Makefile for Hybrid TLS Project with Network Implementation
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g -Isrc
LDFLAGS = -lssl -lcrypto -loqs -lcjson -lm

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Create directories if they don't exist
$(shell mkdir -p $(OBJDIR) $(BINDIR))

# Source files
STAGE_SRCS = stage.c $(SRCDIR)/qkd_data.c
TEST_RUNNER_SRCS = $(SRCDIR)/test_runner.c $(SRCDIR)/config.c $(SRCDIR)/qkd_interface.c \
                   $(SRCDIR)/classical_crypto.c $(SRCDIR)/pqc_crypto.c $(SRCDIR)/mac_ops.c \
                   $(SRCDIR)/qkd_data.c

# Protocol implementation sources
PROTOCOL_SRCS = $(SRCDIR)/hybrid_tls_protocol.c $(SRCDIR)/protocol_demo.c $(SRCDIR)/config.c \
                $(SRCDIR)/qkd_interface.c $(SRCDIR)/classical_crypto.c $(SRCDIR)/pqc_crypto.c \
                $(SRCDIR)/mac_ops.c $(SRCDIR)/qkd_data.c

# Object files
STAGE_OBJS = $(OBJDIR)/stage.o $(OBJDIR)/qkd_data.o
TEST_RUNNER_OBJS = $(OBJDIR)/test_runner.o $(OBJDIR)/config.o $(OBJDIR)/qkd_interface.o \
                   $(OBJDIR)/classical_crypto.o $(OBJDIR)/pqc_crypto.o $(OBJDIR)/mac_ops.o \
                   $(OBJDIR)/qkd_data.o
PROTOCOL_OBJS = $(OBJDIR)/hybrid_tls_protocol.o $(OBJDIR)/protocol_demo.o $(OBJDIR)/config.o \
                $(OBJDIR)/qkd_interface.o $(OBJDIR)/classical_crypto.o $(OBJDIR)/pqc_crypto.o \
                $(OBJDIR)/mac_ops.o $(OBJDIR)/qkd_data.o

# Network program object files
ALICE_OBJS = $(OBJDIR)/alice_client.o $(OBJDIR)/network_protocol.o $(OBJDIR)/hybrid_tls_protocol.o \
             $(OBJDIR)/config.o $(OBJDIR)/qkd_interface.o $(OBJDIR)/classical_crypto.o \
             $(OBJDIR)/pqc_crypto.o $(OBJDIR)/mac_ops.o $(OBJDIR)/qkd_data.o

BOB_OBJS = $(OBJDIR)/bob_server.o $(OBJDIR)/network_protocol.o $(OBJDIR)/hybrid_tls_protocol.o \
           $(OBJDIR)/config.o $(OBJDIR)/qkd_interface.o $(OBJDIR)/classical_crypto.o \
           $(OBJDIR)/pqc_crypto.o $(OBJDIR)/mac_ops.o $(OBJDIR)/qkd_data.o

# Targets
STAGE_TARGET = $(BINDIR)/stage
TEST_RUNNER_TARGET = $(BINDIR)/test_runner
PROTOCOL_DEMO_TARGET = $(BINDIR)/protocol_demo
ALICE_CLIENT_TARGET = $(BINDIR)/alice_client
BOB_SERVER_TARGET = $(BINDIR)/bob_server

# Default target - build all
all: $(STAGE_TARGET) $(TEST_RUNNER_TARGET) $(PROTOCOL_DEMO_TARGET) $(ALICE_CLIENT_TARGET) $(BOB_SERVER_TARGET)

# Stage target (QKD key generation)
$(STAGE_TARGET): $(STAGE_OBJS)
	$(CC) $(STAGE_OBJS) -o $(STAGE_TARGET) $(LDFLAGS)

# Test runner target (crypto foundation tests)
$(TEST_RUNNER_TARGET): $(TEST_RUNNER_OBJS)
	$(CC) $(TEST_RUNNER_OBJS) -o $(TEST_RUNNER_TARGET) $(LDFLAGS)

# Protocol demo target (complete hybrid TLS implementation)
$(PROTOCOL_DEMO_TARGET): $(PROTOCOL_OBJS)
	$(CC) $(PROTOCOL_OBJS) -o $(PROTOCOL_DEMO_TARGET) $(LDFLAGS)

# Alice client target (network TLS client)
$(ALICE_CLIENT_TARGET): $(ALICE_OBJS)
	$(CC) $(ALICE_OBJS) -o $(ALICE_CLIENT_TARGET) $(LDFLAGS)

# Bob server target (network TLS server)
$(BOB_SERVER_TARGET): $(BOB_OBJS)
	$(CC) $(BOB_OBJS) -o $(BOB_SERVER_TARGET) $(LDFLAGS)

# Object file rules
$(OBJDIR)/stage.o: stage.c
	$(CC) $(CFLAGS) -c stage.c -o $(OBJDIR)/stage.o

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets
.PHONY: clean test setup install-deps check-deps protocol-test network-demo start-bob start-alice

# Clean build files
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	find . -name "*.o" -delete

# Setup directory structure and copy new files
setup:
	mkdir -p $(SRCDIR) $(OBJDIR) $(BINDIR) tests QKD_Scripts
	@echo "Directory structure created."

# Check if dependencies are installed
check-deps:
	@echo "Checking dependencies..."
	@echo -n "OpenSSL: "
	@pkg-config --exists openssl && echo "OK" || echo "MISSING"
	@echo -n "cJSON: "
	@pkg-config --exists libcjson && echo "OK" || echo "MISSING"
	@echo -n "LibOQS: "
	@test -f /usr/local/lib/liboqs.so && echo "OK" || echo "MISSING"
	@echo -n "GCC: "
	@which gcc >/dev/null && echo "OK" || echo "MISSING"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libssl-dev libcjson-dev build-essential cmake git
	sudo apt-get install -y python3 python3-pip python3-dev
	pip3 install numpy --user

# Run basic crypto tests
test: $(TEST_RUNNER_TARGET)
	@echo "Running basic crypto foundation tests..."
	./$(TEST_RUNNER_TARGET)

# Run full test suite (all 108 combinations)
test-full: $(TEST_RUNNER_TARGET)
	@echo "Running full test suite (108 combinations)..."
	@echo "Warning: This will take significant time!"
	./$(TEST_RUNNER_TARGET) --full

# Run QKD key generation
run-stage: $(STAGE_TARGET)
	@echo "Running QKD key generation..."
	./$(STAGE_TARGET)

# Run protocol demonstration
protocol-demo: $(PROTOCOL_DEMO_TARGET)
	@echo "Running Hybrid TLS Protocol Demo..."
	./$(PROTOCOL_DEMO_TARGET)

# Quick protocol demo
protocol-quick: $(PROTOCOL_DEMO_TARGET)
	@echo "Running quick protocol demo..."
	./$(PROTOCOL_DEMO_TARGET) --quick

# Protocol test suite
protocol-suite: $(PROTOCOL_DEMO_TARGET)
	@echo "Running protocol test suite..."
	./$(PROTOCOL_DEMO_TARGET) --suite

# Protocol performance benchmark
protocol-benchmark: $(PROTOCOL_DEMO_TARGET)
	@echo "Running protocol performance benchmark..."
	./$(PROTOCOL_DEMO_TARGET) --benchmark

# Combined test (generate QKD keys then run crypto tests)
full-test: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)
	@echo "=== Step 1: Generating QKD Keys ==="
	./$(STAGE_TARGET)
	@echo "=== Step 2: Running Hybrid TLS Tests ==="
	./$(TEST_RUNNER_TARGET)

# Complete protocol test (QKD + Protocol Demo)
complete-test: $(STAGE_TARGET) $(PROTOCOL_DEMO_TARGET)
	@echo "=== Step 1: Generating QKD Keys ==="
	./$(STAGE_TARGET)
	@echo "=== Step 2: Running Protocol Demonstration ==="
	./$(PROTOCOL_DEMO_TARGET) --quick

# Network demo targets
network-demo: $(BOB_SERVER_TARGET) $(ALICE_CLIENT_TARGET)
	@echo "=== Network TLS Demo Setup ==="
	@echo "Run the following commands in separate terminals:"
	@echo "Terminal 1: make start-bob"
	@echo "Terminal 2: make start-alice"
	@echo ""
	@echo "Or run the automated demo:"
	@echo "make network-test"

# Start Bob server
start-bob: $(BOB_SERVER_TARGET)
	@echo "Starting Bob (TLS Server) on port 8081..."
	./$(BOB_SERVER_TARGET) 8081

# Start Alice client
start-alice: $(ALICE_CLIENT_TARGET)
	@echo "Starting Alice (TLS Client) connecting to localhost:8081..."
	sleep 2
	./$(ALICE_CLIENT_TARGET) 127.0.0.1 8081 8080

# Automated network test (runs both in background)
network-test: $(BOB_SERVER_TARGET) $(ALICE_CLIENT_TARGET)
	@echo "=== Automated Network TLS Test ==="
	@echo "Starting Bob server in background..."
	./$(BOB_SERVER_TARGET) 8081 &
	@sleep 3
	@echo "Starting Alice client..."
	./$(ALICE_CLIENT_TARGET) 127.0.0.1 8081 8080
	@echo "Stopping background processes..."
	@pkill -f bob_server || true

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean all

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean all

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all --std=c99 $(SRCDIR)/*.c stage.c

# Memory check with Valgrind
memcheck: $(PROTOCOL_DEMO_TARGET)
	@echo "Running memory check on protocol demo..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(PROTOCOL_DEMO_TARGET) --quick

# Generate documentation
docs:
	@echo "Generating documentation..."
	doxygen Doxyfile 2>/dev/null || echo "Doxygen not installed"

# Code formatting
format:
	@echo "Formatting code..."
	find $(SRCDIR) -name "*.c" -o -name "*.h" | xargs clang-format -i 2>/dev/null || echo "clang-format not installed"
	clang-format -i stage.c 2>/dev/null || echo "clang-format not installed"

# Show build statistics
stats: $(PROTOCOL_DEMO_TARGET)
	@echo "=== Build Statistics ==="
	@echo "Protocol demo size: $(shell du -h $(PROTOCOL_DEMO_TARGET) 2>/dev/null | cut -f1 || echo 'N/A')"
	@echo "Alice client size: $(shell du -h $(ALICE_CLIENT_TARGET) 2>/dev/null | cut -f1 || echo 'N/A')"
	@echo "Bob server size: $(shell du -h $(BOB_SERVER_TARGET) 2>/dev/null | cut -f1 || echo 'N/A')"

# Help target
help:
	@echo "Hybrid TLS Makefile - Complete Implementation"
	@echo ""
	@echo "Build Targets:"
	@echo "  all              - Build all programs"
	@echo "  clean            - Clean build files"
	@echo ""
	@echo "Single Process Demo:"
	@echo "  protocol-quick   - Quick protocol demo"
	@echo "  complete-test    - Generate QKD keys + run protocol demo"
	@echo ""
	@echo "Network Demo (Client-Server):"
	@echo "  network-demo     - Show instructions for manual network demo"
	@echo "  start-bob        - Start Bob TLS server (port 8081)"
	@echo "  start-alice      - Start Alice TLS client"
	@echo "  network-test     - Automated network test (both processes)"
	@echo ""
	@echo "Development:"
	@echo "  debug            - Build with debug symbols"
	@echo "  analyze          - Run static analysis"
	@echo "  memcheck         - Run memory leak detection"
	@echo ""
	@echo "Quick Start:"
	@echo "  make all && make complete-test    # Single process demo"
	@echo "  make all && make network-test     # Network demo"