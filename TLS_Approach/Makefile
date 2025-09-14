# Makefile for Hybrid TLS Project with Protocol Implementation
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

# Targets
STAGE_TARGET = $(BINDIR)/stage
TEST_RUNNER_TARGET = $(BINDIR)/test_runner
PROTOCOL_DEMO_TARGET = $(BINDIR)/protocol_demo

# Default target - build all
all: $(STAGE_TARGET) $(TEST_RUNNER_TARGET) $(PROTOCOL_DEMO_TARGET)

# Stage target (QKD key generation)
$(STAGE_TARGET): $(STAGE_OBJS)
	$(CC) $(STAGE_OBJS) -o $(STAGE_TARGET) $(LDFLAGS)

# Test runner target (crypto foundation tests)
$(TEST_RUNNER_TARGET): $(TEST_RUNNER_OBJS)
	$(CC) $(TEST_RUNNER_OBJS) -o $(TEST_RUNNER_TARGET) $(LDFLAGS)

# Protocol demo target (complete hybrid TLS implementation)
$(PROTOCOL_DEMO_TARGET): $(PROTOCOL_OBJS)
	$(CC) $(PROTOCOL_OBJS) -o $(PROTOCOL_DEMO_TARGET) $(LDFLAGS)

# Object file rules
$(OBJDIR)/stage.o: stage.c
	$(CC) $(CFLAGS) -c stage.c -o $(OBJDIR)/stage.o

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets
.PHONY: clean test setup install-deps check-deps protocol-test

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

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean all

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean all

# Help target
help:
	@echo "Hybrid TLS Makefile - Protocol Implementation"
	@echo ""
	@echo "Build Targets:"
	@echo "  all              - Build all targets (stage + test_runner + protocol_demo)"
	@echo "  protocol-demo    - Build and run hybrid TLS protocol demonstration"
	@echo "  protocol-quick   - Run quick protocol demo (single config)"
	@echo "  protocol-suite   - Run protocol test suite (multiple configs)"
	@echo "  protocol-benchmark - Run protocol performance benchmark"
	@echo "  complete-test    - Generate QKD keys + run protocol demo"
	@echo ""
	@echo "Quick Start:"
	@echo "  make all && make complete-test"