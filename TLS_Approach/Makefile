# Makefile for Hybrid TLS Project
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
STAGE_SRC = stage.c
TEST_RUNNER_SRCS = $(SRCDIR)/test_runner.c $(SRCDIR)/config.c $(SRCDIR)/qkd_interface.c $(SRCDIR)/classical_crypto.c

# Object files
STAGE_OBJ = $(OBJDIR)/stage.o
TEST_RUNNER_OBJS = $(TEST_RUNNER_SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Targets
STAGE_TARGET = $(BINDIR)/stage
TEST_RUNNER_TARGET = $(BINDIR)/test_runner

# Default target
all: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Stage target (QKD key generation)
$(STAGE_TARGET): $(STAGE_OBJ)
	$(CC) $(STAGE_OBJ) -o $(STAGE_TARGET) $(LDFLAGS)

# Test runner target
$(TEST_RUNNER_TARGET): $(TEST_RUNNER_OBJS)
	$(CC) $(TEST_RUNNER_OBJS) -o $(TEST_RUNNER_TARGET) $(LDFLAGS)

# Object file rules
$(OBJDIR)/stage.o: stage.c
	$(CC) $(CFLAGS) -c stage.c -o $(OBJDIR)/stage.o

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets
.PHONY: clean test setup install-deps

# Clean build files
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	find . -name "*.o" -delete

# Setup directory structure
setup:
	mkdir -p $(SRCDIR) $(OBJDIR) $(BINDIR) tests QKD_Scripts

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libssl-dev libcjson-dev build-essential
	@echo "Installing liboqs..."
	@echo "Please follow liboqs installation instructions at: https://github.com/open-quantum-safe/liboqs"

# Run basic tests
test: $(TEST_RUNNER_TARGET)
	./$(TEST_RUNNER_TARGET)

# Run full test suite (all 108 combinations)
test-full: $(TEST_RUNNER_TARGET)
	./$(TEST_RUNNER_TARGET) --full

# Run QKD key generation
run-stage: $(STAGE_TARGET)
	./$(STAGE_TARGET)

# Combined test (generate QKD keys then run tests)
full-test: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)
	@echo "=== Step 1: Generating QKD Keys ==="
	./$(STAGE_TARGET)
	@echo "=== Step 2: Running Hybrid TLS Tests ==="
	./$(TEST_RUNNER_TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Help target
help:
	@echo "Hybrid TLS Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all targets"
	@echo "  stage       - Build QKD key generator"
	@echo "  test_runner - Build test framework"
	@echo "  test        - Run basic test suite"
	@echo "  test-full   - Run full test suite (108 combinations)"
	@echo "  run-stage   - Generate QKD keys"
	@echo "  full-test   - Generate keys and run tests"
	@echo "  clean       - Clean build files"
	@echo "  setup       - Create directory structure"
	@echo "  install-deps- Install system dependencies"
	@echo "  debug       - Build with debug symbols"
	@echo "  release     - Build optimized release"
	@echo "  help        - Show this help message"