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
TEST_RUNNER_SRCS = $(SRCDIR)/test_runner.c $(SRCDIR)/config.c $(SRCDIR)/qkd_interface.c \
                   $(SRCDIR)/classical_crypto.c $(SRCDIR)/pqc_crypto.c $(SRCDIR)/mac_ops.c

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
.PHONY: clean test setup install-deps check-deps

# Clean build files
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	find . -name "*.o" -delete

# Setup directory structure
setup:
	mkdir -p $(SRCDIR) $(OBJDIR) $(BINDIR) tests QKD_Scripts

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
	@echo "LibOQS installation required separately. See: https://github.com/open-quantum-safe/liboqs"

# Run basic tests
test: $(TEST_RUNNER_TARGET)
	@echo "Running basic test suite..."
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

# Combined test (generate QKD keys then run tests)
full-test: $(STAGE_TARGET) $(TEST_RUNNER_TARGET)
	@echo "=== Step 1: Generating QKD Keys ==="
	./$(STAGE_TARGET)
	@echo "=== Step 2: Running Hybrid TLS Tests ==="
	./$(TEST_RUNNER_TARGET)

# Test single algorithm combination
test-single: $(TEST_RUNNER_TARGET)
	@echo "Running single test combination..."
	./$(TEST_RUNNER_TARGET) --single

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Performance profiling build
profile: CFLAGS += -pg -O2
profile: LDFLAGS += -pg
profile: clean $(STAGE_TARGET) $(TEST_RUNNER_TARGET)

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all --std=c99 $(SRCDIR)/*.c stage.c

# Memory check with Valgrind
memcheck: $(TEST_RUNNER_TARGET)
	@echo "Running memory check..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_RUNNER_TARGET)

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
stats: $(TEST_RUNNER_TARGET)
	@echo "=== Build Statistics ==="
	@echo "Source files: $(words $(TEST_RUNNER_SRCS)) + stage.c"
	@echo "Object files: $(words $(TEST_RUNNER_OBJS)) + stage.o"
	@echo "Executable size: $(du -h $(TEST_RUNNER_TARGET) | cut -f1)"
	@echo "Total lines of code: $(cat $(TEST_RUNNER_SRCS) stage.c | wc -l)"

# Help target
help:
	@echo "Hybrid TLS Makefile"
	@echo ""
	@echo "Build Targets:"
	@echo "  all         - Build all targets"
	@echo "  stage       - Build QKD key generator only"
	@echo "  test_runner - Build test framework only"
	@echo "  debug       - Build with debug symbols"
	@echo "  release     - Build optimized release"
	@echo "  profile     - Build with profiling enabled"
	@echo ""
	@echo "Test Targets:"
	@echo "  test        - Run basic test suite (3 tests)"
	@echo "  test-full   - Run full test suite (108 combinations)"
	@echo "  test-single - Run single test combination"
	@echo "  run-stage   - Generate QKD keys only"
	@echo "  full-test   - Generate keys and run tests"
	@echo ""
	@echo "Development Targets:"
	@echo "  check-deps  - Check if dependencies are installed"
	@echo "  install-deps- Install system dependencies"
	@echo "  analyze     - Run static analysis"
	@echo "  memcheck    - Run memory leak detection"
	@echo "  format      - Format source code"
	@echo "  docs        - Generate documentation"
	@echo "  stats       - Show build statistics"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean       - Clean build files"
	@echo "  setup       - Create directory structure"
	@echo "  help        - Show this help message"