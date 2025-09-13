#!/bin/bash

# setup.sh - Hybrid TLS Project Setup Script

set -e  # Exit on any error

echo "=== Hybrid TLS Project Setup ==="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies on different systems
install_dependencies() {
    echo "Installing system dependencies..."
    
    if command_exists apt-get; then
        # Ubuntu/Debian
        echo "Detected Ubuntu/Debian system"
        sudo apt-get update
        sudo apt-get install -y build-essential cmake git
        sudo apt-get install -y libssl-dev libcjson-dev
        sudo apt-get install -y python3 python3-pip python3-dev
        pip3 install numpy --user
    elif command_exists yum; then
        # CentOS/RHEL/Fedora
        echo "Detected CentOS/RHEL/Fedora system"
        sudo yum install -y gcc gcc-c++ make cmake git
        sudo yum install -y openssl-devel libcjson-devel
        sudo yum install -y python3 python3-pip python3-devel
        pip3 install numpy --user
    elif command_exists brew; then
        # macOS
        echo "Detected macOS system"
        brew install openssl cjson cmake
        brew install python3
        pip3 install numpy
    else
        echo "Warning: Unknown system. Please install dependencies manually:"
        echo "  - build-essential (gcc, make, cmake)"
        echo "  - libssl-dev"
        echo "  - libcjson-dev"
        echo "  - python3 with numpy"
        echo "  - liboqs (see instructions below)"
    fi
}

# Function to install liboqs
install_liboqs() {
    echo "Installing liboqs..."
    
    if [ ! -d "liboqs" ]; then
        git clone https://github.com/open-quantum-safe/liboqs.git
    fi
    
    cd liboqs
    mkdir -p build
    cd build
    
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_ENABLE_KEM_ML_KEM=ON \
          -DOQS_ENABLE_KEM_HQC=ON \
          -DOQS_ENABLE_KEM_BIKE=ON \
          -DOQS_ENABLE_SIG_ML_DSA=ON \
          -DOQS_ENABLE_SIG_FALCON=ON \
          -DOQS_ENABLE_SIG_SPHINCS=ON ..
    
    make -j$(nproc)
    sudo make install
    sudo ldconfig
    
    cd ../..
    echo "liboqs installed successfully"
}

# Function to create directory structure
create_directories() {
    echo "Creating directory structure..."
    
    mkdir -p src
    mkdir -p obj
    mkdir -p bin  
    mkdir -p tests
    mkdir -p QKD_Scripts
    mkdir -p docs
    
    echo "Directory structure created"
}

# Function to create QKD script files
create_qkd_scripts() {
    echo "Creating QKD script files..."
    
    # Note: In actual implementation, you would copy your bb84_keygen.py, 
    # e91_keygen.py, and mdi_keygen.py files here
    
    cat > QKD_Scripts/bb84_keygen.py << 'EOF'
#!/usr/bin/env python3
# Placeholder for BB84 key generation script
# Replace with your actual bb84_keygen.py

import json
import sys

def main():
    # Mock implementation - replace with your actual code
    result = {
        "protocol": "BB84",
        "alice_key": "110100101001110",
        "bob_key": "110100101001110", 
        "key_length": 15,
        "qber": 0.023,
        "success": True,
        "distance_km": 10.0,
        "raw_bits": 1000,
        "sifted_bits": 156,
        "detection_rate": 0.6234
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
EOF

    cat > QKD_Scripts/e91_keygen.py << 'EOF'
#!/usr/bin/env python3  
# Placeholder for E91 key generation script
# Replace with your actual e91_keygen.py

import json
import sys

def main():
    # Mock implementation - replace with your actual code
    result = {
        "protocol": "E91",
        "alice_key": "1101001010",
        "bob_key": "1101001010",
        "key_length": 10,
        "qber": 0.0345,
        "bell_parameter": 2.248,
        "success": True,
        "distance_km": 10.0,
        "raw_pairs": 1000,
        "coincident_detections": 245,
        "sifted_bits": 87,
        "entanglement_fidelity": 0.92
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
EOF

    cat > QKD_Scripts/mdi_keygen.py << 'EOF'
#!/usr/bin/env python3
# Placeholder for MDI-QKD key generation script  
# Replace with your actual mdi_keygen.py

import json
import sys

def main():
    # Mock implementation - replace with your actual code
    result = {
        "protocol": "MDI-QKD",
        "alice_key": "110100101",
        "bob_key": "110100101",
        "key_length": 9,
        "qber": 0.0425,
        "bsm_success_rate": 0.1845,
        "success": True,
        "distance_km": 10.0,
        "raw_bits": 1000,
        "coincidences": 156,
        "successful_bsm": 29,
        "sifted_bits": 23,
        "charlie_efficiency": 0.85
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
EOF

    chmod +x QKD_Scripts/*.py
    echo "QKD script placeholders created"
}

# Function to verify installation
verify_installation() {
    echo "Verifying installation..."
    
    # Check for required libraries
    echo "Checking OpenSSL..."
    if pkg-config --exists openssl; then
        echo "  OpenSSL: OK"
    else
        echo "  OpenSSL: WARNING - not found via pkg-config"
    fi
    
    echo "Checking cJSON..."
    if pkg-config --exists libcjson; then
        echo "  cJSON: OK"
    elif [ -f "/usr/include/cjson/cJSON.h" ] || [ -f "/usr/local/include/cjson/cJSON.h" ]; then
        echo "  cJSON: OK"
    else
        echo "  cJSON: WARNING - not found"
    fi
    
    echo "Checking liboqs..."
    if [ -f "/usr/local/lib/liboqs.so" ] || [ -f "/usr/lib/liboqs.so" ]; then
        echo "  liboqs: OK"
    else
        echo "  liboqs: WARNING - not found"
    fi
    
    echo "Checking Python3..."
    if command_exists python3; then
        echo "  Python3: OK ($(python3 --version))"
    else
        echo "  Python3: ERROR - not found"
        return 1
    fi
    
    echo "Verification completed"
}

# Function to show next steps
show_next_steps() {
    echo ""
    echo "=== Setup Complete ==="
    echo ""
    echo "Project structure:"
    echo "  TLS_Approach/"
    echo "  ├── src/            # Source code"
    echo "  ├── QKD_Scripts/    # QKD key generation scripts"  
    echo "  ├── obj/            # Build objects"
    echo "  ├── bin/            # Executables"
    echo "  ├── tests/          # Test results"
    echo "  ├── stage.c         # QKD key management"
    echo "  └── Makefile        # Build system"
    echo ""
    echo "Next steps:"
    echo "1. Replace placeholder QKD scripts with your actual implementations:"
    echo "   - Copy your bb84_keygen.py to QKD_Scripts/"
    echo "   - Copy your e91_keygen.py to QKD_Scripts/"  
    echo "   - Copy your mdi_keygen.py to QKD_Scripts/"
    echo ""
    echo "2. Build the project:"
    echo "   make all"
    echo ""
    echo "3. Run basic tests:"
    echo "   make test"
    echo ""
    echo "4. Run full test suite:"
    echo "   make test-full"
    echo ""
    echo "5. Generate QKD keys and run tests:"
    echo "   make full-test"
    echo ""
    echo "For help: make help"
}

# Main setup process
main() {
    echo "Starting hybrid TLS project setup..."
    
    # Check if we're in the right directory
    if [ ! -f "stage.c" ]; then
        echo "Error: stage.c not found. Please run this script from the TLS_Approach directory."
        exit 1
    fi
    
    # Create directory structure
    create_directories
    
    # Install dependencies
    echo ""
    read -p "Install system dependencies? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_dependencies
    fi
    
    # Install liboqs
    echo ""
    read -p "Install liboqs library? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_liboqs
    fi
    
    # Create QKD script placeholders
    create_qkd_scripts
    
    # Verify installation
    echo ""
    verify_installation
    
    # Show next steps
    show_next_steps
    
    echo ""
    echo "Setup completed successfully!"
}

# Run main function
main "$@"