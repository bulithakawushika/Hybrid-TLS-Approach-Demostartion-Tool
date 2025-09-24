# 🔐 Hybrid TLS with Quantum Key Distribution (QKD) and PQC – Protocol Suite Evaluation

This repository provides a demo implementation and evaluation of 144 hybrid TLS protocol suites that integrate Quantum Key Distribution (QKD), Post-Quantum Cryptography (PQC), and Elliptic Curve Cryptography (ECC).

It extends the QKD Protocol Simulation with NetSquid by incorporating a server–client architecture for testing QKD-assisted TLS handshakes, focusing on key management, hybrid cryptographic integration, and realistic physical-layer modeling.

## 🎯 Research Motivation

The rise of quantum computing threatens classical public-key cryptosystems such as RSA and ECC. While PQC algorithms provide resistance against quantum adversaries, Quantum Key Distribution (QKD) offers information-theoretic security by using the laws of quantum mechanics.

This project aims to combine QKD, PQC, and ECC in a hybrid TLS architecture, evaluating the performance and security trade-offs of 144 distinct protocol suites.

## 🗂 Repository Overview

| Component | Description |
|-----------|-------------|
| QKD Simulation | BB84, E91, and MDI-QKD protocols implemented with NetSquid, modeling fiber noise, depolarization, and detector inefficiencies. |
| Server–Client Framework | Python-based TLS testbed that negotiates hybrid key exchanges and digital signatures across 144 protocol suites. |
| Key Management Module (KMM) | Periodic QKD key generation, storage, reuse, and integration into the TLS handshake. |
| Performance Evaluation | Scripts for measuring latency, throughput, Quantum Bit Error Rate (QBER), and TLS handshake success across protocols. |

## ⚙️ Technical Details

### 1. QKD Channel Simulation

- **Simulator:** NetSquid 1.1.1
- **Models Used:**
  - Fiber loss: 0.1 dB connector loss + 0.2 dB/km attenuation
  - Fiber delay: Speed of light in fiber ≈ 1.9 × 10⁵ km/s
  - Depolarization noise: 0.008 per qubit
  - Detector efficiency: 85% with 1.5% bit error probability
- **Protocols Implemented:** BB84, E91, and MDI-QKD
- **Channel Setup:** 10 km optical fiber between nodes

### 2. Hybrid TLS Implementation

**Classical ECC Algorithms:**
- ECDHE P-256
- X25519
- Signatures: ECDSA P-256, Ed25519

**Post-Quantum Cryptography (PQC):**
- Key Encapsulation: ML-KEM-768, HQC-192, BIKE-L3
- Signatures: ML-DSA-65, Falcon-512, SPHINCS+ (SHA2-192f-simple, SHAKE-192f-simple)
- **Excluded Algorithms:** RSA (quantum vulnerable), Rainbow & SIDH (broken), Classic McEliece (impractical size)

### 3. QKD Key Management Module (KMM)

- Periodic QKD key generation with retention policy (~3h)
- Keys stored with UUIDs (derived from SHA-256 hash)
- Reuse mechanism to reduce overhead in repeated connections
- SHA3-512 hashing to standardize variable-length QKD keys
- Integrated with TLS handshake via Get_Key and Get_Key_With_KeyID APIs
- Replay protection with timestamps and revocation
- White Rabbit (WR) time protocol for synchronization

## 🏗️ Hybrid TLS Handshake Architecture

- TLS handshake integrates ECC, PQC, and QKD-derived keys
- **Final session key derived as:**

```
Kfinal = HMAC(Kclassical ⊕ Kpqc ⊕ Kqkd, v)
```

**Where:**
- `Kclassical` → ECC shared secret
- `Kpqc` → PQC shared secret
- `Kqkd` → QKD-derived key
- `v` → Binding string (includes public keys, ciphertext, UUID)

- Poly1305 HMAC ensures message integrity and authenticity
- Dual digital signatures (ECC + PQC) required for authentication
- Replay attack prevention via timestamp and KMM-based key revocation

## 🧩 Protocol Suite Combinations

Using the above primitives, we constructed 144 hybrid TLS protocol suites:

- 2 × ECC Key Exchange (P-256, X25519)
- 2 × ECC Signatures (ECDSA, Ed25519)
- 3 × PQC Key Encapsulation (ML-KEM-768, HQC-192, BIKE-L3)
- 4 × PQC Signatures (ML-DSA-65, Falcon-512, SPHINCS+ SHA2, SPHINCS+ SHAKE)
- 3 × QKD Protocols (BB84, E91, MDI-QKD)

**→ 2 × 2 × 3 × 4 × 3 = 144 possible TLS configurations**

## 📊 Performance Metrics

| Metric | Description |
|--------|-------------|
| QBER (%) | Detects eavesdropping & channel quality |
| Handshake Latency (ms) | Time to complete TLS negotiation |
| Throughput (Mbps) | Secure channel performance |
| Key Retention Efficiency | Impact of reusing QKD keys |
| Failure Rate | Handshake retries due to expired/mismatched QKD keys |

## 🚀 Getting Started

### Prerequisites

- Python 3.x
- netsquid 1.1.1
- openssl 3.4.1
- liboqs 0.14.0

### Run Demo (Server–Client)

```bash
# Start server
python server.py --suite BB84+ML-KEM-768+Falcon-512+X25519

# Start client
python client.py --suite BB84+ML-KEM-768+Falcon-512+X25519
```

### Run Full Evaluation (All 144 Suites)

```bash
python evaluate_all.py
```

Results (latency, QBER, handshake success) will be logged in `/results/`.

## 🔬 Research Contribution

This work demonstrates:

- Integration of QKD protocols into TLS with PQC & ECC
- 144 hybrid protocol suite evaluation
- Realistic modeling of quantum channels with NetSquid
- A modular KMM design for periodic key reuse
- Performance–security trade-offs in hybrid post-quantum TLS

## 🔒 License

This project is licensed under the MIT License – see the LICENSE file for details.

## 📚 References

- [NetSquid Documentation](https://netsquid.org/)
- [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- Ekert, A. (1991). Quantum Cryptography Based on Bell's Theorem.
- Lo, H.-K. et al. (2012). Measurement-Device-Independent QKD.
- [ResearchGate – Comprehensive Study of BB84 Protocol](https://www.researchgate.net/)
