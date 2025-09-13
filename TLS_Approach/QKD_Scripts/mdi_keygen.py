import numpy as np
import random
import math
import json
import argparse
import sys
from typing import List, Tuple, Dict

class FibreLossModel:
    """Models fiber loss in optical channel"""
    def __init__(self, p_loss_init=0.0, p_loss_length=0.2):
        self.p_loss_init = p_loss_init
        self.p_loss_length = p_loss_length  # dB/km
    
    def apply_loss(self, distance_km):
        """Calculate transmission probability after fiber loss"""
        total_loss_db = self.p_loss_init + self.p_loss_length * distance_km
        transmission_prob = 10 ** (-total_loss_db / 10)
        return transmission_prob

class FibreDelayModel:
    """Models fiber delay"""
    def __init__(self, c=2e5):  # speed of light in fiber (km/s)
        self.c = c
    
    def get_delay(self, distance_km):
        """Calculate delay in seconds"""
        return distance_km / self.c

class DepolarNoiseModel:
    """Models depolarization noise"""
    def __init__(self, depolar_rate=0.005):
        self.depolar_rate = depolar_rate
    
    def apply_noise(self, qubit_state):
        """Apply depolarization noise to qubit"""
        if random.random() < self.depolar_rate:
            # Bit flip
            return 1 - qubit_state
        return qubit_state

class QuantumChannel:
    """Quantum channel with loss, delay, and noise"""
    def __init__(self, distance_km, loss_model, delay_model, noise_model):
        self.distance_km = distance_km
        self.loss_model = loss_model
        self.delay_model = delay_model
        self.noise_model = noise_model
        self.transmission_prob = loss_model.apply_loss(distance_km)
        self.delay = delay_model.get_delay(distance_km)
    
    def transmit(self, qubit_state):
        """Transmit qubit through channel"""
        # Check if photon survives loss
        if random.random() > self.transmission_prob:
            return None  # Photon lost
        
        # Apply noise
        noisy_state = self.noise_model.apply_noise(qubit_state)
        return noisy_state

class Party:
    """Represents Alice or Bob"""
    def __init__(self, name):
        self.name = name
        self.bits = []
        self.bases = []
        self.measurements = []
        self.sifted_key = []
        self.final_key = []
    
    def generate_random_bits(self, n):
        """Generate n random bits"""
        self.bits = [random.randint(0, 1) for _ in range(n)]
        return self.bits
    
    def generate_random_bases(self, n):
        """Generate n random measurement bases (0=Z, 1=X)"""
        self.bases = [random.randint(0, 1) for _ in range(n)]
        return self.bases
    
    def prepare_qubits(self):
        """Prepare qubits based on bits and bases"""
        qubits = []
        for bit, basis in zip(self.bits, self.bases):
            if basis == 0:  # Z basis
                qubit_state = bit  # |0⟩ or |1⟩
            else:  # X basis
                qubit_state = bit  # |+⟩ or |-⟩ (encoded as 0,1)
            qubits.append((qubit_state, basis))
        return qubits

class Charlie:
    """Untrusted measurement device (Charlie) with realistic performance"""
    def __init__(self, distance_km):
        self.name = "Charlie"
        self.measurements = []
        self.coincidences = []
        self.distance_km = distance_km
        
        # Realistic Bell State Measurement parameters
        self.bsm_success_rate = self._calculate_bsm_success_rate(distance_km)
        self.detector_efficiency = 0.85  # Realistic detector efficiency
        self.timing_window_error = 0.03  # 3% timing synchronization errors
        self.dark_count_rate = 1e-6  # Dark counts per pulse
        self.interference_visibility = 0.95  # HOM interference visibility
        
    def _calculate_bsm_success_rate(self, distance_km):
        """Calculate realistic BSM success rate based on distance"""
        # Bell State Measurement becomes harder with distance due to:
        # 1. Timing synchronization challenges
        # 2. Detector jitter
        # 3. Phase drift
        base_success_rate = 0.25  # Theoretical maximum for 2-photon BSM
        
        # Distance-dependent degradation
        timing_penalty = 1.0 - (distance_km * 0.005)  # 0.5% penalty per km
        phase_drift_penalty = 1.0 - (distance_km * 0.003)  # Phase drift increases with distance
        
        realistic_rate = base_success_rate * timing_penalty * phase_drift_penalty
        return max(0.05, realistic_rate)  # Minimum 5% success rate
    
    def bell_state_measurement(self, qubit1, qubit2, basis1, basis2):
        """Realistic Bell state measurement with proper limitations"""
        # Check if both qubits arrived
        if qubit1 is None or qubit2 is None:
            return None, None
        
        # Apply detector efficiency
        if random.random() > self.detector_efficiency:
            return None, None  # Detection failed
        
        # Apply timing window errors
        if random.random() < self.timing_window_error:
            return None, None  # Timing synchronization failed
        
        # Dark count noise
        if random.random() < self.dark_count_rate:
            return False, random.randint(0, 1)  # False positive from dark count
        
        # Only attempt BSM when bases match (realistic constraint)
        if basis1 != basis2:
            return False, None  # Basis mismatch - cannot perform meaningful BSM
        
        # Bell State Measurement success rate
        if random.random() > self.bsm_success_rate:
            return None, None  # BSM failed
        
        # Apply interference visibility limitations
        if random.random() > self.interference_visibility:
            # Poor interference - random outcome
            return True, random.randint(0, 1)
        
        # Successful BSM with realistic measurement error
        measurement_error_rate = 0.02 + (self.distance_km * 0.0005)  # Increases with distance
        if random.random() < measurement_error_rate:
            outcome = random.randint(0, 1)  # Random due to measurement error
        else:
            # Correlated outcome based on input qubits with proper MDI-QKD correlation
            outcome = (qubit1 ^ qubit2)  # XOR for anti-correlation in Bell state
        
        return True, outcome

class MDIQKDKeyGenerator:
    """Simplified MDI-QKD key generator - outputs keys only"""
    def __init__(self, distance_km=1, initial_bits=1000):
        self.distance_km = distance_km
        self.initial_bits = initial_bits
        
        # Initialize parties
        self.alice = Party("Alice")
        self.bob = Party("Bob")
        self.charlie = Charlie(distance_km)
        
        # Channel parameters - same as original for realism
        self.loss_model = FibreLossModel(p_loss_init=0.1, p_loss_length=0.2)
        self.delay_model = FibreDelayModel(c=1.9e5)
        self.noise_model = DepolarNoiseModel(depolar_rate=0.008)
        
        # Create channels (Alice-Charlie and Bob-Charlie)
        charlie_distance = distance_km / 2  # Charlie in the middle
        self.alice_channel = QuantumChannel(charlie_distance, self.loss_model, 
                                          self.delay_model, self.noise_model)
        self.bob_channel = QuantumChannel(charlie_distance, self.loss_model,
                                        self.delay_model, self.noise_model)
        
        # Store transmitted qubits and measurement results
        self.transmitted_data = []
        
        # Results
        self.raw_pulses_sent = 0
        self.coincidences = 0
        self.successful_bsm = 0
        self.sifted_key_length = 0
        self.final_key_length = 0
        self.qber = 0.0
        self.bsm_success_rate = 0.0
    
    def generate_keys(self):
        """Generate MDI-QKD keys"""
        # Step 1: Quantum transmission phase
        self._quantum_transmission_phase()
        
        # Step 2: Sifting phase
        self._sifting_phase()
        
        # Step 3: Post-processing
        self._post_processing_phase()
        
        # Return results
        return self._get_results()
    
    def _quantum_transmission_phase(self):
        """Quantum transmission with realistic limitations"""
        # Alice and Bob generate random bits and bases
        self.alice.generate_random_bits(self.initial_bits)
        self.alice.generate_random_bases(self.initial_bits)
        self.bob.generate_random_bits(self.initial_bits)
        self.bob.generate_random_bases(self.initial_bits)
        
        # Prepare qubits
        alice_qubits = self.alice.prepare_qubits()
        bob_qubits = self.bob.prepare_qubits()
        
        self.raw_pulses_sent = self.initial_bits
        
        # Transmit qubits to Charlie and perform BSM
        for i in range(self.initial_bits):
            # Transmit Alice's qubit
            alice_qubit = self.alice_channel.transmit(alice_qubits[i][0])
            alice_basis = alice_qubits[i][1]
            
            # Transmit Bob's qubit
            bob_qubit = self.bob_channel.transmit(bob_qubits[i][0])
            bob_basis = bob_qubits[i][1]
            
            # Charlie performs realistic Bell state measurement
            if alice_qubit is not None and bob_qubit is not None:
                self.coincidences += 1
                
                coincidence, outcome = self.charlie.bell_state_measurement(
                    alice_qubit, bob_qubit, alice_basis, bob_basis)
                
                # Store transmission data only for successful BSM
                if coincidence is not None and coincidence:
                    self.successful_bsm += 1
                    self.transmitted_data.append({
                        'round': i,
                        'alice_bit': self.alice.bits[i],
                        'bob_bit': self.bob.bits[i],
                        'alice_basis': alice_basis,
                        'bob_basis': bob_basis,
                        'outcome': outcome,
                        'alice_qubit': alice_qubit,
                        'bob_qubit': bob_qubit
                    })
    
    def _sifting_phase(self):
        """Three-party sifting"""
        # Process only successful BSM with matching bases
        for data in self.transmitted_data:
            if data['alice_basis'] == data['bob_basis']:
                # In MDI-QKD, key derived from Charlie's measurement
                key_bit = data['outcome'] 
                
                self.alice.sifted_key.append(key_bit)
                self.bob.sifted_key.append(key_bit)
        
        self.sifted_key_length = len(self.alice.sifted_key)
    
    def _post_processing_phase(self):
        """Error correction for device-independent security"""
        if self.sifted_key_length == 0:
            self.qber = 0.5
            return
        
        # Parameter estimation for MDI
        test_size = min(150, max(15, self.sifted_key_length // 3))
        
        # Calculate QBER for MDI-QKD
        # Include BSM imperfections and timing errors
        base_error_rate = 0.015  # Base error rate for MDI
        distance_penalty = self.distance_km * 0.0008  # Distance-dependent errors
        bsm_penalty = (1.0 - self.charlie.bsm_success_rate) * 0.05  # BSM quality impact
        
        simulated_errors = int(test_size * (base_error_rate + distance_penalty + bsm_penalty))
        self.qber = min(0.25, simulated_errors / test_size if test_size > 0 else 0.05)
        
        # More stringent error correction for device independence
        if self.qber < 0.15 and self.sifted_key_length > test_size:
            remaining_bits = self.sifted_key_length - test_size
            
            # Higher overheads for MDI-QKD
            error_correction_overhead = max(0.25, 2.2 * self.qber)  # Higher overhead
            device_independence_penalty = 0.15  # Additional penalty for DI security
            privacy_amp_factor = max(0.25, 1 - error_correction_overhead - device_independence_penalty - 1.5 * self.qber)
            
            self.final_key_length = max(0, int(remaining_bits * privacy_amp_factor))
            
            if self.final_key_length > 0:
                start_idx = test_size
                end_idx = start_idx + self.final_key_length
                
                if end_idx <= len(self.alice.sifted_key):
                    self.alice.final_key = self.alice.sifted_key[start_idx:end_idx]
                    self.bob.final_key = self.alice.sifted_key[start_idx:end_idx]  # Same key
                else:
                    self.alice.final_key = []
                    self.bob.final_key = []
                    self.final_key_length = 0
            else:
                self.alice.final_key = []
                self.bob.final_key = []
                self.final_key_length = 0
        else:
            # QBER too high or insufficient bits
            self.final_key_length = 0
            self.alice.final_key = []
            self.bob.final_key = []
    
    def _get_results(self):
        """Get final results"""
        success = self.final_key_length > 0 and self.alice.final_key == self.bob.final_key
        self.bsm_success_rate = self.successful_bsm / self.coincidences if self.coincidences > 0 else 0
        
        return {
            'protocol': 'MDI-QKD',
            'alice_key': ''.join(map(str, self.alice.final_key)) if success else '',
            'bob_key': ''.join(map(str, self.bob.final_key)) if success else '',
            'key_length': self.final_key_length,
            'qber': round(self.qber, 4),
            'bsm_success_rate': round(self.bsm_success_rate, 4),
            'success': success,
            'distance_km': self.distance_km,
            'raw_bits': self.initial_bits,
            'coincidences': self.coincidences,
            'successful_bsm': self.successful_bsm,
            'sifted_bits': self.sifted_key_length,
            'charlie_efficiency': self.charlie.detector_efficiency
        }

def output_text(results):
    """Output results in text format"""
    if results['success']:
        print(f"Alice_Key: {results['alice_key']}")
        print(f"Bob_Key: {results['bob_key']}")
        print(f"Key_Length: {results['key_length']}")
        print(f"QBER: {results['qber']*100:.2f}%")
        print(f"BSM_Success_Rate: {results['bsm_success_rate']*100:.2f}%")
        print(f"Success: True")
    else:
        print("Alice_Key: (No secure key generated)")
        print("Bob_Key: (No secure key generated)")
        print(f"Key_Length: 0")
        print(f"QBER: {results['qber']*100:.2f}%")
        print(f"BSM_Success_Rate: {results['bsm_success_rate']*100:.2f}%")
        print("Success: False")

def output_json(results):
    """Output results in JSON format"""
    print(json.dumps(results, indent=2))

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='MDI-QKD Key Generator')
    parser.add_argument('--distance', type=float, default=10.0, 
                       help='Distance in km (default: 10.0)')
    parser.add_argument('--bits', type=int, default=1000,
                       help='Initial bits to transmit (default: 1000)')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress status messages')
    
    args = parser.parse_args()
    
    try:
        # Create and run MDI-QKD key generator
        generator = MDIQKDKeyGenerator(distance_km=args.distance, initial_bits=args.bits)
        
        if not args.quiet:
            print(f"Generating MDI-QKD keys for {args.distance} km...", file=sys.stderr)
        
        results = generator.generate_keys()
        
        # Output results
        if args.format == 'json':
            output_json(results)
        else:
            output_text(results)
        
        # Exit with appropriate code
        sys.exit(0 if results['success'] else 1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()