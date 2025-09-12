#!/usr/bin/env python3
"""
QKD Performance Testing Script
Runs multiple iterations of BB84, E91, and MDI-QKD simulations
and calculates average performance metrics.
"""

import subprocess
import sys
import os
import re
import statistics
from typing import Dict, List, Tuple

class QKDTestRunner:
    """Class to run QKD simulations and collect performance metrics"""
    
    def __init__(self):
        self.scripts_dir = "Scripts"
        self.protocols = {
            'BB84': 'bb84.py',
            'E91': 'e91.py', 
            'MDI-QKD': 'mdi.py'
        }
        
    def run_single_simulation(self, script_name: str) -> Dict:
        """Run a single QKD simulation and extract metrics"""
        script_path = os.path.join(self.scripts_dir, script_name)
        
        try:
            # Run the script and capture output
            result = subprocess.run([sys.executable, script_path], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=30)
            
            if result.returncode != 0:
                print(f"Error running {script_name}: {result.stderr}")
                return None
                
            output = result.stdout
            return self.parse_output(output)
            
        except subprocess.TimeoutExpired:
            print(f"Timeout running {script_name}")
            return None
        except Exception as e:
            print(f"Exception running {script_name}: {e}")
            return None
    
    def parse_output(self, output: str) -> Dict:
        """Parse simulation output and extract performance metrics"""
        metrics = {
            'raw_key_rate': 0,
            'qber': 0.0,
            'latency': 0.0,
            'channel_loss_rate': 0.0,
            'throughput': 0.0,
            'communication_overhead': 0,
            'synchronization_time': 0.0,
            'computation_time_per_round': 0.0,
            'key_generation_failed': False,
            'bell_parameter': None  # Only for E91
        }
        
        try:
            # Check if key generation failed
            if "No secure key generated" in output:
                metrics['key_generation_failed'] = True
            
            # Extract Raw Key Rate
            match = re.search(r'Raw Key Rate:\s+(\d+)\s+bits', output)
            if match:
                metrics['raw_key_rate'] = int(match.group(1))
            
            # Extract QBER
            match = re.search(r'QBER:\s+([\d.]+)%', output)
            if match:
                metrics['qber'] = float(match.group(1))
            
            # Extract Latency
            match = re.search(r'Latency:\s+([\d.]+)\s+milli seconds', output)
            if match:
                metrics['latency'] = float(match.group(1))
            
            # Extract Channel Loss Rate
            match = re.search(r'Channel Loss Rate:\s+([\d.]+)%', output)
            if match:
                metrics['channel_loss_rate'] = float(match.group(1))
            
            # Extract Throughput
            match = re.search(r'Throughput:\s+([\d.]+)\s+bits/sec', output)
            if match:
                metrics['throughput'] = float(match.group(1))
            
            # Extract Communication Overhead
            match = re.search(r'Communication Overhead:\s+(\d+)\s+messages', output)
            if match:
                metrics['communication_overhead'] = int(match.group(1))
            
            # Extract Synchronization Time
            match = re.search(r'Synchronization Time:\s+([\d.]+)\s+milli seconds', output)
            if match:
                metrics['synchronization_time'] = float(match.group(1))
            
            # Extract Computation Time/Round
            match = re.search(r'Computation Time/Round:\s+([\d.]+)\s+nano seconds', output)
            if match:
                metrics['computation_time_per_round'] = float(match.group(1))
            
            # Extract Bell Parameter (E91 only)
            match = re.search(r'Bell Parameter:\s+([\d.]+)', output)
            if match:
                metrics['bell_parameter'] = float(match.group(1))
                
        except Exception as e:
            print(f"Error parsing output: {e}")
            
        return metrics
    
    def calculate_averages(self, results: List[Dict]) -> Dict:
        """Calculate average metrics from list of results"""
        if not results:
            return {}
            
        # Filter out failed runs for averaging (except for failure count)
        successful_results = [r for r in results if not r['key_generation_failed']]
        
        if not successful_results:
            # All runs failed
            return {
                'raw_key_rate': 0.0,
                'qber': 0.0,
                'latency': 0.0,
                'channel_loss_rate': 0.0,
                'throughput': 0.0,
                'communication_overhead': 0.0,
                'synchronization_time': 0.0,
                'computation_time_per_round': 0.0,
                'key_generation_failures': len(results),
                'bell_parameter': None
            }
        
        averages = {}
        
        # Calculate averages for successful runs
        averages['raw_key_rate'] = statistics.mean([r['raw_key_rate'] for r in successful_results])
        averages['qber'] = statistics.mean([r['qber'] for r in successful_results])
        averages['latency'] = statistics.mean([r['latency'] for r in successful_results])
        averages['channel_loss_rate'] = statistics.mean([r['channel_loss_rate'] for r in successful_results])
        averages['throughput'] = statistics.mean([r['throughput'] for r in successful_results])
        averages['communication_overhead'] = statistics.mean([r['communication_overhead'] for r in successful_results])
        averages['synchronization_time'] = statistics.mean([r['synchronization_time'] for r in successful_results])
        averages['computation_time_per_round'] = statistics.mean([r['computation_time_per_round'] for r in successful_results])
        
        # Count failures
        averages['key_generation_failures'] = len([r for r in results if r['key_generation_failed']])
        
        # Bell parameter for E91
        bell_params = [r['bell_parameter'] for r in successful_results if r['bell_parameter'] is not None]
        if bell_params:
            averages['bell_parameter'] = statistics.mean(bell_params)
        else:
            averages['bell_parameter'] = None
            
        return averages
    
    def run_test_suite(self, num_runs: int):
        """Run complete test suite for all protocols"""
        print(f"Starting QKD Performance Test Suite")
        print(f"Running {num_runs} iterations for each protocol...")
        print("=" * 60)
        
        all_results = {}
        
        for protocol_name, script_name in self.protocols.items():
            print(f"\nTesting {protocol_name} Protocol...")
            print("-" * 40)
            
            results = []
            
            for i in range(num_runs):
                print(f"Run {i+1}/{num_runs}", end="", flush=True)
                
                result = self.run_single_simulation(script_name)
                if result is not None:
                    results.append(result)
                    print(" ✓")
                else:
                    print(" ✗ (failed)")
                    # Add a failed result to maintain count
                    failed_result = {
                        'raw_key_rate': 0, 'qber': 0.0, 'latency': 0.0,
                        'channel_loss_rate': 0.0, 'throughput': 0.0,
                        'communication_overhead': 0, 'synchronization_time': 0.0,
                        'computation_time_per_round': 0.0, 'key_generation_failed': True,
                        'bell_parameter': None
                    }
                    results.append(failed_result)
            
            all_results[protocol_name] = results
        
        # Display results
        self.display_results(all_results, num_runs)
    
    def display_results(self, all_results: Dict, num_runs: int):
        """Display averaged test results"""
        print("\n" + "=" * 80)
        print("QKD PERFORMANCE TEST RESULTS")
        print(f"Based on {num_runs} runs per protocol")
        print("=" * 80)
        
        for protocol_name, results in all_results.items():
            averages = self.calculate_averages(results)
            
            print(f"\n{protocol_name} PROTOCOL AVERAGE RESULTS:")
            print("-" * 50)
            print(f"Raw Key Rate:              {averages['raw_key_rate']:.2f} bits")
            print(f"QBER:                      {averages['qber']:.2f}%")
            print(f"Latency:                   {averages['latency']:.4f} milli seconds")
            print(f"Channel Loss Rate:         {averages['channel_loss_rate']:.2f}%")
            print(f"Throughput:                {averages['throughput']:.2f} bits/sec")
            print(f"Communication Overhead:    {averages['communication_overhead']:.0f} messages")
            print(f"Synchronization Time:      {averages['synchronization_time']:.4f} milli seconds")
            print(f"Computation Time/Round:    {averages['computation_time_per_round']:.4f} nano seconds")
            
            if averages['bell_parameter'] is not None:
                print(f"Bell Parameter:            {averages['bell_parameter']:.3f}")
            
            print(f"Number of key generation failures: {averages['key_generation_failures']}")
            print("-" * 50)
        
        print("\n" + "=" * 80)

def main():
    """Main function to run the test suite"""
    try:
        # Get number of test runs from user
        num_runs = int(input("How many test runs should be performed for each protocol? "))
        
        if num_runs <= 0:
            print("Number of runs must be positive!")
            return
        
        # Check if Scripts directory exists
        if not os.path.exists("Scripts"):
            print("Error: Scripts directory not found!")
            print("Please ensure the Scripts folder is in the same directory as this script.")
            return
        
        # Check if all required scripts exist
        required_scripts = ["bb84.py", "e91.py", "mdi.py"]
        for script in required_scripts:
            if not os.path.exists(os.path.join("Scripts", script)):
                print(f"Error: {script} not found in Scripts directory!")
                return
        
        # Create test runner and run tests
        test_runner = QKDTestRunner()
        test_runner.run_test_suite(num_runs)
        
    except ValueError:
        print("Please enter a valid number!")
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()