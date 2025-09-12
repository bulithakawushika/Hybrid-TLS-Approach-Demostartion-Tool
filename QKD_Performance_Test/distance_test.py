#!/usr/bin/env python3
"""
QKD Distance Performance Analysis Script
Tests Raw Key Rate vs Distance for BB84, E91, and MDI-QKD protocols
"""

import subprocess
import sys
import os
import re
import tempfile
import shutil
import statistics
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple

class QKDDistanceTest:
    """Class to test QKD protocols across different distances"""
    
    def __init__(self):
        self.scripts_dir = "Scripts"
        self.protocols = {
            'BB84': 'bb84.py',
            'E91': 'e91.py',
            'MDI-QKD': 'mdi.py'
        }
        self.temp_dir = None
        
    def setup_temp_directory(self):
        """Create temporary directory for modified scripts"""
        self.temp_dir = tempfile.mkdtemp(prefix="qkd_distance_test_")
        
        # Copy original scripts to temp directory
        for script_name in self.protocols.values():
            src_path = os.path.join(self.scripts_dir, script_name)
            dst_path = os.path.join(self.temp_dir, script_name)
            shutil.copy2(src_path, dst_path)
    
    def cleanup_temp_directory(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def modify_script_distance(self, script_name: str, distance_km: int):
        """Modify script to use specified distance"""
        script_path = os.path.join(self.temp_dir, script_name)
        
        # Read the original script
        with open(script_path, 'r') as f:
            content = f.read()
        
        # Modify the distance parameter in the main() function
        if script_name == 'bb84.py':
            # Replace: simulation = BB84Simulation(distance_km=10, initial_bits=1000)
            content = re.sub(
                r'simulation = BB84Simulation\(distance_km=\d+, initial_bits=1000\)',
                f'simulation = BB84Simulation(distance_km={distance_km}, initial_bits=1000)',
                content
            )
        elif script_name == 'e91.py':
            # Replace: simulation = E91Simulation(distance_km=10, initial_pairs=1000)
            content = re.sub(
                r'simulation = E91Simulation\(distance_km=\d+, initial_pairs=1000\)',
                f'simulation = E91Simulation(distance_km={distance_km}, initial_pairs=1000)',
                content
            )
        elif script_name == 'mdi.py':
            # Replace: simulation = MDIQKDSimulation(distance_km=10, initial_bits=1000)
            content = re.sub(
                r'simulation = MDIQKDSimulation\(distance_km=\d+, initial_bits=1000\)',
                f'simulation = MDIQKDSimulation(distance_km={distance_km}, initial_bits=1000)',
                content
            )
        
        # Write the modified script
        with open(script_path, 'w') as f:
            f.write(content)
    
    def run_single_simulation(self, script_name: str) -> float:
        """Run a single QKD simulation and extract Raw Key Rate"""
        script_path = os.path.join(self.temp_dir, script_name)
        
        try:
            # Run the script and capture output
            result = subprocess.run([sys.executable, script_path], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60,
                                  cwd=self.temp_dir)
            
            if result.returncode != 0:
                return 0.0  # Failed simulation
                
            output = result.stdout
            
            # Extract Raw Key Rate
            match = re.search(r'Raw Key Rate:\s+(\d+)\s+bits', output)
            if match:
                return float(match.group(1))
            else:
                return 0.0  # No key generated
                
        except (subprocess.TimeoutExpired, Exception):
            return 0.0  # Failed simulation
    
    def test_distance_range(self, max_distance: int, tests_per_point: int):
        """Test all protocols across distance range"""
        print(f"Starting QKD Distance Analysis")
        print(f"Testing distances from 1 km to {max_distance} km")
        print(f"Running {tests_per_point} tests per distance point")
        print("=" * 60)
        
        # Setup temporary directory
        self.setup_temp_directory()
        
        # Initialize results storage
        results = {protocol: {'distances': [], 'raw_key_rates': []} 
                  for protocol in self.protocols.keys()}
        
        try:
            # Test each distance point
            for distance in range(1, max_distance + 1):
                print(f"\nTesting Distance: {distance} km")
                print("-" * 30)
                
                for protocol_name, script_name in self.protocols.items():
                    print(f"  {protocol_name}: ", end="", flush=True)
                    
                    # Modify script for current distance
                    self.modify_script_distance(script_name, distance)
                    
                    # Run multiple tests for this distance
                    key_rates = []
                    successful_key_rates = []  # FIXED: Track only successful runs
                    
                    for test in range(tests_per_point):
                        key_rate = self.run_single_simulation(script_name)
                        key_rates.append(key_rate)
                        
                        # FIXED: Only add to successful_key_rates if key_rate > 0
                        if key_rate > 0:
                            successful_key_rates.append(key_rate)
                        
                        print("." if key_rate > 0 else "x", end="", flush=True)
                    
                    # FIXED: Calculate average only from successful runs
                    if successful_key_rates:  # If there are any successful runs
                        avg_key_rate = statistics.mean(successful_key_rates)
                    else:  # If all runs failed
                        avg_key_rate = 0.0
                    
                    results[protocol_name]['distances'].append(distance)
                    results[protocol_name]['raw_key_rates'].append(avg_key_rate)
                    
                    print(f" Avg: {avg_key_rate:.1f} bits")
        
        finally:
            # Cleanup
            self.cleanup_temp_directory()
        
        return results
    
    def plot_results(self, results: Dict, max_distance: int, tests_per_point: int):
        """Create and display the distance vs raw key rate plot"""
        plt.figure(figsize=(12, 8))
        
        # Plot each protocol
        colors = {'BB84': 'blue', 'E91': 'red', 'MDI-QKD': 'green'}
        
        for protocol_name, data in results.items():
            if data['distances'] and data['raw_key_rates']:
                plt.plot(data['distances'], 
                        data['raw_key_rates'], 
                        color=colors.get(protocol_name, 'black'),
                        linestyle='-',
                        linewidth=2,
                        label=protocol_name,
                        alpha=0.8)
        
        # Customize plot
        plt.xlabel('Distance (km)', fontsize=12, fontweight='bold')
        plt.ylabel('Raw Key Rate (bits)', fontsize=12, fontweight='bold')
        plt.title(f'QKD Protocol Performance vs Distance\n({tests_per_point} tests per point)', 
                 fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)
        plt.legend(fontsize=11, loc='best')
        
        # Set axis limits
        plt.xlim(0, max_distance + 1)
        plt.ylim(0, None)  # Auto-scale y-axis from 0
        
        # Add minor gridlines
        plt.minorticks_on()
        plt.grid(which='minor', alpha=0.1)
        
        # Improve layout
        plt.tight_layout()
        
        # Save plot
        plot_filename = f'qkd_distance_analysis_{max_distance}km.png'
        plt.savefig(plot_filename, dpi=300, bbox_inches='tight')
        print(f"\nPlot saved as: {plot_filename}")
        
        # Show plot
        plt.show()
    
    def display_summary_table(self, results: Dict, max_distance: int):
        """Display a summary table of results"""
        print("\n" + "=" * 80)
        print("QKD DISTANCE ANALYSIS SUMMARY")
        print("=" * 80)
        
        # Find key distances to summarize (every 10 km or so)
        summary_distances = list(range(1, max_distance + 1, max(1, max_distance // 10)))
        if max_distance not in summary_distances:
            summary_distances.append(max_distance)
        
        print(f"{'Distance (km)':<12}", end="")
        for protocol in self.protocols.keys():
            print(f"{protocol + ' (bits)':<15}", end="")
        print()
        print("-" * 80)
        
        for dist in summary_distances:
            print(f"{dist:<12}", end="")
            for protocol_name, data in results.items():
                try:
                    idx = data['distances'].index(dist)
                    rate = data['raw_key_rates'][idx]
                    print(f"{rate:<15.1f}", end="")
                except (ValueError, IndexError):
                    print(f"{'N/A':<15}", end="")
            print()
        
        print("-" * 80)
        
        # Performance summary
        print("\nPERFORMANCE SUMMARY:")
        for protocol_name, data in results.items():
            if data['raw_key_rates']:
                max_rate = max(data['raw_key_rates'])
                min_rate = min(data['raw_key_rates'])
                # Find distance where key rate drops to ~10% of maximum
                threshold = max_rate * 0.1
                effective_range = max_distance
                for i, rate in enumerate(data['raw_key_rates']):
                    if rate < threshold:
                        effective_range = data['distances'][i]
                        break
                
                print(f"  {protocol_name}:")
                print(f"    Maximum Key Rate: {max_rate:.1f} bits (at {data['distances'][data['raw_key_rates'].index(max_rate)]} km)")
                print(f"    Minimum Key Rate: {min_rate:.1f} bits (at {max_distance} km)")
                print(f"    Effective Range: ~{effective_range} km (>10% of max rate)")

def main():
    """Main function to run the distance test"""
    try:
        # Get parameters from user
        max_distance = int(input("Enter maximum distance to test (km): "))
        tests_per_point = int(input("Enter number of tests per distance point: "))
        
        if max_distance <= 0 or tests_per_point <= 0:
            print("Distance and tests per point must be positive!")
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
        
        # Create test runner and run distance analysis
        distance_test = QKDDistanceTest()
        
        print("\nStarting distance analysis...")
        results = distance_test.test_distance_range(max_distance, tests_per_point)
        
        # Display results
        distance_test.display_summary_table(results, max_distance)
        
        # Create and show plot
        print("\nGenerating plot...")
        distance_test.plot_results(results, max_distance, tests_per_point)
        
        print("\nDistance analysis completed successfully!")
        
    except ValueError:
        print("Please enter valid numbers!")
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()#!/usr/bin/env python3
"""
QKD Distance Performance Analysis Script
Tests Raw Key Rate vs Distance for BB84, E91, and MDI-QKD protocols
"""

import subprocess
import sys
import os
import re
import tempfile
import shutil
import statistics
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple

class QKDDistanceTest:
    """Class to test QKD protocols across different distances"""
    
    def __init__(self):
        self.scripts_dir = "Scripts"
        self.protocols = {
            'BB84': 'bb84.py',
            'E91': 'e91.py',
            'MDI-QKD': 'mdi.py'
        }
        self.temp_dir = None
        
    def setup_temp_directory(self):
        """Create temporary directory for modified scripts"""
        self.temp_dir = tempfile.mkdtemp(prefix="qkd_distance_test_")
        
        # Copy original scripts to temp directory
        for script_name in self.protocols.values():
            src_path = os.path.join(self.scripts_dir, script_name)
            dst_path = os.path.join(self.temp_dir, script_name)
            shutil.copy2(src_path, dst_path)
    
    def cleanup_temp_directory(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def modify_script_distance(self, script_name: str, distance_km: int):
        """Modify script to use specified distance"""
        script_path = os.path.join(self.temp_dir, script_name)
        
        # Read the original script
        with open(script_path, 'r') as f:
            content = f.read()
        
        # Modify the distance parameter in the main() function
        if script_name == 'bb84.py':
            # Replace: simulation = BB84Simulation(distance_km=10, initial_bits=1000)
            content = re.sub(
                r'simulation = BB84Simulation\(distance_km=\d+, initial_bits=1000\)',
                f'simulation = BB84Simulation(distance_km={distance_km}, initial_bits=1000)',
                content
            )
        elif script_name == 'e91.py':
            # Replace: simulation = E91Simulation(distance_km=10, initial_pairs=1000)
            content = re.sub(
                r'simulation = E91Simulation\(distance_km=\d+, initial_pairs=1000\)',
                f'simulation = E91Simulation(distance_km={distance_km}, initial_pairs=1000)',
                content
            )
        elif script_name == 'mdi.py':
            # Replace: simulation = MDIQKDSimulation(distance_km=10, initial_bits=1000)
            content = re.sub(
                r'simulation = MDIQKDSimulation\(distance_km=\d+, initial_bits=1000\)',
                f'simulation = MDIQKDSimulation(distance_km={distance_km}, initial_bits=1000)',
                content
            )
        
        # Write the modified script
        with open(script_path, 'w') as f:
            f.write(content)
    
    def run_single_simulation(self, script_name: str) -> float:
        """Run a single QKD simulation and extract Raw Key Rate"""
        script_path = os.path.join(self.temp_dir, script_name)
        
        try:
            # Run the script and capture output
            result = subprocess.run([sys.executable, script_path], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60,
                                  cwd=self.temp_dir)
            
            if result.returncode != 0:
                return 0.0  # Failed simulation
                
            output = result.stdout
            
            # Extract Raw Key Rate
            match = re.search(r'Raw Key Rate:\s+(\d+)\s+bits', output)
            if match:
                return float(match.group(1))
            else:
                return 0.0  # No key generated
                
        except (subprocess.TimeoutExpired, Exception):
            return 0.0  # Failed simulation
    
    def test_distance_range(self, max_distance: int, tests_per_point: int):
        """Test all protocols across distance range"""
        print(f"Starting QKD Distance Analysis")
        print(f"Testing distances from 1 km to {max_distance} km")
        print(f"Running {tests_per_point} tests per distance point")
        print("=" * 60)
        
        # Setup temporary directory
        self.setup_temp_directory()
        
        # Initialize results storage
        results = {protocol: {'distances': [], 'raw_key_rates': []} 
                  for protocol in self.protocols.keys()}
        
        try:
            # Test each distance point
            for distance in range(1, max_distance + 1):
                print(f"\nTesting Distance: {distance} km")
                print("-" * 30)
                
                for protocol_name, script_name in self.protocols.items():
                    print(f"  {protocol_name}: ", end="", flush=True)
                    
                    # Modify script for current distance
                    self.modify_script_distance(script_name, distance)
                    
                    # Run multiple tests for this distance
                    key_rates = []
                    successful_key_rates = []  # FIXED: Track only successful runs
                    
                    for test in range(tests_per_point):
                        key_rate = self.run_single_simulation(script_name)
                        key_rates.append(key_rate)
                        
                        # FIXED: Only add to successful_key_rates if key_rate > 0
                        if key_rate > 0:
                            successful_key_rates.append(key_rate)
                        
                        print("." if key_rate > 0 else "x", end="", flush=True)
                    
                    # FIXED: Calculate average only from successful runs
                    if successful_key_rates:  # If there are any successful runs
                        avg_key_rate = statistics.mean(successful_key_rates)
                    else:  # If all runs failed
                        avg_key_rate = 0.0
                    
                    results[protocol_name]['distances'].append(distance)
                    results[protocol_name]['raw_key_rates'].append(avg_key_rate)
                    
                    print(f" Avg: {avg_key_rate:.1f} bits")
        
        finally:
            # Cleanup
            self.cleanup_temp_directory()
        
        return results
    
    def plot_results(self, results: Dict, max_distance: int, tests_per_point: int):
        """Create and display the distance vs raw key rate plot"""
        plt.figure(figsize=(12, 8))
        
        # Plot each protocol
        colors = {'BB84': 'blue', 'E91': 'red', 'MDI-QKD': 'green'}
        
        for protocol_name, data in results.items():
            if data['distances'] and data['raw_key_rates']:
                plt.plot(data['distances'], 
                        data['raw_key_rates'], 
                        color=colors.get(protocol_name, 'black'),
                        linestyle='-',
                        linewidth=2,
                        label=protocol_name,
                        alpha=0.8)
        
        # Customize plot
        plt.xlabel('Distance (km)', fontsize=12, fontweight='bold')
        plt.ylabel('Raw Key Rate (bits)', fontsize=12, fontweight='bold')
        plt.title(f'QKD Protocol Performance vs Distance\n({tests_per_point} tests per point)', 
                 fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)
        plt.legend(fontsize=11, loc='best')
        
        # Set axis limits
        plt.xlim(0, max_distance + 1)
        plt.ylim(0, None)  # Auto-scale y-axis from 0
        
        # Add minor gridlines
        plt.minorticks_on()
        plt.grid(which='minor', alpha=0.1)
        
        # Improve layout
        plt.tight_layout()
        
        # Save plot
        plot_filename = f'qkd_distance_analysis_{max_distance}km.png'
        plt.savefig(plot_filename, dpi=300, bbox_inches='tight')
        print(f"\nPlot saved as: {plot_filename}")
        
        # Show plot
        plt.show()
    
    def display_summary_table(self, results: Dict, max_distance: int):
        """Display a summary table of results"""
        print("\n" + "=" * 80)
        print("QKD DISTANCE ANALYSIS SUMMARY")
        print("=" * 80)
        
        # Find key distances to summarize (every 10 km or so)
        summary_distances = list(range(1, max_distance + 1, max(1, max_distance // 10)))
        if max_distance not in summary_distances:
            summary_distances.append(max_distance)
        
        print(f"{'Distance (km)':<12}", end="")
        for protocol in self.protocols.keys():
            print(f"{protocol + ' (bits)':<15}", end="")
        print()
        print("-" * 80)
        
        for dist in summary_distances:
            print(f"{dist:<12}", end="")
            for protocol_name, data in results.items():
                try:
                    idx = data['distances'].index(dist)
                    rate = data['raw_key_rates'][idx]
                    print(f"{rate:<15.1f}", end="")
                except (ValueError, IndexError):
                    print(f"{'N/A':<15}", end="")
            print()
        
        print("-" * 80)
        
        # Performance summary
        print("\nPERFORMANCE SUMMARY:")
        for protocol_name, data in results.items():
            if data['raw_key_rates']:
                max_rate = max(data['raw_key_rates'])
                min_rate = min(data['raw_key_rates'])
                # Find distance where key rate drops to ~10% of maximum
                threshold = max_rate * 0.1
                effective_range = max_distance
                for i, rate in enumerate(data['raw_key_rates']):
                    if rate < threshold:
                        effective_range = data['distances'][i]
                        break
                
                print(f"  {protocol_name}:")
                print(f"    Maximum Key Rate: {max_rate:.1f} bits (at {data['distances'][data['raw_key_rates'].index(max_rate)]} km)")
                print(f"    Minimum Key Rate: {min_rate:.1f} bits (at {max_distance} km)")
                print(f"    Effective Range: ~{effective_range} km (>10% of max rate)")

def main():
    """Main function to run the distance test"""
    try:
        # Get parameters from user
        max_distance = int(input("Enter maximum distance to test (km): "))
        tests_per_point = int(input("Enter number of tests per distance point: "))
        
        if max_distance <= 0 or tests_per_point <= 0:
            print("Distance and tests per point must be positive!")
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
        
        # Create test runner and run distance analysis
        distance_test = QKDDistanceTest()
        
        print("\nStarting distance analysis...")
        results = distance_test.test_distance_range(max_distance, tests_per_point)
        
        # Display results
        distance_test.display_summary_table(results, max_distance)
        
        # Create and show plot
        print("\nGenerating plot...")
        distance_test.plot_results(results, max_distance, tests_per_point)
        
        print("\nDistance analysis completed successfully!")
        
    except ValueError:
        print("Please enter valid numbers!")
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()