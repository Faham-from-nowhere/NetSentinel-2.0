# attack_simulator.py

import threading
import random
from scapy.all import IP, TCP, UDP, send, RandShort

def run_simulation_in_thread(func, *args):
    """Helper to run a simulation in a non-blocking background thread."""
    t = threading.Thread(target=func, args=args, daemon=True)
    t.start()

# Simulation 1: Port Scan

def _do_port_scan():
    """
    Simulates a port scan by sending 50 TCP SYN packets
    to random ports on localhost.
    """
    print("[Simulator] ### STARTING PORT SCAN SIMULATION... ###")
    target_ip = "127.0.0.1"
    ports_to_scan = random.sample(range(1, 1024), 50) # Scan 50 random common ports
    
    for port in ports_to_scan:
        # Create a TCP SYN packet
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        
    print("[Simulator] ### Port scan simulation complete. ###")

def simulate_port_scan():
    """Public function to start the port scan in a thread."""
    run_simulation_in_thread(_do_port_scan)

# Simulation 2: UDP Flood (DDoS) 

def _do_udp_flood():
    """
    Simulates a simple UDP flood by sending 500 large UDP
    packets to random ports on localhost.
    """
    print("[Simulator] ### STARTING UDP FLOOD SIMULATION... ###")
    target_ip = "127.0.0.1"
    
    for _ in range(500): # Send 500 packets
        # Create a 1KB UDP packet to a random high port
        pkt = IP(dst=target_ip) / UDP(dport=RandShort()) / (random.choice("abcdef123456") * 1024)
        send(pkt, verbose=0)
        
    print("[Simulator] ### UDP flood simulation complete. ###")

def simulate_udp_flood():
    """Public function to start the UDP flood in a thread."""
    run_simulation_in_thread(_do_udp_flood)