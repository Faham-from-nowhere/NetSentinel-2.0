# packet_analyzer.py

import time
import pandas as pd
import random
import os
import os.path
import joblib
import requests 
from collections import deque, defaultdict 
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from threading import Thread, Lock
from datetime import datetime, timedelta 
from dotenv import load_dotenv 

# Load Environment Variables 
load_dotenv() 
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Configuration 
TRAINING_PACKET_COUNT = 500
MAX_PACKET_QUEUE_SIZE = 2000
ANALYSIS_WINDOW_SECONDS = 10
INCIDENT_COOLDOWN_SECONDS = 300
MODEL_FILE_PATH = "netsentinel_model.joblib"
# Threat Intel Config
ENABLE_THREAT_INTEL = bool(ABUSEIPDB_API_KEY) # Only enable if key exists
IP_CACHE_EXPIRY_MINUTES = 60 # Check IP reputation once per hour
ABUSEIPDB_CONFIDENCE_THRESHOLD = 75 # Report IPs with >= 75 confidence score


# Global State
packet_queue = deque(maxlen=MAX_PACKET_QUEUE_SIZE)
queue_lock = Lock()

model = IsolationForest(contamination=0.01)
is_model_trained = False
last_analysis_time = time.time()

incident_database = {}
active_ip_to_incident = {}
db_lock = Lock()
ip_lookup_lock = Lock()

anomaly_alerts_queue = deque()

# Threat Intel Cache 
ip_reputation_cache = {} # { "ip_address": (timestamp, is_malicious, report_link) }
cache_lock = Lock()


# Threat Intelligence Check 
def check_ip_reputation(ip_address: str) -> tuple[bool, str, str]:
    """
    Checks IP reputation using AbuseIPDB API with caching.
    Returns (is_malicious, reason, report_link).
    """
    global ip_reputation_cache
    if not ENABLE_THREAT_INTEL:
        return (False, "Threat Intel Disabled", "")
        
    # Check if IP is internal/private - skip check if so
    if (ip_address.startswith('10.') or
        ip_address.startswith('192.168.') or
        ip_address.startswith('172.') or # Simplified check for 172.16-31
        ip_address == '127.0.0.1'):
        return (False, "Internal IP", "")

    current_time = datetime.now()

    with cache_lock:
        # Check cache first
        if ip_address in ip_reputation_cache:
            cache_time, is_malicious, link = ip_reputation_cache[ip_address]
            if current_time - cache_time < timedelta(minutes=IP_CACHE_EXPIRY_MINUTES):
                # print(f"[Threat Intel] Cache hit for {ip_address}: Malicious={is_malicious}")
                return (is_malicious, "Cached result", link)
            else:
                # Cache expired, remove entry
                del ip_reputation_cache[ip_address]

    # If not in cache or expired, query API
    print(f"[Threat Intel] Querying AbuseIPDB for {ip_address}...")
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90' # Look back 90 days
    }
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5)
        response.raise_for_status() # Raise exception for bad status codes
        data = response.json().get('data', {})

        abuse_score = data.get('abuseConfidenceScore', 0)
        report_link = f"https://www.abuseipdb.com/check/{ip_address}"

        if abuse_score >= ABUSEIPDB_CONFIDENCE_THRESHOLD:
            print(f"[Threat Intel] !!! Malicious IP detected: {ip_address} (Score: {abuse_score}) !!!")
            is_malicious = True
            reason = f"AbuseIPDB Score: {abuse_score}"
        else:
            # print(f"[Threat Intel] IP {ip_address} is clean (Score: {abuse_score}).")
            is_malicious = False
            reason = f"Clean (Score: {abuse_score})"

        # Update cache
        with cache_lock:
            ip_reputation_cache[ip_address] = (current_time, is_malicious, report_link)

        return (is_malicious, reason, report_link)

    except requests.exceptions.RequestException as e:
        print(f"[Threat Intel] API Error for {ip_address}: {e}")
        # Cache failure temporarily to avoid spamming
        with cache_lock:
            ip_reputation_cache[ip_address] = (current_time, False, "")
        return (False, f"API Error: {e}", "")
    except Exception as e:
        print(f"[Threat Intel] Unexpected error checking {ip_address}: {e}")
        return (False, f"Error: {e}", "")

# Packet Sniffing
def packet_callback(packet):
    """
    Called by Scapy for each packet sniffed.
    MODIFIED: Now includes Threat Intel check.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        pkt_len = packet[IP].len

        # Check IP Reputation 
        # Run checks in separate threads to avoid blocking packet capture
        t_src = Thread(target=check_ip_reputation, args=(src_ip,), daemon=True)
        t_dst = Thread(target=check_ip_reputation, args=(dst_ip,), daemon=True)
        t_src.start()
        t_dst.start()
        t_src.join(timeout=1.0) # Wait max 1 sec for results
        t_dst.join(timeout=1.0)
        
        # We need to get the results back (this is tricky with threads, simpler without threads but blocks)
        # For simplicity in hackathon, let's re-check the cache directly here (results should be there now).We dont need to go full BS for a hackathon brothas
        is_src_malicious, src_reason, src_link = check_ip_reputation(src_ip)
        is_dst_malicious, dst_reason, dst_link = check_ip_reputation(dst_ip)
        
        if is_src_malicious or is_dst_malicious:
            malicious_ip = src_ip if is_src_malicious else dst_ip
            reason = src_reason if is_src_malicious else dst_reason
            link = src_link if is_src_malicious else dst_link
            
            #  IMMEDIATELY CREATE INCIDENT 
            event_data = {
                "timestamp": datetime.now().isoformat(),
                "type": "Threat Intel Hit",
                "details": f"Connection involves known malicious IP: {malicious_ip} ({reason}). Report: {link}"
            }
            # Use the existing incident creation logic (thread-safe)
            with ip_lookup_lock, db_lock:
                # Use malicious IP as the key for correlation
                create_new_incident(malicious_ip, event_data, override_score=100, main_event="Threat Intel Hit: Malicious IP")
            # We skip adding this packet to the queue for ML analysis, 
            # as we already know it's bad.
            return 

        src_port, dst_port = 0, 0
        if TCP in packet: src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet: src_port, dst_port = packet[UDP].sport, packet[UDP].dport

        features = {
            "timestamp": time.time(), "src_ip": src_ip, "dst_ip": dst_ip,
            "proto": proto, "src_port": src_port, "dst_port": dst_port,
            "pkt_len": pkt_len
        }
        with queue_lock:
            packet_queue.append(features)

def start_sniffing():
    print("[Analyzer] Starting packet sniffer...")
    t = Thread(target=lambda: sniff(prn=packet_callback, store=0), daemon=True)
    t.start()

# Model Loading/Training 
def try_load_model():
    global model, is_model_trained
    if os.path.exists(MODEL_FILE_PATH):
        try:
            print(f"[Analyzer] Found existing model '{MODEL_FILE_PATH}'. Loading...")
            model = joblib.load(MODEL_FILE_PATH)
            is_model_trained = True
            print("[Analyzer] Model loaded successfully. Switching to detection mode.")
            return True
        except Exception as e:
            print(f"[Analyzer] Error loading model: {e}. Will retrain.")
            return False
    else:
        print("[Analyzer] No model file found. Will train a new one.")
        return False

# Anomaly Detection Loop 
def analyze_traffic():
    global is_model_trained, last_analysis_time, model
    print("[Analyzer] Traffic analyzer started.")
    if try_load_model():
        with queue_lock: packet_queue.clear()

    while True:
        if not is_model_trained:
             with queue_lock:
                current_packets = list(packet_queue)
            
             if len(current_packets) < TRAINING_PACKET_COUNT:
                print(f"[Analyzer] Collecting training data... {len(current_packets)}/{TRAINING_PACKET_COUNT} packets.")
                time.sleep(2)
                continue
             else:
                print("[Analyzer] Training Isolation Forest model...")
                df = pd.DataFrame(current_packets)
                features_to_train = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
                model.fit(features_to_train)
                is_model_trained = True
                
                try:
                    print(f"[Analyzer] Saving trained model to '{MODEL_FILE_PATH}'...")
                    joblib.dump(model, MODEL_FILE_PATH)
                    print("[Analyzer] Model saved.")
                except Exception as e:
                    print(f"[Analyzer] Error saving model: {e}")
                
                print("[Analyzer] Model training complete. Switching to detection mode.")
                with queue_lock:
                    packet_queue.clear()
                continue

        current_time = time.time()
        if current_time - last_analysis_time < ANALYSIS_WINDOW_SECONDS:
            time.sleep(1)
            continue
        last_analysis_time = current_time
        
        packets_to_analyze = []
        with queue_lock:
            while packet_queue:
                packets_to_analyze.append(packet_queue.popleft())
        
        if not packets_to_analyze:
            continue
        
        df = pd.DataFrame(packets_to_analyze)
        print(f"[Analyzer] Analyzing {len(df)} packets from last ~{ANALYSIS_WINDOW_SECONDS}s...")
        
        features_to_predict = df[['proto', 'src_port', 'dst_port', 'pkt_len']]
        scores = model.predict(features_to_predict)
        
        anomaly_indices = [i for i, score in enumerate(scores) if score == -1]
        
        if anomaly_indices:
            print(f"[Analyzer] !!! Found {len(anomaly_indices)} ML anomalous packets !!!") # Clarified ML
            for index in anomaly_indices:
                anomaly_packet = packets_to_analyze[index]
                attacker_ip = anomaly_packet['src_ip']
                event_data = {
                    "timestamp": datetime.fromtimestamp(anomaly_packet['timestamp']).isoformat(),
                    "type": "ML Anomalous Packet", # Clarified ML
                    "details": f"Packet from {attacker_ip}:{anomaly_packet['src_port']} to {anomaly_packet['dst_ip']}:{anomaly_packet['dst_port']} (Proto: {anomaly_packet['proto']}, Size: {anomaly_packet['pkt_len']})"
                }
                with ip_lookup_lock, db_lock:
                    if attacker_ip in active_ip_to_incident:
                        incident_id, last_seen = active_ip_to_incident[attacker_ip]
                        if time.time() - last_seen < INCIDENT_COOLDOWN_SECONDS:
                            print(f"[Analyzer] Correlating ML event with existing incident {incident_id}")
                            incident_database[incident_id]['sequence'].append(event_data)
                            incident_database[incident_id]['threat_score'] = min(100, incident_database[incident_id]['threat_score'] + 5)
                            incident_database[incident_id]['last_seen'] = time.time()
                            active_ip_to_incident[attacker_ip] = (incident_id, time.time())
                        else:
                            print(f"[Analyzer] Cooldown expired for {attacker_ip}. Creating new ML incident.")
                            create_new_incident(attacker_ip, event_data) # Default score 90
                    else:
                        print(f"[Analyzer] New attacker IP {attacker_ip}. Creating new ML incident.")
                        create_new_incident(attacker_ip, event_data) # Default score 90

# Incident Creation 
def create_new_incident(attacker_ip, first_event, override_score=90, main_event="ML Anomaly Detected"):
    """
    Handles the logic for creating a new incident entry.
    MODIFIED: Added override_score and main_event parameters.
    """
    incident_id = f"INC-REAL-{random.randint(1000, 9999)}"
    current_time = time.time()
    
    new_incident = {
        "incident_id": incident_id,
        "threat_score": override_score, # Use override or default
        "main_event": main_event,       # Use override or default
        "status": "new",
        "first_seen": current_time,
        "last_seen": current_time,
        "attacker_ip": attacker_ip,
        "sequence": [first_event]
    }
    
    # Check if incident ID already exists (rare collision)
    if incident_id in incident_database:
        print(f"[Analyzer] Incident ID collision! Regenerating for {attacker_ip}")
        create_new_incident(attacker_ip, first_event, override_score, main_event) # Recurse
        return

    print(f"[Analyzer] Creating new incident {incident_id} for IP {attacker_ip} (Event: {main_event})")
    incident_database[incident_id] = new_incident
    active_ip_to_incident[attacker_ip] = (incident_id, current_time)
    
    initial_alert_data = {
        "incident_id": incident_id,
        "threat_score": new_incident['threat_score'],
        "main_event": new_incident['main_event'],
        "status": new_incident['status'],
        "sequence": [first_event],
        "attacker_ip": attacker_ip # Pass attacker IP for AI context
    }
    
    anomaly_alerts_queue.append(initial_alert_data)


def start_analysis_loop():
    t = Thread(target=analyze_traffic, daemon=True)
    t.start()