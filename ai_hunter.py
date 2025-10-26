# ai_hunter.py

import time
import pandas as pd
import google.generativeai as genai
import os
import json
from dotenv import load_dotenv
from threading import Thread
from packet_analyzer import packet_queue, queue_lock, create_new_incident, db_lock, ip_lookup_lock

# AI Configuration 
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash')

# Hunter Configuration 
HUNT_INTERVAL_SECONDS = 60 # How often the hunter wakes up

def run_threat_hunter():
    """
    Main loop for the AI Threat Hunter.
    Wakes up, analyzes the packet queue, and hunts for threats.
    """
    print(f"[AI Hunter] Watchdog agent activated. Will hunt every {HUNT_INTERVAL_SECONDS}s.")
    while True:
        time.sleep(HUNT_INTERVAL_SECONDS)
        
        print(f"[AI Hunter] Waking up... Analyzing packet data from the last {HUNT_INTERVAL_SECONDS}s.")
        
        # 1. Get Packet Data 
        packets_to_analyze = []
        with queue_lock:
            packets_to_analyze = list(packet_queue) # Get a snapshot
            
        if len(packets_to_analyze) < 20: # Don't bother hunting if there's no traffic
            print("[AI Hunter] Not enough traffic to hunt. Going back to sleep.")
            continue
            
        df = pd.DataFrame(packets_to_analyze)
        
        # 2. Create a High-Level Summary for the AI
        try:
            top_talkers_src = df['src_ip'].value_counts().head(5).to_dict()
            top_ports_dst = df['dst_port'].value_counts().head(5).to_dict()
            protocol_counts = df['proto'].value_counts().to_dict()

            summary = f"""
            - Total Packets: {len(df)}
            - Protocol Counts: {protocol_counts}
            - Top 5 Source IPs: {top_talkers_src}
            - Top 5 Destination Ports (and count): {top_ports_dst}
            """
        except Exception as e:
            print(f"[AI Hunter] Error creating summary: {e}")
            continue

        # 3. Run the AI Hunt 
        try:
            hunt_prompt = f"""
            You are an elite 'AI Threat Hunter.' Your job is to find one subtle, behavioral threat that a statistical model might miss.
            Based *only* on the following traffic summary, identify ONE potential threat pattern to investigate.

            **Traffic Summary:**
            {summary}

            **Your Task:**
            Respond *only* with a JSON object for the hunt mission.
            - If you see a potential "low and slow" data exfiltration (e.g., a single IP sending data to an unusual high port), choose "low_and_slow".
            - If you see potential internal reconnaissance (e.g., an internal IP scanning other internal IPs), choose "lateral_movement".
            - If you see unusual DNS activity (e.g., high volume from one host), choose "dns_tunneling".
            - If nothing looks suspicious, return "hunt_type": "none".
            
            Provide a *brief* reason for your choice.

            **Example Response:**
            {{"hunt_type": "low_and_slow", "reason": "The IP 10.0.9.179 is sending a low volume of traffic to an unusual high port (33456), which is characteristic of a 'low and slow' C2 channel."}}
            """
            
            response = model.generate_content(hunt_prompt)
            # Clean the response to get just the JSON
            json_response_str = response.text.strip().replace("```json", "").replace("```", "")
            hunt_mission = json.loads(json_response_str)
            
            if hunt_mission['hunt_type'] == "none":
                print("[AI Hunter] AI found no suspicious patterns. Going back to sleep.")
                continue

            print(f"[AI Hunter] AI Mission: Hunt for '{hunt_mission['hunt_type']}'. Reason: {hunt_mission['reason']}")
            
            # 4. Execute the Hunt Mission
            # This is a simple executioner. It finds the first packet that matches the AI's hunt.
            
            found_threat = None
            
            if hunt_mission['hunt_type'] == "lateral_movement":
                # Hunt: Find a packet where src and dst are both internal IPs
                internal_ips = (df['src_ip'].str.startswith('10.') | df['src_ip'].str.startswith('192.168.'))
                internal_dst = (df['dst_ip'].str.startswith('10.') | df['dst_ip'].str.startswith('192.168.'))
                lateral_packets = df[internal_ips & internal_dst]
                
                if not lateral_packets.empty:
                    found_threat = lateral_packets.iloc[0].to_dict()
                    
            elif hunt_mission['hunt_type'] == "low_and_slow":
                # Hunt: Find a packet going to an unusual (high) non-standard port
                unusual_port_packets = df[(df['dst_port'] > 10000) & (df['dst_port'] != 5353) & (df['dst_port'] != 1900)]
                if not unusual_port_packets.empty:
                    found_threat = unusual_port_packets.iloc[0].to_dict()

            # 5. Create an Incident if Found 
            if found_threat:
                print(f"[AI Hunter] !!! THREAT FOUND by AI Hunter: {hunt_mission['hunt_type']} !!!")
                
                attacker_ip = found_threat['src_ip']
                
                # Format the threat into an event for our incident database
                event_data = {
                    "timestamp": pd.to_datetime(found_threat['timestamp'], unit='s').isoformat(),
                    "type": f"AI Hunter ({hunt_mission['hunt_type']})",
                    "details": f"AI Watchdog detected pattern: {hunt_mission['reason']}. Evidence: Packet from {attacker_ip}:{int(found_threat['src_port'])} to {found_threat['dst_ip']}:{int(found_threat['dst_port'])}"
                }
                
                # This automatically handles correlation and WebSocket alerting.
                with ip_lookup_lock, db_lock:
                    create_new_incident(attacker_ip, event_data) # This is the function from packet_analyzer.py

        except Exception as e:
            print(f"[AI Hunter] Error during hunt: {e}")
            continue

def start_threat_hunter():
    """Starts the AI threat hunter loop in a background thread."""
    t = Thread(target=run_threat_hunter, daemon=True)
    t.start()