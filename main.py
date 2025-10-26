# main.py

import uvicorn
import asyncio
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from contextlib import asynccontextmanager
from plyer import notification
from ai_hunter import start_threat_hunter 

# Existing Imports 
from ai_analyst import generate_threat_report
from packet_analyzer import (
    start_sniffing,
    start_analysis_loop,
    anomaly_alerts_queue, 
    incident_database,
    db_lock
)
from attack_simulator import simulate_port_scan, simulate_udp_flood

# Queues for Fan-Out 
websocket_queue = asyncio.Queue()
desktop_queue = asyncio.Queue()

# Data Models 
class IncidentSequenceItem(BaseModel):
    timestamp: str
    type: str
    details: str

class Alert(BaseModel):
    incident_id: str
    threat_score: int
    main_event: str
    status: str
    sequence: List[IncidentSequenceItem]
    ai_summary: str

class FullIncident(BaseModel):
    incident_id: str
    threat_score: int
    main_event: str
    status: str
    first_seen: float
    last_seen: float
    attacker_ip: str
    sequence: List[IncidentSequenceItem]
    ai_summary: Optional[str] = None

class SimulationResponse(BaseModel):
    message: str

# Desktop Notification Function 
def send_desktop_notification(alert: Alert):
    """
    Sends a desktop toast notification using plyer.
    Truncates the message if it's too long for Windows.
    """
    try:
        title = f"🚨 NetSentinel Alert: {alert.main_event} ({alert.threat_score}/100)"
        # Get just the summary part of the AI report before the MITRE details
        message_summary = alert.ai_summary.split("---")[0].strip()

        # Truncate message for Windows limit
        max_len = 250 # Be safe, leave a little buffer under 256
        if len(message_summary) > max_len:
            message_summary = message_summary[:max_len] + "..."

        notification.notify(
            title=title,
            message=message_summary, # Pass the potentially truncated message
            app_name="NetSentinel",
            timeout=15
            # app_icon='path/to/icon.ico'
        )
        print(f"[Desktop Notifier] Sent notification for {alert.incident_id}")
    except Exception as e:
        print(f"[Desktop Notifier] Error sending notification: {e}")


# Central Alert Processor Task 
async def alert_processor_task():
    """
    The *only* task that reads from the raw anomaly queue.
    It enriches the alert with AI analysis and fans it out.
    """
    print("[Alert Processor] Started.")
    while True:
        if not anomaly_alerts_queue:
            await asyncio.sleep(0.5) # Check frequently but don't busy-wait
            continue
            
        # 1. Get Raw Alert
        initial_alert_data = anomaly_alerts_queue.popleft()
        incident_id = initial_alert_data['incident_id']
        print(f"[Alert Processor] Processing raw alert {incident_id}...")

        # 2. Get AI Report
        try:
            report_text = await generate_threat_report(initial_alert_data)
            initial_alert_data["ai_summary"] = report_text
            print(f"[Alert Processor] AI analysis complete for {incident_id}.")

            # 3. Update the main incident DB with the AI summary
            with db_lock:
                if incident_id in incident_database:
                    incident_database[incident_id]['ai_summary'] = report_text
                    
            # 4. Validate and create the full Alert object
            full_alert = Alert(**initial_alert_data)
            
            # 5. Fan out to subscribers
            await websocket_queue.put(full_alert)
            await desktop_queue.put(full_alert)
            print(f"[Alert Processor] Fanned out alert {incident_id}.")

        except Exception as e:
            print(f"[Alert Processor] Error processing alert {incident_id}: {e}")

# Desktop Notification Task 
async def desktop_notification_loop():
    """
    Waits for enriched alerts and sends desktop notifications.
    """
    print("[Desktop Notifier] Started. Waiting for alerts...")
    while True:
        try:
            full_alert: Alert = await desktop_queue.get()
            print(f"[Desktop Notifier] Received alert {full_alert.incident_id}. Triggering notification.")
            # Run the synchronous plyer notification in a separate thread
            # to avoid blocking the asyncio event loop.
            await asyncio.to_thread(send_desktop_notification, full_alert)
            desktop_queue.task_done() # Mark as processed
        except Exception as e:
            print(f"[Desktop Notifier] Error in loop: {e}")
            await asyncio.sleep(5) # Avoid rapid error loops


# Lifespan Manager 
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("--- Server Starting Up ---")
    start_sniffing()
    start_analysis_loop()
    start_threat_hunter() 
    # Start our new background tasks 
    print("[Lifespan] Starting background tasks...")
    alert_processor_handle = asyncio.create_task(alert_processor_task())
    desktop_notifier_handle = asyncio.create_task(desktop_notification_loop())

    yield # App is running

    # Cleanup background tasks on shutdown 
    print("--- Server Shutting Down ---")
    print("[Lifespan] Cancelling background tasks...")
    alert_processor_handle.cancel()
    desktop_notifier_handle.cancel()
    try:
        await alert_processor_handle
        await desktop_notifier_handle
    except asyncio.CancelledError:
        print("[Lifespan] Background tasks cancelled.")

# Initialize FastAPI App
app = FastAPI(
    title="NetSentinel Backend",
    description="Manages packet analysis, alert streaming, and notifications.", 
    lifespan=lifespan
)


# WebSocket
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    print("[WebSocket] Frontend client connected.")
    
    try:
        while True:
            # Just wait for an alert from the processor
            full_alert: Alert = await websocket_queue.get()
            
            await websocket.send_json(full_alert.model_dump())
            print(f"[WebSocket] Sent alert {full_alert.incident_id} to frontend.")
            websocket_queue.task_done() # Mark as processed

    except WebSocketDisconnect:
        print("[WebSocket] Frontend client disconnected.")
    except Exception as e:
        print(f"[WebSocket] An error occurred: {e}")
        # Attempt to close gracefully
        try:
            await websocket.close()
        except: pass

# Incident API 
@app.get("/api/incident/{incident_id}", response_model=FullIncident)
def get_incident_details(incident_id: str):
    print(f"[API] Frontend requested details for {incident_id}")
    with db_lock:
        incident = incident_database.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return FullIncident(**incident)

# Simulator API Endpoints
@app.post("/api/simulate/portscan", response_model=SimulationResponse)
async def http_simulate_portscan():
    simulate_port_scan()
    return {"message": "Port scan simulation started."}

@app.post("/api/simulate/udpflood", response_model=SimulationResponse)
async def http_simulate_udpflood():
    simulate_udp_flood()
    return {"message": "UDP flood simulation started."}

# Mitigation "Honeypot" API Endpoints 
blocked_ips_db = set() # Moved global definition here for clarity

@app.post("/api/mitigate/block_ip/{ip_address}", response_model=SimulationResponse)
async def block_ip(ip_address: str):
    print(f"[Mitigation] ### Received request to BLOCK/HONEYPOT IP: {ip_address} ###")
    blocked_ips_db.add(ip_address)
    return {"message": f"IP {ip_address} has been added to the blocklist/honeypot redirect."}

@app.get("/api/mitigate/blocked_ips")
async def get_blocked_ips():
    return {"blocked_ips": sorted(list(blocked_ips_db))}

# Root Endpoint 
@app.get("/")
def read_root():
    return {"status": "NetSentinel Backend is running."}

# Run the Server 
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)