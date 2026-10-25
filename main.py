import sys
import os
import time
import threading

# Add root folder to python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logger # Bootstrap logging and stdout redirection
import database
from app import app
from collectors.win_event_log import start_event_log_collectors
from monitors.process_monitor import start_process_monitor
from monitors.file_monitor import start_file_monitor
from monitors.usb_monitor import start_usb_monitor
from health_checker.system_health import run_health_checker_loop

def print_banner():
    banner = """
======================================================================
                 SOC-LITE: HOST-BASED MONITORING AGENT
                    Active Endpoint Security Console
======================================================================
[+] Database Layer initialized.
[+] Ingestion Layer (Win Event Logs) active.
[+] Telemetry Layer (Process & File Integrity) active.
[+] Intelligence Layer (Risk Scoring Engine) active.
[+] Baseline Security Checker (Defender/Firewall) scheduled.
[+] API Web Server launching at http://127.0.0.1:5000
======================================================================
    """
    print(banner)

def main():
    # 1. Initialize SQLite Database
    database.init_db()
    
    # 2. Start Ingestion and Telemetry Agents
    start_event_log_collectors()
    start_process_monitor()
    file_observer = start_file_monitor() # Watchdog observer
    start_usb_monitor()

    # 3. Start Periodic Security Health Checker in a background thread
    health_thread = threading.Thread(
        target=run_health_checker_loop,
        args=(30,),  # Run every 30 seconds
        daemon=True,
        name="SecurityHealthChecker"
    )
    health_thread.start()

    # Print startup message
    print_banner()

    # 4. Start Flask App in the main thread to keep process alive
    try:
        app.run(debug=False, host='127.0.0.1', port=5000)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Stopping local SOC-Lite agents...")
    finally:
        # Clean up watchdog observers
        if file_observer:
            file_observer.stop()
            file_observer.join()
        print("[+] SOC-Lite agents terminated successfully.")

if __name__ == '__main__':
    main()
