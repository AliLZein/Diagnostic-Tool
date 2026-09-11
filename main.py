import subprocess
import sys
import time
import threading
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from dashboard import app

def run_step(description, command):
    print(f"\n{'='*50}\n{description}\n{'='*50}")
    subprocess.run(command, shell=True, check=False)

def run_diagnostic_pipeline():
    """Runs your 4-step diagnostic pipeline continuously."""
    print("\n[INFO] Starting continuous diagnostic cycle...")
    run_step("Step 1: Generating fake system log", "python data/generate_fake_log.py")
    run_step("Step 2: Scanning network baseline", "python network_scanner/scanner.py")
    run_step("Step 3: Analyzing packet capture", "python packet_analyzer/analyzer.py")
    run_step("Step 4: Correlating logs with network findings", "python log_correlator/correlator.py")
    print("\nCycle complete. Full findings updated in data/findings.db")

def run_web_dashboard():
    """Runs the persistent Flask web server on port 5000."""
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    print("=== Initializing Root-Cause Diagnostic Toolkit (Live Dashboard & Loop Mode) ===")
    
    dashboard_thread = threading.Thread(target=run_web_dashboard, daemon=True)
    dashboard_thread.start()
    print("[INFO] Web dashboard running on http://localhost:5000")

    while True:
        try:
            run_diagnostic_pipeline()
            
            print("[INFO] Waiting 5 seconds before next cycle...")
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n[INFO] Stopping diagnostic toolkit gracefully.")
            break
        except Exception as e:
            print(f"[ERROR] An error occurred in the loop: {e}")
            time.sleep(10)