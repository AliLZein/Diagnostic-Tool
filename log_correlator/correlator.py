import re
from datetime import datetime, timedelta
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from storage.db import log_finding, get_all_findings

def parse_log(filepath):
    entries = []
    pattern = re.compile(r"^(\S+) (ERROR|WARNING|INFO): (.+)$")
    with open(filepath, "r") as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                timestamp_str, level, message = match.groups()
                entries.append({
                    "timestamp": datetime.fromisoformat(timestamp_str),
                    "level": level,
                    "message": message
                })
    return entries

def correlate(log_entries, window_seconds=60):
    """For every ERROR in the log, check if a network finding happened within `window_seconds`."""
    findings = get_all_findings()
    error_entries = [e for e in log_entries if e["level"] == "ERROR"]

    for error in error_entries:
        nearby_findings = [
            f for f in findings
            if abs((f.timestamp - error["timestamp"]).total_seconds()) <= window_seconds
            and f.category in ("network", "security")
        ]

        if nearby_findings:
            related = "; ".join(f.message for f in nearby_findings[:3])
            log_finding(
                "system", "critical", "correlator",
                f"Error '{error['message']}' at {error['timestamp']} correlates with: {related}"
            )
            print(f"ROOT CAUSE CANDIDATE: '{error['message']}' likely linked to: {related}")
        else:
            log_finding(
                "system", "warning", "correlator",
                f"Error '{error['message']}' at {error['timestamp']} has no correlated network finding — investigate app logic"
            )

if __name__ == "__main__":
    entries = parse_log("data/system.log")
    correlate(entries)
    print("Correlation complete. Check data/findings.db for results.")