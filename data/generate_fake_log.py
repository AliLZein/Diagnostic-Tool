import random
from datetime import datetime, timedelta

def generate_log(filepath="data/system.log", num_lines=50):
    events = ["INFO: Service started", "INFO: Health check OK",
              "ERROR: Connection timeout to database",
              "WARNING: High response latency", "INFO: Request processed"]
    start_time = datetime.now() - timedelta(minutes=30)

    with open(filepath, "w") as f:
        for i in range(num_lines):
            timestamp = start_time + timedelta(seconds=i * 30)
            event = random.choice(events)
            f.write(f"{timestamp.isoformat()} {event}\n")

    print(f"Fake log written to {filepath}")

if __name__ == "__main__":
    generate_log()