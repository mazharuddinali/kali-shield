import datetime
import os

LOG_FILE = "kali_shield.log"

def log_event(category, message):
    """Writes an event to the log file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{category.upper()}] {message}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def get_logs():
    """Reads the last 100 lines of the log file."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        return lines[-100:] # Return last 100 entries
