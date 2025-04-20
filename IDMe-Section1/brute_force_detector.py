import json
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dotenv import load_dotenv
from geoip2.database import Reader

# Load environment variables
load_dotenv()

CONFIG = {
    "log_file": "Corrected-JSON-1.json",
    "alert_output": "alerts.json",
    # "brute_force_threshold": 10,
    # Given the input file, there were no IPs which had 10 or more attempts in 5 minutes. To get results, reduced the attempts to 5
    "brute_force_threshold": 5,
    "brute_force_window_minutes": 5,
    # Downloaded GeoLite2 from https://www.maxmind.com/en/accounts/1157195/geoip/downloads
    "geoip_db_path": os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb"),
    "rate_limit": 100
}

def parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

def rate_limiter(max_per_minute):
    timestamps = deque()
    def allow():
        now = time.time()
        while timestamps and now - timestamps[0] > 60:
            timestamps.popleft()
        # Loop to check if calls are made more than 100 times in 60 secs(1 min)
        if len(timestamps) < max_per_minute:
            timestamps.append(now)
            return True
        return False
    return allow

reader = Reader(CONFIG["geoip_db_path"])
allow_geo = rate_limiter(CONFIG["rate_limit"])

# Load the log entries from the json file
with open(CONFIG["log_file"], "r") as f:
    data = json.load(f)

logs = data.get("logs", [])
failed_logins_by_ip = defaultdict(list)

# Loop through the get all the failed login entries and add it to failed_logins_by_ip
for log in logs:
    if log.get("event_type") == "failed_login":
        ip = log["source_ip"]
        ts = parse_timestamp(log["timestamp"])
        # create collection of failed logins {ip:ts, ip:ts, ip:ts....}
        failed_logins_by_ip[ip].append(ts)

alerts = []
for ip, timestamps in failed_logins_by_ip.items():
    # Sort the collection based on timestamp ts
    timestamps.sort()
    # initialize a double ended queue so that elements can be added or removed on both sides
    dq = deque()
    for ts in timestamps:
        dq.append(ts)
        # Loop through the entries for 5 minutes
        while dq and (ts - dq[0]) > timedelta(minutes=CONFIG["brute_force_window_minutes"]):
            dq.popleft()
        # If there are 5 or more occurrences then trigger alert
        if len(dq) >= CONFIG["brute_force_threshold"]:
            alert = {
                "source_ip": ip,
                "failed_attempts": len(dq),
                "start_time": dq[0].isoformat(),
                "end_time": dq[-1].isoformat()
            }

            if allow_geo():
                try:
                    response = reader.city(ip)
                    alert["location"] = {
                        "country": response.country.name,
                        "city": response.city.name,
                        "latitude": response.location.latitude,
                        "longitude": response.location.longitude
                    }
                except Exception as e:
                    alert["location"] = {
                        "error": str(e)
                    }
            else:
                alert["location"] = {
                    "note": "Rate limit exceeded"
                }

            alerts.append(alert)
            break

with open(CONFIG["alert_output"], "w") as out:
    json.dump(alerts, out, indent=2)

reader.close()
print(f"Generated {len(alerts)} alert(s). See {CONFIG['alert_output']}.")
