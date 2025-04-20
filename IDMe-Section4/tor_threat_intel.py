import os
import json
import sqlite3
import requests
from dotenv import load_dotenv

# Load config from .env file
load_dotenv('config.env')

def fetch_tor_exit_nodes():
    url = "https://check.torproject.org/torbulkexitlist"
    response = requests.get(url)
    if response.status_code == 200:
        return set(line.strip() for line in response.text.splitlines() if line.strip())
    else:
        raise Exception(f"Failed to fetch Tor Exit Nodes. Status: {response.status_code}")

def load_blocked_ips_from_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        # Create a set from the python object 'data' and return the set
        return set(data.get("blocked_ips", []))

# Save the ips in a DB called threats.db
def save_new_threats_to_db(new_threats, db_path="threats.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS threats (ip TEXT PRIMARY KEY)")
    for ip in new_threats:
        # Insert only if it is a new ip, if it is duplicate then Ignore
        cursor.execute("INSERT OR IGNORE INTO threats (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()

# In real world replace the print statement with input to the real firewall sim file.
def update_firewall_sim(new_threats):
    print("\nSimulating firewall update:")
    for ip in new_threats:
        print(f"Blocking IP: {ip}")

def main():
    # Create a set from the tor ips
    tor_ips = fetch_tor_exit_nodes()
    # The input JSON file had to be corrected to fix errors
    # Create a set from the input JSON file
    blocked_ips = load_blocked_ips_from_file("Corrected-JSON.json")
    # Diff between the 2 sets
    new_threats = tor_ips - blocked_ips

    print(f" Found {len(new_threats)} new threats to block.")
    save_new_threats_to_db(new_threats)
    update_firewall_sim(new_threats)

if __name__ == "__main__":
    main()