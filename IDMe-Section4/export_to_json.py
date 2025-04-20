import sqlite3
import json

def export_sqlite_to_json(db_file="threats.db", output_file="new_threats.json"):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM threats")
    # Get all the ips from the db as a list of tuple
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()

    with open(output_file, "w") as f:
        # Put all the ips from the tuple in the josn file
        json.dump({"new_threats": ips}, f, indent=2)

    print(f" Exported {len(ips)} IPs to {output_file}")

if __name__ == "__main__":
    export_sqlite_to_json()