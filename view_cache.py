import sqlite3
import os

db_path = "agent_cache.db"

if not os.path.exists(db_path):
    print(f"Database {db_path} does not exist yet. Run test_midsem.py first!")
else:
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Query all records
    cur.execute("SELECT ip, timestamp FROM blocked_ips")
    records = cur.fetchall()
    
    print("=== IDEMPOTENCY CACHE (BLOCKED IPs) ===")
    if not records:
        print("Empty (No IPs currently blocked)")
    else:
        for row in records:
            ip_address = row[0]
            time_blocked = row[1]
            print(f"- IP: {ip_address} | Blocked at: {time_blocked} (UTC)")
            
    conn.close()
