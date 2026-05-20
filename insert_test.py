import sqlite3
from datetime import datetime

# Connect to your database
conn = sqlite3.connect('viroscan.db')
cursor = conn.cursor()

# Sample test data
date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
scan_type = "Test"
target = "http://example.com"
status = "Complete"
result = "No threats found"

# Insert test data
cursor.execute(
    "INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
    (date, scan_type, target, status, result)
)

conn.commit()
conn.close()

print("Test data inserted successfully.")
