import sqlite3

# Connect to the database
conn = sqlite3.connect('viroscan.db')
cursor = conn.cursor()

# Fetch all records from the scan_history table
cursor.execute("SELECT * FROM scan_history")
rows = cursor.fetchall()

# Print each row
if rows:
    print("Scan History Records:")
    for row in rows:
        print(row)
else:
    print("No records found.")

conn.close()
