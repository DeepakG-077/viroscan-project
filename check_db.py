import sqlite3

# Connect to your database
conn = sqlite3.connect('viroscan.db')
cursor = conn.cursor()

# Fetch all rows from scan_history
cursor.execute("SELECT * FROM scan_history")
rows = cursor.fetchall()

# Show results
if rows:
    for row in rows:
        print(row)
else:
    print("No scan records found.")

conn.close()
