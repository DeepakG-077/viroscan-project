import sqlite3

# Step 1: Connect to your database
conn = sqlite3.connect(r'C:/Users/DELL/Desktop/New folder/viroscan.db')
cursor = conn.cursor()

# Step 2: See all tables inside the database
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables inside viroscan.db:", tables)

# Step 3: Example: See contents from scan_history table
cursor.execute("SELECT * FROM scan_history;")
rows = cursor.fetchall()

print("\nData inside scan_history table:")
for row in rows:
    print(row)

# Step 4: (Optional) Close connection
conn.close()
