import sqlite3

conn = sqlite3.connect("C:/Users/DELL/Desktop/New folder/viroscan.db")
cursor = conn.cursor()

# Delete rows where target is 'http://example.com'
cursor.execute("DELETE FROM scan_history WHERE target = 'http://example.com'")

conn.commit()
conn.close()

print("✅ Deleted all 'http://example.com' records from database!")
