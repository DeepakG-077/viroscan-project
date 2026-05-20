import sqlite3
from datetime import datetime
import sqlite3
import os
import time
import urllib.parse
from datetime import datetime
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import requests

# Step 1: Insert test data into scan_history table
def insert_test_data():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
        (current_time, "Test", "http://example.com", "Complete", "No threats found")
    )
    conn.commit()
    conn.close()
    print("✅ Test data inserted successfully.\n")

# Step 2: Fetch all records from scan_history
def print_all_records():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scan_history")
    records = cursor.fetchall()
    conn.close()

    print("📋 Scan History Records:")
    for row in records:
        print(row)

# Step 3: Run both functions
if __name__ == "__main__":
    insert_test_data()
    print_all_records()
