import sqlite3

def init_db():
    conn = sqlite3.connect('viroscan.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            scan_type TEXT,
            target TEXT,
            status TEXT,
            result TEXT
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
