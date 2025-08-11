import sqlite3

def init_db():
    conn = sqlite3.connect("qumail.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key_id TEXT PRIMARY KEY,
            key_value TEXT,
            used BOOLEAN DEFAULT FALSE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def store_key(key_id, key_value):
    conn = sqlite3.connect("qumail.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key_id, key_value, used) VALUES (?, ?, ?)",
                  (key_id, key_value, False))
    conn.commit()
    conn.close()

def get_key(key_id):
    conn = sqlite3.connect("qumail.db")
    cursor = conn.cursor()
    cursor.execute("SELECT key_value, used FROM keys WHERE key_id = ?", (key_id,))
    result = cursor.fetchone()
    conn.close()
    return result  # Returns (key_value, used) or None