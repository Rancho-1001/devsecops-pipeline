"""Seed a tiny SQLite DB so the API runs. Shared shape with the fixed app."""
import hashlib
import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "app.db")

USERS = [
    (1, "alice", "alice@example.com", "admin", "password1"),
    (2, "bob", "bob@example.com", "user", "hunter2"),
    (3, "carol", "carol@example.com", "user", "letmein"),
]


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, "
        "role TEXT, password TEXT)")
    for uid, uname, email, role, pw in USERS:
        # Matches the vulnerable app's MD5 scheme (fixed app re-seeds with bcrypt).
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                     (uid, uname, email, role, hashlib.md5(pw.encode()).hexdigest()))
    conn.commit()
    conn.close()
    print(f"Seeded {DB_PATH} with {len(USERS)} users.")


if __name__ == "__main__":
    main()
