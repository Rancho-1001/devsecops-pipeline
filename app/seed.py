"""Seed SQLite with bcrypt-hashed passwords for the secure app."""
import os
import sqlite3

import bcrypt

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
        "role TEXT, password BLOB)")
    for uid, uname, email, role, pw in USERS:
        pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                     (uid, uname, email, role, pw_hash))
    conn.commit()
    conn.close()
    print(f"Seeded {DB_PATH} with {len(USERS)} users (bcrypt).")


if __name__ == "__main__":
    main()
