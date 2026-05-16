import sqlite3

db = sqlite3.connect("data/keystroke_auth.db")

count = db.execute("SELECT COUNT(*) FROM keystroke_samples;").fetchone()[0]

print("keystroke_samples:", count)

db.close()