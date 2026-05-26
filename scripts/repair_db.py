"""
Run from project root: .venv\\Scripts\\python scripts\\repair_db.py
"""
import sqlite3, os, shutil
from datetime import datetime

DB_PATH   = os.path.join(os.path.dirname(__file__), '..', 'data', 'keystroke_auth.db')
BACKUP    = DB_PATH + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
RECOVERED = DB_PATH + ".recovered"

shutil.copy2(DB_PATH, BACKUP)
print(f"Backup salvat: {BACKUP}")

src = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
dst = sqlite3.connect(RECOVERED)

recovered, skipped = 0, 0
for line in src.iterdump():
    try:
        dst.execute(line)
        recovered += 1
    except Exception as e:
        print(f"  [skip] {e}")
        skipped += 1

dst.commit()
src.close()
dst.close()

os.remove(DB_PATH)
shutil.move(RECOVERED, DB_PATH)

print(f"\n[OK] Recuperare finalizata: {recovered} linii salvate, {skipped} sarite.")
print("Acum poti rula generate_impostor_logins.py.")
