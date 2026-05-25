"""
populate_test_device.py
-----------------------
Populeaza 15 probe keystroke genuine pentru dispozitivul de test,
ca sa depaseasca pragul de enrollment (12) si sa permita testarea
agentului keystroke + agentului facial.

Rulare: python populate_test_device.py
(cu Flask OPRIT)
"""

import json
import uuid
import random
import sqlite3
from datetime import datetime, timedelta

DB_PATH      = 'data/keystroke_auth.db'
DEVICE_TOKEN = '5f73378b-337c-4600-9e7c-6398562f9ff9'
MIN_SAMPLES  = 15   # vrem sa depasim pragul de 12

# ── Gasire device si user ──────────────────────────────────────────────────

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur  = conn.cursor()

cur.execute("SELECT * FROM devices WHERE token=?", [DEVICE_TOKEN])
device = cur.fetchone()

if not device:
    print("EROARE: device_token nu a fost gasit in DB.")
    print("Asigura-te ca Flask-ul e oprit si ai dat cel putin un login cu browserul.")
    conn.close()
    exit(1)

device_id  = device['device_id']
user_id    = device['user_id']
cur_count  = device['login_count']

print(f"Device gasit: {device_id[:8]}...")
print(f"User:         {user_id[:8]}...")
print(f"Login count actual: {cur_count}")

# ── Generare probe sintetice realiste ─────────────────────────────────────

def make_sample(seed_offset=0):
    """
    Genereaza o secventa de taste realista pentru o parola de ~8 caractere.
    Valorile sunt in milisecunde, cu variatie naturala.
    """
    random.seed(42 + seed_offset)

    keys = ['t', 'e', 's', 't', '1', '2', '3', '!']
    events = []
    t = 1000.0  # timp de start fictiv

    for i, key in enumerate(keys):
        dwell  = random.gauss(120, 20)       # ~120ms dwell, variatie normala
        dwell  = max(60, dwell)

        if i == 0:
            flight = None
        else:
            flight = random.gauss(95, 25)    # ~95ms flight
            flight = max(30, flight)

        down_time = t
        up_time   = t + dwell

        events.append({
            'key':        key,
            'position':   i,
            'downTime':   round(down_time, 2),
            'upTime':     round(up_time, 2),
            'dwellTime':  round(dwell, 2),
            'flightTime': round(flight, 2) if flight is not None else None,
            'unreliable': False,
        })

        t = up_time + (flight if flight else 0) + random.gauss(5, 2)

    return events


# ── Inserare probe ────────────────────────────────────────────────────────

samples_needed = max(0, MIN_SAMPLES - cur_count)
print(f"\nInserare {samples_needed} probe noi (target: {MIN_SAMPLES} total)...")

base_time = datetime.utcnow() - timedelta(days=7)

for i in range(samples_needed):
    events    = make_sample(seed_offset=i)
    sample_id = str(uuid.uuid4())
    login_id  = str(uuid.uuid4())
    timestamp = (base_time + timedelta(hours=i * 6)).isoformat()

    cur.execute("""
        INSERT INTO keystroke_samples (
            sample_id, user_id, device_id, login_id,
            final_sequence_json, auxiliary_json,
            has_backspace, confidence, is_truncated,
            attempt_label, usable_for_training, usable_for_evaluation,
            recorded_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        sample_id, user_id, device_id, login_id,
        json.dumps(events), '[]',
        0, 'normal', 0,
        'enrollment_genuine', 1, 1,
        timestamp
    ])

# ── Actualizare login_count pe device ────────────────────────────────────

new_count = cur_count + samples_needed
cur.execute("UPDATE devices SET login_count=? WHERE device_id=?", [new_count, device_id])

conn.commit()
conn.close()

print(f"Done. Login count actualizat: {cur_count} → {new_count}")
print(f"\nAcum poti porni Flask si testa endpointul facial.")
print(f"Keystroke analysis va porni la urmatoarea logare de pe acest browser.")
