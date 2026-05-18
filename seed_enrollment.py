"""
seed_enrollment.py
------------------
Populeaza 10 probe de enrollment pentru dispozitivul VS Code
al utilizatorului bancilanama@gmail.com.

Dupa rulare: device-ul va fi enrolled si ks_analyze va putea
calcula un scor real la urmatorul login.
"""

import json
import uuid
import random
from datetime import datetime, timedelta
from utils.database import init_db, get_db, insert, update, execute_query

random.seed(42)  # reproductibil

init_db()
db = get_db()

# ── Identificare user si device ───────────────────────────────────────────────
user = db.execute(
    "SELECT user_id FROM users WHERE email='bancilanama@gmail.com'"
).fetchone()
assert user, "User negasit"
uid = user['user_id']

DEVICE_ID = '5618bb77-baa0-4690-b7dd-5e04ae8b1c0a'
dev = db.execute(
    "SELECT login_count FROM devices WHERE device_id=?", [DEVICE_ID]
).fetchone()
assert dev, "Device negasit"

current_count = dev['login_count']
print(f"Login count curent: {current_count}")

# ── Generare probe keystroke realiste ─────────────────────────────────────────
# Simulam tastarea unui sir de 8-10 taste cu timinguri consistente
# (aceeasi persoana => media si variatia raman stabile intre probe)

KEYS = ['p', 'a', 's', 's', 'w', 'o', 'r', 'd', '1', '2']

def generate_sample(mean_dwell=105.0, mean_flight=148.0, noise=0.12):
    """
    Genereaza o secventa de events tastatura cu timinguri realiste.
    noise = factor de zgomot relativ (12% variatie naturala).
    """
    events = []
    t = 1000.0  # timestamp start arbitrar (ms)

    for i, key in enumerate(KEYS):
        dwell  = max(40.0, random.gauss(mean_dwell,  mean_dwell  * noise))
        flight = max(20.0, random.gauss(mean_flight, mean_flight * noise)) if i > 0 else None

        down_time = t
        up_time   = t + dwell

        event = {
            'key':        key,
            'position':   i,
            'downTime':   round(down_time,  2),
            'upTime':     round(up_time,    2),
            'dwellTime':  round(dwell,      2),
            'flightTime': round(flight, 2) if flight is not None else None,
            'unreliable': False,
        }
        events.append(event)
        t = up_time + (flight if flight else 0)

    return events

# ── Inserare probe + login_attempts ──────────────────────────────────────────
base_time = datetime(2026, 5, 10, 9, 0, 0)  # incepem de pe 10 mai

for i in range(10):
    login_id   = str(uuid.uuid4())
    sample_id  = str(uuid.uuid4())
    ts         = (base_time + timedelta(hours=i * 3)).isoformat()
    events     = generate_sample()

    # Salveaza proba keystroke
    insert('keystroke_samples', {
        'sample_id':             sample_id,
        'user_id':               uid,
        'device_id':             DEVICE_ID,
        'login_id':              login_id,
        'final_sequence_json':   json.dumps(events),
        'auxiliary_json':        json.dumps([]),
        'has_backspace':         0,
        'confidence':            'normal',
        'is_truncated':          0,
        'attempt_label':         'enrollment_genuine',
        'usable_for_training':   1,
        'usable_for_evaluation': 1,
        'recorded_at':           ts,
    })

    # Salveaza login_attempt corespunzator
    insert('login_attempts', {
        'login_id':        login_id,
        'user_id':         uid,
        'device_id':       DEVICE_ID,
        'timestamp':       ts,
        'device_info':     json.dumps({'userAgent': 'Code/Electron seed', 'platform': 'Win32'}),
        'ip_address':      '127.0.0.1',
        'keystroke_score': 1.0,
        'ip_score':        1.0,
        'final_score':     1.0,
        'classification':  'enrollment',
        'decision':        'allow',
        'twofa_passed':    1,
        'status':          'active',
    })

    print(f"  Proba {i+1:2d} inserata — login_id: {login_id[:8]}... ts: {ts}")

# ── Actualizeaza device ───────────────────────────────────────────────────────
new_count = current_count + 10
update('devices',
       {'login_count': new_count, 'enrolled': 1},
       {'device_id': DEVICE_ID})

print()
print(f"Device actualizat: login_count={new_count}, enrolled=1")
print()
print("Gata. La urmatorul login din VS Code, ks_analyze va calcula un scor real.")
