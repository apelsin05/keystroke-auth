"""
Ruleaza din radacina proiectului:
    .venv\\Scripts\\python scripts\\generate_impostor_logins.py
"""
import sqlite3, json, uuid, random, math
from datetime import datetime, timedelta
import os

DB_PATH   = os.path.join(os.path.dirname(__file__), '..', 'data', 'keystroke_auth.db')
USER_ID   = '5fa86b33-5143-4577-8b75-1e840c78fd26'
DEVICE_ID = '73d93c5a-511b-4f7a-b828-38529ffc02c2'

PASSWORD_KEYS = ['p', 'a', 'r', 'o', 'l', 'a', '1', '!']

random.seed(42)

GENUINE_PROFILE = {
    'mean_dwell':  {'mean': 96.0,  'variation': 20.0},
    'std_dwell':   {'mean': 18.0,  'variation': 8.0},
    'mean_flight': {'mean': 189.0, 'variation': 80.0},
    'std_flight':  {'mean': 60.0,  'variation': 30.0},
}
GENUINE_THRESHOLD = 4.5


def generate_impostor_events(attempt_num):
    if attempt_num <= 10:
        base_dwell, base_flight = random.uniform(280, 480), random.uniform(600, 950)
        dwell_var, flight_var   = 0.25, 0.35
    else:
        base_dwell, base_flight = random.uniform(200, 350), random.uniform(400, 750)
        dwell_var, flight_var   = 0.40, 0.45

    events, current_time = [], random.uniform(1000, 10000)
    for pos, key in enumerate(PASSWORD_KEYS):
        dwell  = max(80, base_dwell * (1 + random.uniform(-dwell_var, dwell_var)))
        down_t = current_time
        up_t   = down_t + dwell
        flight = None if pos == 0 else max(50, base_flight * (1 + random.uniform(-flight_var, flight_var)))

        events.append({
            'key': key, 'position': pos,
            'downTime': round(down_t, 3), 'upTime': round(up_t, 3),
            'dwellTime': round(dwell, 3), 'unreliable': False,
            'flightTime': round(flight, 3) if flight is not None else None,
        })

        if pos < len(PASSWORD_KEYS) - 1:
            next_flight  = max(50, base_flight * (1 + random.uniform(-flight_var, flight_var)))
            current_time = up_t + next_flight

    return events


def compute_features(events):
    dwells  = [e['dwellTime']  for e in events if e.get('dwellTime') and e['dwellTime'] > 0]
    flights = [e['flightTime'] for e in events
               if e.get('flightTime') is not None and not e.get('unreliable')]
    if not dwells or not flights:
        return None

    def median(vals):
        s = sorted(vals); mid = len(s) // 2
        return (s[mid-1] + s[mid]) / 2 if len(s) % 2 == 0 else s[mid]
    def mad(vals):
        m = median(vals)
        return max(median([abs(v - m) for v in vals]), 1e-6)

    return {
        'mean_dwell':  sum(dwells)  / len(dwells),
        'std_dwell':   mad(dwells),
        'mean_flight': sum(flights) / len(flights),
        'std_flight':  mad(flights),
    }


def estimate_keystroke_score(features):
    if not features:
        return 0.0, float('inf')
    score_raw = sum(
        abs(features[k] - GENUINE_PROFILE[k]['mean']) / GENUINE_PROFILE[k]['variation']
        for k in GENUINE_PROFILE
    )
    ks_score = math.exp(-0.693 * score_raw / GENUINE_THRESHOLD)
    return round(ks_score, 4), round(score_raw, 3)


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    user = conn.execute("SELECT username FROM users WHERE user_id=?", [USER_ID]).fetchone()
    if not user:
        print(f"[EROARE] User {USER_ID} nu exista in baza de date!")
        conn.close(); return
    print(f"[OK] Generare pentru user: {user['username']}\n")

    existing = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE user_id=? AND classification='impostor'",
        [USER_ID]
    ).fetchone()[0]
    print(f"[INFO] Loginuri impostor existente: {existing}")

    base_dt   = datetime(2026, 5, 24, 8, 0, 0)
    generated = []

    for i in range(1, 21):
        login_dt  = base_dt + timedelta(hours=(i - 1) * 3.5)
        timestamp = login_dt.isoformat()
        login_id  = str(uuid.uuid4())
        sample_id = str(uuid.uuid4())
        log_id    = str(uuid.uuid4())

        events   = generate_impostor_events(i)
        features = compute_features(events)
        ks_score, score_raw = estimate_keystroke_score(features)

        ip_score    = round(random.uniform(0.1, 0.3), 3)
        final_score = round(ks_score * 0.6 + ip_score * 0.4, 3)
        decision    = ('reject'    if ks_score < 0.1
                  else 'uncertain' if ks_score < 0.3
                  else 'accept')

        device_info = json.dumps({
            'userAgent':   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'screenWidth': '1920', 'screenHeight': '1080',
            'timezone':    'Europe/London', 'language': 'en-GB',
            'platform':    'Linux x86_64',
        })
        ip_address = f'185.220.{random.randint(100,199)}.{random.randint(1,254)}'

        conn.execute("""
            INSERT INTO login_attempts
              (login_id, user_id, device_id, timestamp, device_info, location,
               ip_address, keystroke_score, ip_score, final_score,
               classification, decision, twofa_passed, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            login_id, USER_ID, DEVICE_ID, timestamp,
            device_info, 'London, GB', ip_address,
            ks_score, ip_score, final_score,
            'impostor', decision, 0, 'rejected_biometric',
        ])

        conn.execute("""
            INSERT INTO keystroke_samples
              (sample_id, user_id, device_id, login_id, final_sequence_json,
               auxiliary_json, has_backspace, confidence, is_truncated,
               attempt_label, usable_for_training, usable_for_evaluation, recorded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            sample_id, USER_ID, DEVICE_ID, login_id,
            json.dumps(events), json.dumps([]),
            0, 'normal', 0,
            'test_impostor', 0, 1, timestamp,
        ])

        conn.execute("""
            INSERT INTO ml_log
              (log_id, timestamp, event_type, user_id, device_id, login_id,
               n_samples, mean_dwell_ms, std_dwell_ms, mean_flight_ms, std_flight_ms,
               score_raw, threshold, keystroke_score, ip_score, final_score,
               decision, login_status, sample_added, confirmed, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            log_id, timestamp, 'login_keystroke',
            USER_ID, DEVICE_ID, login_id,
            len([e for e in events if e.get('dwellTime')]),
            round(features['mean_dwell'],  3) if features else None,
            round(features['std_dwell'],   3) if features else None,
            round(features['mean_flight'], 3) if features else None,
            round(features['std_flight'],  3) if features else None,
            score_raw, GENUINE_THRESHOLD,
            ks_score, ip_score, final_score,
            decision, 'rejected_biometric', 0, 0,
            f'synthetic_impostor_{"slow" if i <= 10 else "nervous"}',
        ])

        generated.append({
            'i': i, 'timestamp': timestamp,
            'mean_dwell':  round(features['mean_dwell'],  1) if features else 0,
            'mean_flight': round(features['mean_flight'], 1) if features else 0,
            'score_raw': score_raw, 'ks_score': ks_score, 'decision': decision,
        })

    conn.commit()
    conn.close()

    print(f"✓ Inserate {len(generated)} loginuri impostor\n")
    print(f"{'#':>2}  {'Timestamp':20s}  {'mean_dwell':>10}  {'mean_flight':>11}  "
          f"{'raw_score':>9}  {'ks_score':>8}  {'Decision'}")
    print("-" * 85)
    for g in generated:
        print(f"{g['i']:>2}  {g['timestamp']:20s}  {g['mean_dwell']:>9.1f}ms  "
              f"{g['mean_flight']:>10.1f}ms  {g['score_raw']:>9.3f}  "
              f"{g['ks_score']:>8.4f}  {g['decision']}")

    print(f"\n[NOTE] Profilul genuine are mean_dwell~96ms si mean_flight~189ms.")
    print("[NOTE] Impostorii generati sunt de 3-5x mai lenti → reject consistent.")


if __name__ == '__main__':
    main()
