"""
migrate_csv_to_db.py
--------------------
Script de migrare one-time: copiaza datele din CSV-urile existente
in noua baza de date SQLite.

Ruleaza O SINGURA DATA, inainte de a porni aplicatia cu noul cod.
    python migrate_csv_to_db.py

Daca vrei sa rulezi din nou (de ex. dupa test), sterge keystroke_auth.db
si ruleaza din nou.
"""

import os
import sys
import json
import pandas as pd
import sqlite3

# Adauga directorul curent in path ca sa gaseasca utils/
sys.path.insert(0, os.path.dirname(__file__))

from utils.database import init_db, get_db

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

def csv_path(name):
    return os.path.join(DATA_DIR, name)

def safe_read(filename, **kwargs):
    path = csv_path(filename)
    if not os.path.exists(path):
        print(f"  [SKIP] {filename} nu exista")
        return pd.DataFrame()
    df = pd.read_csv(path, **kwargs)
    print(f"  [OK]   {filename}: {len(df)} randuri")
    return df

def nan_to_none(val):
    """Converteste NaN/NA pandas la None pentru SQLite."""
    try:
        if pd.isna(val):
            return None
    except Exception:
        pass
    return val if val != '' else None


def migrate():
    print("=== Migrare CSV → SQLite ===\n")
    init_db()
    db = get_db()

    # ── 1. users ──────────────────────────────────────────────────────────
    print("1. users.csv")
    df = safe_read('users.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO users
                (user_id, email, username, password_hash, name, surname,
                 phone, keystroke_enabled, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, [
                row['user_id'], row['email'], row['username'],
                row['password_hash'],
                nan_to_none(row.get('name')),
                nan_to_none(row.get('surname')),
                nan_to_none(row.get('phone')),
                int(row.get('keystroke_enabled', 1)),
                row['created_at']
            ])
        except Exception as e:
            print(f"    EROARE user {row.get('email')}: {e}")
    db.commit()

    # ── 2. devices ────────────────────────────────────────────────────────
    print("2. devices.csv")
    df = safe_read('devices.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO devices
                (device_id, user_id, fingerprint_hash, token,
                 first_seen, last_seen, trusted, login_count, enrolled)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, [
                row['device_id'], row['user_id'],
                row['fingerprint_hash'], row['token'],
                row['first_seen'], row['last_seen'],
                int(row.get('trusted', 0)),
                int(row.get('login_count', 0)),
                int(row.get('enrolled', 0))
            ])
        except Exception as e:
            print(f"    EROARE device {row.get('device_id')}: {e}")
    db.commit()

    # ── 3. keystrokes ────────────────────────────────────────────────────
    print("3. keystrokes.csv")
    df = safe_read('keystrokes.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO keystroke_samples
                (sample_id, user_id, device_id, login_id,
                 final_sequence_json, auxiliary_json,
                 has_backspace, confidence, is_truncated,
                 attempt_label, usable_for_training, usable_for_evaluation,
                 recorded_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [
                row['sample_id'], row['user_id'], row['device_id'],
                nan_to_none(row.get('login_id')),
                row['final_sequence_json'],
                nan_to_none(row.get('auxiliary_json')),
                1 if str(row.get('has_backspace', 'False')).lower() in ('true', '1') else 0,
                str(row.get('confidence', 'normal')),
                1 if str(row.get('is_truncated', 'False')).lower() in ('true', '1') else 0,
                str(row.get('attempt_label', 'enrollment_genuine')),
                int(row.get('usable_for_training', 0)),
                int(row.get('usable_for_evaluation', 0)),
                row['recorded_at']
            ])
        except Exception as e:
            print(f"    EROARE sample {row.get('sample_id')}: {e}")
    db.commit()

    # ── 4. logins → login_attempts ───────────────────────────────────────
    print("4. logins.csv → login_attempts")
    df = safe_read('logins.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO login_attempts
                (login_id, user_id, device_id, timestamp, device_info,
                 location, ip_address, status)
                VALUES (?,?,?,?,?,?,?,?)
            """, [
                row['login_id'], row['user_id'],
                nan_to_none(row.get('device_id')),
                row['timestamp'],
                nan_to_none(row.get('device_info')),
                nan_to_none(row.get('location')),
                None,
                str(row.get('status', 'active'))
            ])
        except Exception as e:
            print(f"    EROARE login {row.get('login_id')}: {e}")
    db.commit()

    # ── 5. sessions ───────────────────────────────────────────────────────
    print("5. sessions.csv")
    df = safe_read('sessions.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO sessions
                (session_id, user_id, status, created_at)
                VALUES (?,?,?,?)
            """, [
                row['session_id'], row['user_id'],
                str(row.get('status', 'active')),
                row['created_at']
            ])
        except Exception as e:
            print(f"    EROARE session {row.get('session_id')}: {e}")
    db.commit()

    # ── 6. 2fa_codes ─────────────────────────────────────────────────────
    print("6. 2fa_codes.csv")
    df = safe_read('2fa_codes.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO twofa_codes
                (session_id, code, expires_at)
                VALUES (?,?,?)
            """, [row['session_id'], str(row['code']).zfill(6), row['expires_at']])
        except Exception as e:
            print(f"    EROARE 2fa {row.get('session_id')}: {e}")
    db.commit()

    # ── 7. known_ips ─────────────────────────────────────────────────────
    print("7. known_ips.csv")
    df = safe_read('known_ips.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO known_ips
                (ip_id, user_id, ip_address, country, city, isp,
                 first_seen, last_seen, times_seen, trusted)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, [
                row['ip_id'], row['user_id'], row['ip_address'],
                nan_to_none(row.get('country')),
                nan_to_none(row.get('city')),
                nan_to_none(row.get('isp')),
                row['first_seen'], row['last_seen'],
                int(row.get('times_seen', 1)),
                int(row.get('trusted', 0))
            ])
        except Exception as e:
            print(f"    EROARE ip {row.get('ip_id')}: {e}")
    db.commit()

    # ── 8. security_events ───────────────────────────────────────────────
    print("8. security_events.csv")
    df = safe_read('security_events.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO security_events
                (event_id, user_id, device_id, event_type, timestamp,
                 details, confirm_token, token_expires_at, resolved)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, [
                row['event_id'], row['user_id'],
                nan_to_none(row.get('device_id')),
                row['event_type'], row['timestamp'],
                nan_to_none(row.get('details')),
                nan_to_none(row.get('confirm_token')),
                nan_to_none(row.get('token_expires_at')),
                int(row.get('resolved', 0))
            ])
        except Exception as e:
            print(f"    EROARE event {row.get('event_id')}: {e}")
    db.commit()

    # ── 9. auth_audit ────────────────────────────────────────────────────
    print("9. auth_audit.csv")
    df = safe_read('auth_audit.csv')
    for _, row in df.iterrows():
        try:
            codes_match_val = row.get('codes_match')
            if pd.isna(codes_match_val):
                codes_match_db = None
            else:
                codes_match_db = 1 if str(codes_match_val).lower() in ('true', '1') else 0

            is_expired_val = row.get('is_expired')
            if pd.isna(is_expired_val):
                is_expired_db = None
            else:
                is_expired_db = 1 if str(is_expired_val).lower() in ('true', '1') else 0

            db.execute("""
                INSERT OR IGNORE INTO auth_audit
                (audit_id, timestamp, stage, user_id, email, session_id,
                 device_id, ip_address, entered_code_masked, stored_code_masked,
                 entered_length, stored_length, codes_match, expires_at,
                 is_expired, twofa_attempts, reason, device_info)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [
                row['audit_id'], row['timestamp'], row['stage'],
                nan_to_none(row.get('user_id')),
                nan_to_none(row.get('email')),
                nan_to_none(row.get('session_id')),
                nan_to_none(row.get('device_id')),
                nan_to_none(row.get('ip_address')),
                nan_to_none(row.get('entered_code_masked')),
                nan_to_none(row.get('stored_code_masked')),
                nan_to_none(row.get('entered_length')),
                nan_to_none(row.get('stored_length')),
                codes_match_db,
                nan_to_none(row.get('expires_at')),
                is_expired_db,
                nan_to_none(row.get('twofa_attempts')),
                nan_to_none(row.get('reason')),
                nan_to_none(row.get('device_info'))
            ])
        except Exception as e:
            print(f"    EROARE audit {row.get('audit_id')}: {e}")
    db.commit()

    # ── 10. ml_log ───────────────────────────────────────────────────────
    print("10. ml_log.csv")
    df = safe_read('ml_log.csv')
    for _, row in df.iterrows():
        try:
            db.execute("""
                INSERT OR IGNORE INTO ml_log
                (log_id, timestamp, event_type, user_id, device_id, login_id,
                 n_samples, mean_dwell_ms, std_dwell_ms, mean_flight_ms, std_flight_ms,
                 score_raw, threshold, keystroke_score, ip_score, final_score,
                 decision, login_status, sample_added, confirmed,
                 train_mean_dwell, train_std_dwell, train_mean_flight, train_std_flight,
                 notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [
                row['log_id'], row['timestamp'],
                nan_to_none(row.get('event_type')),
                nan_to_none(row.get('user_id')),
                nan_to_none(row.get('device_id')),
                nan_to_none(row.get('login_id')),
                nan_to_none(row.get('n_samples')),
                nan_to_none(row.get('mean_dwell_ms')),
                nan_to_none(row.get('std_dwell_ms')),
                nan_to_none(row.get('mean_flight_ms')),
                nan_to_none(row.get('std_flight_ms')),
                # score_if din CSV -> score_raw in DB
                nan_to_none(row.get('score_if')),
                # score_svm din CSV -> threshold in DB
                nan_to_none(row.get('score_svm')),
                nan_to_none(row.get('keystroke_score')),
                nan_to_none(row.get('ip_score')),
                nan_to_none(row.get('final_score')),
                nan_to_none(row.get('decision')),
                nan_to_none(row.get('login_status')),
                nan_to_none(row.get('sample_added')),
                nan_to_none(row.get('confirmed')),
                nan_to_none(row.get('train_mean_dwell')),
                nan_to_none(row.get('train_std_dwell')),
                nan_to_none(row.get('train_mean_flight')),
                nan_to_none(row.get('train_std_flight')),
                nan_to_none(row.get('notes'))
            ])
        except Exception as e:
            print(f"    EROARE ml_log {row.get('log_id')}: {e}")
    db.commit()

    # ── Verificare finala ─────────────────────────────────────────────────
    print("\n=== Verificare randuri migrate ===")
    tables = ['users', 'devices', 'keystroke_samples', 'login_attempts',
              'sessions', 'twofa_codes', 'known_ips', 'security_events',
              'auth_audit', 'ml_log', 'user_profiles', 'archived_profiles']
    for t in tables:
        count = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t:<25} {count} randuri")

    print("\nMigrare finalizata.")
    db_size = os.path.getsize(
        os.path.join(os.path.dirname(__file__), 'data', 'keystroke_auth.db')
    )
    print(f"Dimensiune DB: {db_size / 1024:.1f} KB")


if __name__ == '__main__':
    migrate()