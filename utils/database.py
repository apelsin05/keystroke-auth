"""
database.py
-----------
Strat de acces la baza de date SQLite pentru keystroke-auth.
Inlocuieste toate operatiile CSV (pandas read/append/to_csv).

Mod de utilizare:
    from utils.database import get_db, init_db

    init_db()           # apelat o data la pornirea aplicatiei
    db = get_db()       # returneaza conexiunea thread-locala
"""

import sqlite3
import os
import threading

# ── Cale baza de date ──────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'keystroke_auth.db')

# Conexiune thread-locala (Flask poate rula cu mai multe thread-uri)
_local = threading.local()


def get_db():
    """
    Returneaza conexiunea SQLite pentru thread-ul curent.
    O creeaza daca nu exista inca.
    row_factory = sqlite3.Row permite accesul pe nume de coloana (row['user_id']).
    """
    if not hasattr(_local, 'conn') or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        # Activeaza foreign keys (SQLite le are dezactivate implicit)
        _local.conn.execute("PRAGMA foreign_keys = ON")
        _local.conn.execute("PRAGMA journal_mode = WAL")   # scrieri concurente mai sigure
    return _local.conn


def close_db():
    """Inchide conexiunea thread-ului curent (apelat la teardown Flask)."""
    if hasattr(_local, 'conn') and _local.conn:
        _local.conn.close()
        _local.conn = None


# ── Schema ─────────────────────────────────────────────────────────────────

def init_db():
    """
    Creeaza toate tabelele daca nu exista deja.
    Sigur de apelat la fiecare pornire (IF NOT EXISTS).
    """
    db = get_db()
    db.executescript("""
        -- 1. Utilizatori
        CREATE TABLE IF NOT EXISTS users (
            user_id          TEXT PRIMARY KEY,
            email            TEXT UNIQUE NOT NULL,
            username         TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            name             TEXT,
            surname          TEXT,
            phone            TEXT,
            keystroke_enabled INTEGER DEFAULT 1,
            created_at       TEXT NOT NULL
        );

        -- 2. Dispozitive per user
        CREATE TABLE IF NOT EXISTS devices (
            device_id        TEXT PRIMARY KEY,
            user_id          TEXT NOT NULL REFERENCES users(user_id),
            fingerprint_hash TEXT NOT NULL,
            token            TEXT UNIQUE,
            first_seen       TEXT NOT NULL,
            last_seen        TEXT NOT NULL,
            trusted          INTEGER DEFAULT 0,
            login_count      INTEGER DEFAULT 0,
            enrolled         INTEGER DEFAULT 0
        );

        -- 3. Probe de keystroke (blob JSON per sesiune, nu per tasta)
        --    Pastreaza abordarea actuala care functioneaza cu algoritmul ML.
        CREATE TABLE IF NOT EXISTS keystroke_samples (
            sample_id              TEXT PRIMARY KEY,
            user_id                TEXT NOT NULL REFERENCES users(user_id),
            device_id              TEXT NOT NULL REFERENCES devices(device_id),
            login_id               TEXT,
            final_sequence_json    TEXT NOT NULL,
            auxiliary_json         TEXT,
            has_backspace          INTEGER DEFAULT 0,
            confidence             TEXT DEFAULT 'normal',
            is_truncated           INTEGER DEFAULT 0,
            attempt_label          TEXT DEFAULT 'enrollment_genuine',
            usable_for_training    INTEGER DEFAULT 0,
            usable_for_evaluation  INTEGER DEFAULT 0,
            recorded_at            TEXT NOT NULL
        );

        -- 4. Istoricul autentificarilor (logins.csv extins cu campuri ML)
        CREATE TABLE IF NOT EXISTS login_attempts (
            login_id        TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(user_id),
            device_id       TEXT REFERENCES devices(device_id),
            timestamp       TEXT NOT NULL,
            device_info     TEXT,
            location        TEXT,
            ip_address      TEXT,
            keystroke_score REAL,
            ip_score        REAL,
            final_score     REAL,
            classification  TEXT,
            decision        TEXT,
            twofa_passed    INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'active'
        );

        -- 5. Sesiuni Flask
        CREATE TABLE IF NOT EXISTS sessions (
            session_id  TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            status      TEXT DEFAULT 'active',
            created_at  TEXT NOT NULL
        );

        -- 6. Coduri 2FA temporare
        CREATE TABLE IF NOT EXISTS twofa_codes (
            session_id  TEXT PRIMARY KEY,
            code        TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        );

        -- 7. IP-uri cunoscute per user
        CREATE TABLE IF NOT EXISTS known_ips (
            ip_id       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            ip_address  TEXT NOT NULL,
            country     TEXT,
            city        TEXT,
            isp         TEXT,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            times_seen  INTEGER DEFAULT 1,
            trusted     INTEGER DEFAULT 0
        );

        -- 8. Evenimente de securitate
        CREATE TABLE IF NOT EXISTS security_events (
            event_id         TEXT PRIMARY KEY,
            user_id          TEXT NOT NULL REFERENCES users(user_id),
            device_id        TEXT,
            event_type       TEXT NOT NULL,
            timestamp        TEXT NOT NULL,
            details          TEXT,
            confirm_token    TEXT,
            token_expires_at TEXT,
            resolved         INTEGER DEFAULT 0
        );

        -- 9. Audit tehnic 2FA
        CREATE TABLE IF NOT EXISTS auth_audit (
            audit_id              TEXT PRIMARY KEY,
            timestamp             TEXT NOT NULL,
            stage                 TEXT NOT NULL,
            user_id               TEXT,
            email                 TEXT,
            session_id            TEXT,
            device_id             TEXT,
            ip_address            TEXT,
            entered_code_masked   TEXT,
            stored_code_masked    TEXT,
            entered_length        INTEGER,
            stored_length         INTEGER,
            codes_match           INTEGER,
            expires_at            TEXT,
            is_expired            INTEGER,
            twofa_attempts        INTEGER,
            reason                TEXT,
            device_info           TEXT
        );

        -- 10. Log ML (scoruri biometrice per login)
        CREATE TABLE IF NOT EXISTS ml_log (
            log_id               TEXT PRIMARY KEY,
            timestamp            TEXT NOT NULL,
            event_type           TEXT,
            user_id              TEXT,
            device_id            TEXT,
            login_id             TEXT,
            n_samples            INTEGER,
            mean_dwell_ms        REAL,
            std_dwell_ms         REAL,
            mean_flight_ms       REAL,
            std_flight_ms        REAL,
            score_raw            REAL,
            threshold            REAL,
            keystroke_score      REAL,
            ip_score             REAL,
            final_score          REAL,
            decision             TEXT,
            login_status         TEXT,
            sample_added         INTEGER,
            confirmed            INTEGER,
            train_mean_dwell     REAL,
            train_std_dwell      REAL,
            train_mean_flight    REAL,
            train_std_flight     REAL,
            notes                TEXT
        );

        -- 11. Profiluri biometrice per user+device (nou - nu exista in CSV)
        CREATE TABLE IF NOT EXISTS user_profiles (
            profile_id   TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL REFERENCES users(user_id),
            device_id    TEXT NOT NULL REFERENCES devices(device_id),
            mean_dwell   REAL,
            std_dwell    REAL,
            mean_flight  REAL,
            std_flight   REAL,
            model_path   TEXT,
            computed_at  TEXT NOT NULL,
            active       INTEGER DEFAULT 1
        );

        -- 12. Profiluri arhivate la re-enrollment
        CREATE TABLE IF NOT EXISTS archived_profiles (
            archive_id  TEXT PRIMARY KEY,
            profile_id  TEXT NOT NULL,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            device_id   TEXT NOT NULL REFERENCES devices(device_id),
            mean_dwell  REAL,
            std_dwell   REAL,
            mean_flight REAL,
            std_flight  REAL,
            archived_at TEXT NOT NULL,
            reason      TEXT
        );

        -- Indecsi pentru query-urile frecvente
        CREATE INDEX IF NOT EXISTS idx_devices_user       ON devices(user_id);
        CREATE INDEX IF NOT EXISTS idx_ks_user_device     ON keystroke_samples(user_id, device_id);
        CREATE INDEX IF NOT EXISTS idx_logins_user        ON login_attempts(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_user      ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_known_ips_user     ON known_ips(user_id, ip_address);
        CREATE INDEX IF NOT EXISTS idx_sec_events_user    ON security_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_ml_log_user_device ON ml_log(user_id, device_id);
    
        -- Tabele pentru agentul de recunoastere faciala
        CREATE TABLE IF NOT EXISTS face_profiles (
            profile_id     TEXT PRIMARY KEY,
            user_id        TEXT NOT NULL REFERENCES users(user_id),
            embedding_json TEXT NOT NULL,
            model_name     TEXT DEFAULT 'Facenet',
            created_at     TEXT NOT NULL,
            is_active      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS face_attempts (
            attempt_id   TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            login_id     TEXT NOT NULL,
            distance     REAL,
            decision     TEXT,
            attempted_at TEXT NOT NULL
        );                 
    """)

    # Migrare, adauga face_enabled daca nu exista
    try:
        db.execute("ALTER TABLE users ADD COLUMN face_enabled INTEGER DEFAULT 0")
        db.commit()
    except Exception:
        pass  # coloana exista deja

    db.commit()


# ── Functii de acces generice ───────────────────────────────────────────────

def insert(table, row_dict):
    """
    Insereaza un rand intr-un tabel.
    row_dict: {'coloana': valoare, ...}
    """
    db = get_db()
    cols = ', '.join(row_dict.keys())
    placeholders = ', '.join(['?' for _ in row_dict])
    db.execute(
        f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",
        list(row_dict.values())
    )
    db.commit()


def fetchone(table, where_dict):
    """
    Returneaza primul rand care respecta conditiile din where_dict.
    Exemplu: fetchone('users', {'email': 'ana@test.com'})
    Returneaza sqlite3.Row sau None.
    """
    db = get_db()
    conditions = ' AND '.join([f"{k} = ?" for k in where_dict])
    cursor = db.execute(
        f"SELECT * FROM {table} WHERE {conditions} LIMIT 1",
        list(where_dict.values())
    )
    return cursor.fetchone()


def fetchall(table, where_dict=None, order_by=None, limit=None):
    """
    Returneaza toate randurile care respecta conditiile.
    where_dict optional; fara el returneaza tot tabelul.
    """
    db = get_db()
    query = f"SELECT * FROM {table}"
    params = []

    if where_dict:
        conditions = ' AND '.join([f"{k} = ?" for k in where_dict])
        query += f" WHERE {conditions}"
        params = list(where_dict.values())

    if order_by:
        query += f" ORDER BY {order_by}"

    if limit:
        query += f" LIMIT {limit}"

    cursor = db.execute(query, params)
    return cursor.fetchall()


def update(table, set_dict, where_dict):
    """
    Actualizeaza randurile care respecta where_dict cu valorile din set_dict.
    Exemplu: update('devices', {'login_count': 5}, {'device_id': 'abc'})
    """
    db = get_db()
    set_clause   = ', '.join([f"{k} = ?" for k in set_dict])
    where_clause = ' AND '.join([f"{k} = ?" for k in where_dict])
    db.execute(
        f"UPDATE {table} SET {set_clause} WHERE {where_clause}",
        list(set_dict.values()) + list(where_dict.values())
    )
    db.commit()


def delete_where(table, where_dict):
    """
    Sterge randurile care respecta where_dict.
    Exemplu: delete_where('twofa_codes', {'session_id': 'xyz'})
    """
    db = get_db()
    conditions = ' AND '.join([f"{k} = ?" for k in where_dict])
    db.execute(
        f"DELETE FROM {table} WHERE {conditions}",
        list(where_dict.values())
    )
    db.commit()


def execute_query(sql, params=None):
    """
    Executa un query SQL arbitrar si returneaza toate rezultatele.
    Folosit pentru query-uri complexe (JOIN, COUNT, subquery).
    """
    db = get_db()
    cursor = db.execute(sql, params or [])
    return cursor.fetchall()