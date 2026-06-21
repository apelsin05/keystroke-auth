"""
device_fingerprint.py
---------------------
Identificare dispozitiv prin fingerprint SHA256 + token localStorage.
Versiunea SQLite: inlocuieste operatiile pe devices.csv.
"""

import hashlib
import uuid
from datetime import datetime
from utils.database import get_db, insert, update, execute_query

ENROLLMENT_LOGINS = 12


def get_device_info(request):
    return {
        'userAgent':    request.form.get('device_userAgent',    request.headers.get('User-Agent', '')),
        'screenWidth':  request.form.get('device_screenWidth',  ''),
        'screenHeight': request.form.get('device_screenHeight', ''),
        'timezone':     request.form.get('device_timezone',     ''),
        'language':     request.form.get('device_language',     ''),
        'platform':     request.form.get('device_platform',     ''),
    }


def generate_fingerprint_hash(device_info_dict):
    """SHA256 din cei 6 atribute stabile ale dispozitivului → hex 64 caractere."""
    combined = '|'.join([
        str(device_info_dict.get('userAgent',    '')),
        str(device_info_dict.get('screenWidth',  '')),
        str(device_info_dict.get('screenHeight', '')),
        str(device_info_dict.get('timezone',     '')),
        str(device_info_dict.get('language',     '')),
        str(device_info_dict.get('platform',     '')),
    ])
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def generate_device_token():
    return str(uuid.uuid4())


def find_device(user_id, fingerprint, token):
    """
    Cauta device-ul dupa fingerprint si token.
    Returneaza: (status: str, device: dict | None)
    Semnatura simplificata: nu mai primeste calea CSV.

    Statusuri posibile:
      - confident_match  : token + fingerprint se potrivesc
      - browser_updated  : token ok, fingerprint diferit
      - token_cleared    : fingerprint ok, token lipsa/diferit
      - new_device       : niciun match
    """
    db = get_db()

    # Caz 1: token + fingerprint
    if token:
        row = db.execute(
            "SELECT * FROM devices WHERE user_id=? AND token=? AND fingerprint_hash=?",
            [user_id, token, fingerprint]
        ).fetchone()
        if row:
            return 'confident_match', dict(row)

    # Caz 2: token ok, fingerprint diferit (browser updatat)
    if token:
        row = db.execute(
            "SELECT * FROM devices WHERE user_id=? AND token=?",
            [user_id, token]
        ).fetchone()
        if row:
            return 'browser_updated', dict(row)

    # Caz 3: fingerprint ok, token lipsa/diferit (localStorage sters)
    row = db.execute(
        "SELECT * FROM devices WHERE user_id=? AND fingerprint_hash=?",
        [user_id, fingerprint]
    ).fetchone()
    if row:
        return 'token_cleared', dict(row)

    return 'new_device', None


def repair_device_connection(device, status, new_fingerprint, new_token):
    """
    Repara conexiunea dupa browser update sau stergere localStorage.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    if status not in ('browser_updated', 'token_cleared'):
        return None

    now = datetime.utcnow().isoformat()

    if status == 'browser_updated':
        update('devices',
               {'fingerprint_hash': new_fingerprint, 'last_seen': now},
               {'device_id': device['device_id']})

    elif status == 'token_cleared':
        update('devices',
               {'token': new_token, 'last_seen': now},
               {'device_id': device['device_id']})
        return new_token

    return None


def create_device(user_id, fingerprint, token):
    """
    Creeaza un device nou in baza de date.
    Semnatura simplificata: nu mai primeste calea CSV.
    Returneaza dict-ul noului device.
    """
    now       = datetime.utcnow().isoformat()
    device_id = str(uuid.uuid4())

    new_device = {
        'device_id':        device_id,
        'user_id':          user_id,
        'fingerprint_hash': fingerprint,
        'token':            token,
        'first_seen':       now,
        'last_seen':        now,
        'trusted':          0,
        'login_count':      0,
        'enrolled':         0,
    }
    insert('devices', new_device)
    return new_device


def increment_device_login_count(device_id):
    """
    Incrementeaza login_count. Seteaza enrolled=1 la ENROLLMENT_LOGINS.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    db = get_db()
    row = db.execute(
        "SELECT login_count FROM devices WHERE device_id=?", [device_id]
    ).fetchone()

    if not row:
        return

    new_count = row['login_count'] + 1
    enrolled  = 1 if new_count >= ENROLLMENT_LOGINS else 0
    now       = datetime.utcnow().isoformat()

    update('devices',
           {'login_count': new_count, 'enrolled': enrolled, 'last_seen': now},
           {'device_id': device_id})