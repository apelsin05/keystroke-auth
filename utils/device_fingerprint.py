import hashlib
import uuid
import csv
import os
import pandas as pd
from datetime import datetime

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
    """
    Face amprenta unica a device-ului din atributele sale stabile, cu SHA256.
    Rezulta un string hex de 64 de caractere.
    """
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
    """
    Genereaza UUID unic care va fi stocat in browserul utilizatorului
    (localStorage) si trimis la fiecare login pentru identificare.
    """
    return str(uuid.uuid4())


def find_device(user_id, fingerprint, token, devices_csv):
    """
    Cauta device-ul unui user dupa fingerprint si token.
    Returneaza: (status: str, device: dict | None)
    Functia DOAR raporteaza — nu modifica CSV-ul.
    """
    try:
        df = pd.read_csv(devices_csv)
        user_devices = df[df['user_id'] == user_id]
    except Exception:
        return 'new_device', None

    if user_devices.empty:
        return 'new_device', None

    # Caz 1: token + fingerprint se potrivesc = confident match
    if token:
        match = user_devices[
            (user_devices['token'] == token) &
            (user_devices['fingerprint_hash'] == fingerprint)
        ]
        if not match.empty:
            return 'confident_match', match.iloc[0].to_dict()

    # Caz 2: token se potriveste, fingerprint diferit = browser updatat
    if token:
        match = user_devices[user_devices['token'] == token]
        if not match.empty:
            return 'browser_updated', match.iloc[0].to_dict()

    # Caz 3: fingerprint se potriveste, token lipsa/diferit = localStorage sters
    match = user_devices[user_devices['fingerprint_hash'] == fingerprint]
    if not match.empty:
        return 'token_cleared', match.iloc[0].to_dict()

    # Caz 4: niciun match  device necunoscut
    return 'new_device', None


def repair_device_connection(device, status, new_fingerprint, new_token, devices_csv):
    """
    Repara conexiunea daca browser-ul s-a updatat sau token-ul a fost sters.
    Apelata dupa find_device() cand statusul nu e 'confident_match' sau 'new_device'.

    - 'browser_updated' → actualizeaza fingerprint_hash in CSV
    - 'token_cleared'   → actualizeaza token in CSV; returneaza noul token
                          (apelantul trebuie sa il trimita in browser via JS)
    """
    if status not in ('browser_updated', 'token_cleared'):
        return None

    df  = pd.read_csv(devices_csv)
    now = datetime.utcnow().isoformat()
    idx = df[df['device_id'] == device['device_id']].index

    if status == 'browser_updated':
        df.loc[idx, 'fingerprint_hash'] = new_fingerprint
        df.loc[idx, 'last_seen']        = now
        df.to_csv(devices_csv, index=False)
        return None

    if status == 'token_cleared':
        df.loc[idx, 'token']     = new_token
        df.loc[idx, 'last_seen'] = now
        df.to_csv(devices_csv, index=False)
        return new_token


def create_device(user_id, fingerprint, token, devices_csv):
    """
    Creeaza un rand nou in devices.csv pentru un device necunoscut.
    Enrollment incepe de la 0.
    Returneaza dict-ul noului device (ca sa il putem folosi imediat).
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
        'login_count':      0,
        'enrolled':         0,
    }

    with open(devices_csv, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=new_device.keys())
        writer.writerow(new_device)

    return new_device


def increment_device_login_count(device_id, devices_csv):
    """
    Incrementeaza login_count pentru device-ul specificat.
    Daca atinge ENROLLMENT_LOGINS (20), seteaza enrolled=1.
    Actualizeaza si last_seen.
    """
    df  = pd.read_csv(devices_csv)
    idx = df[df['device_id'] == device_id].index

    if idx.empty:
        return

    df.loc[idx, 'login_count'] += 1
    df.loc[idx, 'last_seen']   = datetime.utcnow().isoformat()

    new_count = int(df.loc[idx[0], 'login_count'])
    if new_count >= ENROLLMENT_LOGINS:
        df.loc[idx, 'enrolled'] = 1

    df.to_csv(devices_csv, index=False)