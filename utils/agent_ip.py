import csv
import uuid
import requests
from datetime import datetime

KNOWN_IPS_HEADERS = [
    'ip_id', 'user_id', 'ip_address', 'country', 'city',
    'isp', 'first_seen', 'last_seen', 'times_seen', 'trusted'
]

def get_ip_info(ip_address):
    print(f"[IP DEBUG] ip_address primit: '{ip_address}'")
    if ip_address in ('127.0.0.1', '::1', 'localhost'):
        return {'country': 'LOCAL', 'city': 'LOCAL', 'isp': 'LOCAL'}
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'city':    data.get('city'),
                'isp':     data.get('isp')
            }
    except Exception:
        pass
    return {'country': None, 'city': None, 'isp': None}


def score_ip(user_id, ip_address, known_ips_csv):
    try:
        with open(known_ips_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['user_id'] == user_id and row['ip_address'] == ip_address:
                    return 1.0
    except FileNotFoundError:
        pass
    return 0.0


def record_ip(user_id, ip_address, ip_info, known_ips_csv):
    # Asigură că fișierul există
    try:
        open(known_ips_csv, 'r').close()
    except FileNotFoundError:
        with open(known_ips_csv, 'w', newline='', encoding='utf-8') as f:
            csv.DictWriter(f, fieldnames=KNOWN_IPS_HEADERS).writeheader()

    # Citește toate rândurile
    with open(known_ips_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    now = datetime.utcnow().isoformat()
    found = False

    for row in rows:
        if row['user_id'] == user_id and row['ip_address'] == ip_address:
            row['last_seen']  = now
            row['times_seen'] = int(row['times_seen']) + 1
            found = True
            break

    if not found:
        rows.append({
            'ip_id':      str(uuid.uuid4()),
            'user_id':    user_id,
            'ip_address': ip_address,
            'country':    ip_info.get('country'),
            'city':       ip_info.get('city'),
            'isp':        ip_info.get('isp'),
            'first_seen': now,
            'last_seen':  now,
            'times_seen': 1,
            'trusted':    0
        })

    with open(known_ips_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=KNOWN_IPS_HEADERS)
        writer.writeheader()
        writer.writerows(rows)