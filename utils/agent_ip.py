"""
agent_ip.py
-----------
Agentul de analiza contextuala a adresei IP.
Versiunea SQLite: inlocuieste operatiile pe known_ips.csv.
"""

import uuid
import requests
from datetime import datetime
from utils.database import get_db, insert, fetchone, update, execute_query


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


def score_ip(user_id, ip_address):
    """
    Returneaza 1.0 daca IP-ul e cunoscut pentru acest user, 0.0 altfel.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    row = execute_query(
        "SELECT ip_id FROM known_ips WHERE user_id = ? AND ip_address = ? LIMIT 1",
        [user_id, ip_address]
    )
    return 1.0 if row else 0.0


def record_ip(user_id, ip_address, ip_info):
    """
    Adauga sau actualizeaza un IP in known_ips.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    now = datetime.utcnow().isoformat()
    existing = execute_query(
        "SELECT ip_id, times_seen FROM known_ips WHERE user_id = ? AND ip_address = ? LIMIT 1",
        [user_id, ip_address]
    )
    if existing:
        update('known_ips',
               {'last_seen': now, 'times_seen': existing[0]['times_seen'] + 1},
               {'ip_id': existing[0]['ip_id']})
    else:
        insert('known_ips', {
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