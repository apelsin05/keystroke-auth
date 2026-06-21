from utils.database import init_db, get_db
init_db()
db = get_db()

user = db.execute("SELECT user_id FROM users WHERE email='bancilanama@gmail.com'").fetchone()
uid = user['user_id']

# Cel mai folosit dispozitiv
dev_main = '73d93c5a-511b-4f7a-b828-38529ffc02c2'
# Ultimul dispozitiv (azi)
dev_latest = '5618bb77-baa0-4690-b7dd-5e04ae8b1c0a'

for label, dev_id in [('DISPOZITIV PRINCIPAL (22 loginuri)', dev_main),
                      ('DISPOZITIV AZI (2 loginuri)', dev_latest)]:
    print('=' * 60)
    print(label)
    print('=' * 60)
    row = db.execute("""
        SELECT device_info, ip_address, timestamp
        FROM login_attempts
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, [dev_id]).fetchone()
    if row:
        print('IP         :', row['ip_address'])
        print('Timestamp  :', row['timestamp'])
        print('Device info:', row['device_info'])
    else:
        print('Nicio inregistrare gasita.')
    print()
