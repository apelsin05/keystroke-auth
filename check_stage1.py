"""
check_stage1.py
---------------
Verifica modificarile din Etapa 1 fara sa porneasca serverul Flask.
Rulare: python check_stage1.py
"""

print("=" * 60)
print("TEST 1 - Importuri")
print("=" * 60)
try:
    from utils.agent_keystroke import analyze as ks_analyze
    from utils.agent_ip import analyze as ip_analyze
    from utils.orchestrator import decide
    print("OK  agent_keystroke.analyze importat")
    print("OK  agent_ip.analyze importat")
    print("OK  orchestrator.decide importat")
except ImportError as e:
    print("FAIL:", e)

print()
print("=" * 60)
print("TEST 2 - Migrare DB (tabele + coloana face_enabled)")
print("=" * 60)
from utils.database import init_db, get_db
init_db()
db = get_db()

tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
table_names = [t[0] for t in tables]
print("Tabele gasite:", table_names)

for expected in ('face_profiles', 'face_attempts'):
    status = "OK " if expected in table_names else "FAIL"
    print(status + "  " + expected)

cols = db.execute("PRAGMA table_info(users)").fetchall()
col_names = [c[1] for c in cols]
status = "OK " if "face_enabled" in col_names else "FAIL"
print(status + "  coloana face_enabled in users")

print()
print("=" * 60)
print("TEST 3 - Risk matrix orchestrator")
print("=" * 60)
tests = [
    ('insufficient_data', 'accept',    'opted_out', 'allow'),
    ('accept',            'accept',    'opted_out', 'allow'),
    ('accept',            'uncertain', 'opted_out', '2fa'),
    ('uncertain',         'accept',    'opted_out', '2fa'),
    ('uncertain',         'uncertain', 'opted_out', '2fa'),
    ('reject',            'accept',    'opted_out', '2fa_reenrollment'),
]
for ks, ip, face, expected in tests:
    r = decide(ks, ip, face)
    got = r['decision']
    status = "OK " if got == expected else "FAIL"
    print(status + "  ks=" + ks.ljust(18) + " ip=" + ip.ljust(10) + " -> " + got.ljust(20) + " (asteptat: " + expected + ")")

print()
print("=" * 60)
print("TEST 4 - agent_ip.analyze() pe IP necunoscut")
print("=" * 60)
result = ip_analyze('user-test-inexistent', '8.8.8.8')
print("Rezultat:", result)
status = "OK " if result['decision'] == 'uncertain' else "FAIL"
print(status + "  decision=uncertain pentru IP necunoscut")

print()
print("=" * 60)
print("SUMAR: daca toate sunt OK, ruleaza 'python app.py' si testeaza login manual.")
print("=" * 60)
