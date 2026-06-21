
# import sqlite3
# conn = sqlite3.connect('data/keystroke_auth.db')
# conn.row_factory = sqlite3.Row
# cur = conn.cursor()
# cur.execute('''
#     SELECT attempt_label, confidence, usable_for_training, COUNT(*) as cnt
#     FROM keystroke_samples
#     WHERE device_id = (SELECT device_id FROM devices WHERE token=?)
#     GROUP BY attempt_label, confidence, usable_for_training
# ''', ['5f73378b-337c-4600-9e7c-6398562f9ff9'])
# for r in cur.fetchall():
#     print(dict(r))
# conn.close()


# import sqlite3
# conn = sqlite3.connect('data/keystroke_auth.db')
# conn.row_factory = sqlite3.Row
# cur = conn.cursor()
# cur.execute('SELECT profile_id, user_id, created_at, is_active FROM face_profiles ORDER BY created_at DESC')
# for r in cur.fetchall():
#     print(dict(r))
# conn.close()


# import sqlite3, json
# conn = sqlite3.connect('data/keystroke_auth.db')
# conn.row_factory = sqlite3.Row
# cur = conn.cursor()
# cur.execute('SELECT embedding_json FROM face_profiles WHERE is_active=1 LIMIT 1')
# row = cur.fetchone()
# emb = json.loads(row['embedding_json'])
# print(f'Tip: {type(emb)}')
# print(f'Lungime vector: {len(emb)}')
# print(f'Primele 5 valori: {emb[:5]}')
# print(f'Min: {min(emb):.4f}  Max: {max(emb):.4f}')
# conn.close()

# Un embedding Facenet e un vector de 128 de numere float. Fiecare număr reprezintă o caracteristică abstractă a feței 
# Lungime vector: 128
# Primele 5 valori: [-0.0842, 0.1253, -0.3401, 0.0921, 0.2187]
# Min: -1.2341  Max: 1.4562
# Când compara două fețe, calculeaza distanța cosinus între cele două vectori de 128 valori. 
# Dacă vectorii "pointează" în aceeași direcție → distanță mică → aceeași persoană. 
# Dacă sunt aproape perpendiculari sau opuși → distanță mare → persoane diferite.




