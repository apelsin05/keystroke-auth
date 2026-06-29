"""
Evaluare FAR/FRR Keystroke Dynamics — doar date reale
======================================================
Rulează din directorul proiectului:
    .venv\\Scripts\\python.exe test_farfrr.py

Sau cu un DB extern (ex: exportat de pe server):
    .venv\\Scripts\\python.exe test_farfrr.py --db calea/catre/keystroke_auth.db

Ce face:
  1. Încarcă probele de enrollment și construiește profilul Manhattan per user/device
  2. Calibrează pragul LOO
  3. Evaluează pe genuine + impostor REALE (fără sintetici)
     - Dacă nu există test_impostor pe device-ul principal → fallback orice device
     - Dacă nu există deloc → utilizatorul este SKIP (nu se inventează date)
  4. Calculează matricea de confuzie, FAR, FRR, EER
  5. Scrie rezultatele în test_farfrr_rezultate.txt
"""

import sys, os, json, sqlite3, argparse, numpy as np
from datetime import datetime

# ── Argumente CLI ──────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Evaluare FAR/FRR keystroke — date reale")
parser.add_argument(
    '--db',
    default=None,
    help="Calea către keystroke_auth.db (implicit: data/keystroke_auth.db din directorul scriptului)"
)
args = parser.parse_args()

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = args.db if args.db else os.path.join(BASE_DIR, 'data', 'keystroke_auth.db')
OUT_PATH = os.path.join(BASE_DIR, 'test_farfrr_rezultate.txt')

if not os.path.exists(DB_PATH):
    print(f"[EROARE] DB nu a fost găsit la: {DB_PATH}")
    print("Specifică calea corectă cu --db <cale>")
    sys.exit(1)

sys.path.insert(0, os.path.join(BASE_DIR, 'utils'))
from agent_keystroke import (
    extract_features,
    train_manhattan_profile,
    score_manhattan_scaled,
    calibrate_threshold,
    _raw_to_keystroke_score,
    EPSILON,
)

# Pragul de decizie: scorul 0-1 generat de _raw_to_keystroke_score
# scor >= 0.3 → accept   (analog cu orchestrator.py)
THRESHOLD = 0.3

# ── Utilizatori ────────────────────────────────────────────────────────────────
USER_EMAILS = [
    'vasilebanc@gmail.com',
    'mcraciun@ugal.ro',
    'ana.drawzz@gmail.com',   
]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def load_features_from_rows(rows):
    """Parsează JSON și extrage feature-uri din rânduri DB."""
    result = []
    for row in rows:
        try:
            events = json.loads(row[0])
            feats = extract_features(events)
            if feats is not None:
                result.append(feats)
        except Exception:
            continue
    return result


def score_features(feat_dict, profile, threshold):
    """Scor 0.0-1.0 pentru un feature dict față de un profil Manhattan."""
    raw = score_manhattan_scaled(profile, feat_dict)
    return _raw_to_keystroke_score(raw, threshold)


# ─────────────────────────────────────────────────────────────────────────────
# CONECTARE DB
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 62)
print(f"  DB: {DB_PATH}")
print("=" * 62)

conn = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)

def fetchall(query, params=()):
    cur = conn.execute(query, params)
    return cur.fetchall()

# Rezolvă user_id-urile din emailuri
USERS = {}
for _email in USER_EMAILS:
    row = conn.execute("SELECT user_id FROM users WHERE email = ?", (_email,)).fetchone()
    if row:
        USERS[_email] = row[0]
    else:
        print(f"  [SKIP] Email negasit in DB: {_email}")

# ─────────────────────────────────────────────────────────────────────────────
# EVALUARE PER USER
# ─────────────────────────────────────────────────────────────────────────────
all_results = {}

for email, uid in USERS.items():
    print(f"\n{'=' * 62}")
    print(f"  USER: {email}")
    print(f"{'=' * 62}")

    # ── Alege device-ul cu cei mai mulți enrollment normali ──────────────────
    devs = fetchall("""
        SELECT device_id, COUNT(*) as n
        FROM keystroke_samples
        WHERE user_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift')
          AND confidence = 'normal'
        GROUP BY device_id
        HAVING n >= 3
        ORDER BY n DESC
        LIMIT 1
    """, (uid,))

    if not devs:
        print(f"  [SKIP] Insuficiente probe de enrollment (< 3 normale)")
        continue

    dev_id, n_enroll_raw = devs[0]
    print(f"  Device principal : {dev_id}  ({n_enroll_raw} probe normale)")

    # ── Încarcă enrollment ───────────────────────────────────────────────────
    enroll_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ? AND device_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift')
          AND confidence = 'normal'
        ORDER BY recorded_at
    """, (uid, dev_id))

    enrollment_feats = load_features_from_rows(enroll_rows)
    print(f"  Enrollment features extrase: {len(enrollment_feats)}")

    if len(enrollment_feats) < 3:
        print(f"  [SKIP] Prea putine feature-uri dupa extragere")
        continue

    # ── Construiește profil enrollment și calibrează prag LOO ───────────────
    # Profilul de enrollment rămâne separat — e folosit pentru FRR (test_genuine
    # e scorat față de profilul pe care NU l-a văzut la training).
    profile_enroll = train_manhattan_profile(enrollment_feats)
    loo_thr = calibrate_threshold(enrollment_feats)
    print(f"  Prag LOO calibrat: {loo_thr:.3f}")

    # ── Scoruri genuine (FRR) ────────────────────────────────────────────────
    # Scorăm test_genuine față de profilul de enrollment (fără leakage).
    genuine_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ? AND device_id = ?
          AND attempt_label = 'test_genuine'
          AND confidence = 'normal' AND usable_for_evaluation = 1
    """, (uid, dev_id))

    g_feats = load_features_from_rows(genuine_rows)

    # Fallback: orice device al aceluiași user
    if not g_feats:
        genuine_rows = fetchall("""
            SELECT final_sequence_json FROM keystroke_samples
            WHERE user_id = ?
              AND attempt_label = 'test_genuine'
              AND confidence = 'normal' AND usable_for_evaluation = 1
        """, (uid,))
        g_feats = load_features_from_rows(genuine_rows)

    if not g_feats:
        print("  [SKIP] Nicio proba test_genuine disponibila — nu se calculeaza FRR")

    g_scores = [score_features(f, profile_enroll, loo_thr) for f in g_feats]

    # ── Profil complet pentru FAR (enrollment + test_genuine) ────────────────
    # Impostorul atacă un sistem matur care a văzut toate sesiunile legitime.
    all_genuine_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift', 'test_genuine')
          AND confidence = 'normal'
    """, (uid,))
    all_genuine_feats = load_features_from_rows(all_genuine_rows)

    if len(all_genuine_feats) >= 3:
        profile_full = train_manhattan_profile(all_genuine_feats)
        print(f"  Profil complet (FAR): {len(all_genuine_feats)} probe genuine")
    else:
        profile_full = profile_enroll
        print(f"  [WARN] Profil complet insuficient — folosim enrollment pentru FAR")

    # ── Scoruri impostor reale (FAR) ─────────────────────────────────────────
    imp_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ? AND device_id = ?
          AND attempt_label = 'test_impostor'
          AND confidence = 'normal' AND usable_for_evaluation = 1
    """, (uid, dev_id))

    # Fallback: orice device
    if not imp_rows:
        imp_rows = fetchall("""
            SELECT final_sequence_json FROM keystroke_samples
            WHERE user_id = ?
              AND attempt_label = 'test_impostor'
              AND confidence = 'normal' AND usable_for_evaluation = 1
        """, (uid,))

    i_feats = load_features_from_rows(imp_rows)
    i_scores = [score_features(f, profile_full, loo_thr) for f in i_feats]

    print(f"  Genuine sesiuni : {len(g_scores)}  (fata de profil enrollment)")
    print(f"  Impostor sesiuni: {len(i_scores)}  (fata de profil complet, doar date reale)")

    if not g_scores:
        print("  [SKIP] Nicio proba genuina disponibila")
        continue

    if not i_scores:
        print("  [SKIP] Nicio proba impostor reala disponibila — nu se evalueaza FAR")
        continue

    # ── Matricea de confuzie ──────────────────────────────────────────────────
    TP = sum(1 for s in g_scores if s >= THRESHOLD)
    FN = sum(1 for s in g_scores if s <  THRESHOLD)
    TN = sum(1 for s in i_scores if s <  THRESHOLD)
    FP = sum(1 for s in i_scores if s >= THRESHOLD)

    FAR = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    FRR = FN / (FN + TP) if (FN + TP) > 0 else 0.0

    print(f"\n  Threshold decizie: {THRESHOLD}")
    print(f"\n  +------------------+--------------+--------------+")
    print(f"  |                  | Pred. ACCEPT | Pred. REJECT |")
    print(f"  +------------------+--------------+--------------+")
    print(f"  |  Real GENUINE    |  TP = {TP:<6}  |  FN = {FN:<6}  |")
    print(f"  |  Real IMPOSTOR   |  FP = {FP:<6}  |  TN = {TN:<6}  |")
    print(f"  +------------------+--------------+--------------+")
    print(f"\n  FAR = {FP}/({FP}+{TN}) = {FAR:.4f}  ({FAR*100:.1f}%)")
    print(f"  FRR = {FN}/({FN}+{TP}) = {FRR:.4f}  ({FRR*100:.1f}%)")

    # ── EER ───────────────────────────────────────────────────────────────────
    thresholds = np.arange(0.0, 1.01, 0.01)
    far_list, frr_list = [], []
    for t in thresholds:
        tp = sum(1 for s in g_scores if s >= t)
        fn = sum(1 for s in g_scores if s <  t)
        tn = sum(1 for s in i_scores if s <  t)
        fp = sum(1 for s in i_scores if s >= t)
        far_list.append(fp / (fp + tn) if (fp + tn) > 0 else 0.0)
        frr_list.append(fn / (fn + tp) if (fn + tp) > 0 else 1.0)

    far_np  = np.array(far_list)
    frr_np  = np.array(frr_list)
    eer_idx = int(np.argmin(np.abs(far_np - frr_np)))
    EER     = float((far_np[eer_idx] + frr_np[eer_idx]) / 2)
    EER_thr = float(thresholds[eer_idx])

    print(f"  EER aprox {EER:.4f} ({EER*100:.1f}%)  la threshold optim = {EER_thr:.2f}")
    print(f"\n  Scoruri genuine : min={min(g_scores):.3f}  max={max(g_scores):.3f}  avg={np.mean(g_scores):.3f}")
    print(f"  Scoruri impostor: min={min(i_scores):.3f}  max={max(i_scores):.3f}  avg={np.mean(i_scores):.3f}")

    all_results[email] = dict(
        device_id=dev_id,
        n_enrollment=n_enroll_raw,
        n_full_genuine=len(all_genuine_feats),
        loo_threshold=loo_thr,
        TP=TP, FN=FN, FP=FP, TN=TN,
        FAR=FAR, FRR=FRR, EER=EER, EER_threshold=EER_thr,
        n_genuine=len(g_scores), n_impostor=len(i_scores),
        genuine_scores=g_scores, impostor_scores=i_scores,
        far_curve=far_list, frr_curve=frr_list,
        thresholds=thresholds.tolist(),
    )

conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# SALVARE REZULTATE
# ─────────────────────────────────────────────────────────────────────────────
lines = [
    "EVALUARE FAR/FRR KEYSTROKE DYNAMICS — DATE REALE",
    f"Generat: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    f"Algoritm: Manhattan Scaled Distance + calibrare LOO",
    f"Nota: FRR = test_genuine vs profil enrollment | FAR = test_impostor vs profil complet (enrollment+test_genuine)",
    f"Threshold decizie: {THRESHOLD}",
    f"DB folosit: {DB_PATH}",
    "=" * 62, "",
]

if not all_results:
    lines.append("Niciun utilizator evaluat — lipsesc date reale de test_impostor.")
else:
    for email, r in all_results.items():
        lines += [
            f"Utilizator: {email}",
            f"  Device evaluat   : {r['device_id']}",
            f"  Enrollment normal: {r['n_enrollment']} sesiuni",
            f"  Profil complet   : {r['n_full_genuine']} probe genuine (enrollment + test_genuine)",
            f"  Prag LOO calibrat: {r['loo_threshold']:.3f}",
            f"  Genuine test     : {r['n_genuine']} sesiuni  (FRR: vs profil enrollment)",
            f"  Impostor test    : {r['n_impostor']} sesiuni  (FAR: vs profil complet)",
            "",
            f"  MATRICEA DE CONFUZIE (threshold={THRESHOLD}):",
            f"  TP={r['TP']}  FN={r['FN']}  FP={r['FP']}  TN={r['TN']}",
            "",
            f"  FAR = {r['FAR']*100:.2f}%",
            f"  FRR = {r['FRR']*100:.2f}%",
            f"  EER aprox {r['EER']*100:.2f}%  (threshold optim = {r['EER_threshold']:.2f})",
            "",
            f"  Scoruri genuine : {[round(s,3) for s in r['genuine_scores']]}",
            f"  Scoruri impostor: {[round(s,3) for s in r['impostor_scores']]}",
            "",
            "-" * 62, "",
        ]

with open(OUT_PATH, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print(f"\n{'=' * 62}")
print(f"Rezultate salvate in: {OUT_PATH}")
print("=" * 62)
