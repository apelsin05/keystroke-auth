import sys, os, json, sqlite3, argparse, numpy as np
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument('--db', default=None)
args = parser.parse_args()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = args.db if args.db else os.path.join(BASE_DIR, 'data', 'keystroke_auth.db')
OUT_PATH = os.path.join(BASE_DIR, 'test_farfrr_rezultate.txt')

if not os.path.exists(DB_PATH):
    print(f"[EROARE] DB negasit: {DB_PATH}")
    sys.exit(1)

sys.path.insert(0, os.path.join(BASE_DIR, 'utils'))
from agent_keystroke import (
    extract_features,
    train_manhattan_profile,
    score_manhattan_scaled,
    calibrate_threshold,
    _raw_to_keystroke_score,
)

USER_EMAILS = [
    'vasilebanc@gmail.com',
    'mcraciun@ugal.ro',
    'ana.drawzz@gmail.com',
]

def decide(score):
    if score >= 0.3:
        return 'accept'
    elif score >= 0.1:
        return 'uncertain'
    else:
        return 'reject'

def load_features(rows):
    result = []
    for row in rows:
        try:
            events = json.loads(row[0])
            feats  = extract_features(events)
            if feats is not None:
                result.append(feats)
        except Exception:
            continue
    return result

def compute_score(feat_dict, profile, threshold):
    raw = score_manhattan_scaled(profile, feat_dict)
    return _raw_to_keystroke_score(raw, threshold)

print("=" * 62)
print(f"  DB: {DB_PATH}")
print("=" * 62)

conn = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)

def fetchall(query, params=()):
    return conn.execute(query, params).fetchall()

USERS = {}
for _email in USER_EMAILS:
    row = conn.execute("SELECT user_id FROM users WHERE email = ?", (_email,)).fetchone()
    if row:
        USERS[_email] = row[0]
    else:
        print(f"  [SKIP] Email negasit: {_email}")

all_results = {}

for email, uid in USERS.items():
    print(f"\n{'=' * 62}")
    print(f"  USER: {email}")
    print(f"{'=' * 62}")

    devs = fetchall("""
        SELECT device_id, COUNT(*) as n
        FROM keystroke_samples
        WHERE user_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift')
        GROUP BY device_id
        HAVING n >= 3
        ORDER BY n DESC
        LIMIT 1
    """, (uid,))

    if not devs:
        print("  [SKIP] Insuficiente probe de enrollment (< 3)")
        continue

    dev_id, n_enroll_raw = devs[0]
    print(f"  Device principal : {dev_id}  ({n_enroll_raw} probe)")

    enroll_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ? AND device_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift')
        ORDER BY recorded_at
    """, (uid, dev_id))

    enrollment_feats = load_features(enroll_rows)
    print(f"  Enrollment features extrase: {len(enrollment_feats)}")

    if len(enrollment_feats) < 3:
        print("  [SKIP] Prea putine feature-uri dupa extragere")
        continue

    profile_enroll = train_manhattan_profile(enrollment_feats)
    loo_thr        = calibrate_threshold(enrollment_feats)
    print(f"  Prag LOO calibrat: {loo_thr:.3f}")

    genuine_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ? AND device_id = ?
          AND attempt_label = 'test_genuine'
          AND usable_for_evaluation = 1
    """, (uid, dev_id))

    g_feats = load_features(genuine_rows)

    if not g_feats:
        genuine_rows = fetchall("""
            SELECT final_sequence_json FROM keystroke_samples
            WHERE user_id = ?
              AND attempt_label = 'test_genuine'
              AND usable_for_evaluation = 1
        """, (uid,))
        g_feats = load_features(genuine_rows)

    if not g_feats:
        proxy_rows = fetchall("""
            SELECT final_sequence_json FROM keystroke_samples
            WHERE user_id = ?
              AND attempt_label IN ('enrollment_genuine', 'genuine_drift')
            ORDER BY recorded_at DESC LIMIT 5
        """, (uid,))
        g_feats = load_features(proxy_rows)
        if g_feats:
            print("  [WARN] Fara test_genuine — folosim ultimele 5 enrollment ca proxy")

    g_scores    = [compute_score(f, profile_enroll, loo_thr) for f in g_feats]
    g_decisions = [decide(s) for s in g_scores]

    all_genuine_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ?
          AND attempt_label IN ('enrollment_genuine', 'genuine_drift', 'test_genuine')
    """, (uid,))
    all_genuine_feats = load_features(all_genuine_rows)

    if len(all_genuine_feats) >= 3:
        profile_full  = train_manhattan_profile(all_genuine_feats)
        loo_thr_full  = calibrate_threshold(all_genuine_feats)
        print(f"  Profil complet (FAR): {len(all_genuine_feats)} probe genuine")
    else:
        profile_full = profile_enroll
        loo_thr_full = loo_thr
        print("  [WARN] Profil complet insuficient — folosim enrollment pentru FAR")

    imp_rows = fetchall("""
        SELECT final_sequence_json FROM keystroke_samples
        WHERE user_id = ?
          AND attempt_label = 'test_impostor'
          AND usable_for_evaluation = 1
    """, (uid,))

    i_feats     = load_features(imp_rows)
    i_scores    = [compute_score(f, profile_full, loo_thr_full) for f in i_feats]
    i_decisions = [decide(s) for s in i_scores]

    print(f"  Genuine sesiuni : {len(g_scores)}")
    print(f"  Impostor sesiuni: {len(i_scores)}  (doar date reale)")

    if not g_scores:
        print("  [SKIP] Nicio proba genuina disponibila")
        continue

    if not i_scores:
        print("  [SKIP] Nicio proba impostor reala disponibila — nu se evalueaza FAR")
        continue

    TP          = g_decisions.count('accept')
    G_uncertain = g_decisions.count('uncertain')
    FN          = g_decisions.count('reject')

    FP          = i_decisions.count('accept')
    I_uncertain = i_decisions.count('uncertain')
    TN          = i_decisions.count('reject')

    FAR = FP / len(i_scores) if i_scores else 0.0
    FRR = FN / len(g_scores) if g_scores else 0.0

    print(f"\n  Decizii agent keystroke (accept / uncertain / reject):")
    print(f"  +------------------+---------+-----------+---------+")
    print(f"  |                  | accept  | uncertain | reject  |")
    print(f"  +------------------+---------+-----------+---------+")
    print(f"  |  Real GENUINE    |  {TP:<6} |  {G_uncertain:<8} |  {FN:<6} |")
    print(f"  |  Real IMPOSTOR   |  {FP:<6} |  {I_uncertain:<8} |  {TN:<6} |")
    print(f"  +------------------+---------+-----------+---------+")
    print(f"\n  FAR  = {FP}/{len(i_scores)} = {FAR:.4f}  ({FAR*100:.1f}%)  [impostori cu decizie 'accept']")
    print(f"  FRR  = {FN}/{len(g_scores)} = {FRR:.4f}  ({FRR*100:.1f}%)  [genuine cu decizie 'reject']")
    print(f"  Zona incerta genuine  : {G_uncertain}/{len(g_scores)}  (ar declansa 2FA)")
    print(f"  Zona incerta impostor : {I_uncertain}/{len(i_scores)}  (ar declansa 2FA)")

    thresholds = np.arange(0.0, 1.01, 0.01)
    far_list, frr_list = [], []
    for t in thresholds:
        fp_ = sum(1 for s in i_scores if s >= t)
        tn_ = sum(1 for s in i_scores if s <  t)
        fn_ = sum(1 for s in g_scores if s <  t)
        tp_ = sum(1 for s in g_scores if s >= t)
        far_list.append(fp_ / (fp_ + tn_) if (fp_ + tn_) > 0 else 0.0)
        frr_list.append(fn_ / (fn_ + tp_) if (fn_ + tp_) > 0 else 1.0)

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
        TP=TP, G_uncertain=G_uncertain, FN=FN,
        FP=FP, I_uncertain=I_uncertain, TN=TN,
        FAR=FAR, FRR=FRR, EER=EER, EER_threshold=EER_thr,
        n_genuine=len(g_scores), n_impostor=len(i_scores),
        genuine_scores=g_scores, impostor_scores=i_scores,
        far_curve=far_list, frr_curve=frr_list,
        thresholds=thresholds.tolist(),
    )

conn.close()

lines = [
    "EVALUARE FAR/FRR KEYSTROKE DYNAMICS",
    f"Generat: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    f"Algoritm: Manhattan Scaled Distance + calibrare LOO",
    f"Decizii: accept (>= 0.3) | uncertain (0.1-0.3) | reject (< 0.1)",
    f"DB: {DB_PATH}",
    "=" * 62, "",
]

if not all_results:
    lines.append("Niciun utilizator evaluat — lipsesc date reale de test_impostor.")
else:
    for email, r in all_results.items():
        lines += [
            f"Utilizator: {email}",
            f"  Device evaluat   : {r['device_id']}",
            f"  Enrollment       : {r['n_enrollment']} probe",
            f"  Profil complet   : {r['n_full_genuine']} probe (enrollment + test_genuine)",
            f"  Prag LOO calibrat: {r['loo_threshold']:.3f}",
            f"  Genuine test     : {r['n_genuine']} sesiuni",
            f"  Impostor test    : {r['n_impostor']} sesiuni",
            "",
            f"  DECIZII AGENT KEYSTROKE:",
            f"  Genuine  — accept: {r['TP']}  uncertain: {r['G_uncertain']}  reject: {r['FN']}",
            f"  Impostor — accept: {r['FP']}  uncertain: {r['I_uncertain']}  reject: {r['TN']}",
            "",
            f"  FAR = {r['FAR']*100:.2f}%  (impostori cu decizie 'accept')",
            f"  FRR = {r['FRR']*100:.2f}%  (genuine cu decizie 'reject')",
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
