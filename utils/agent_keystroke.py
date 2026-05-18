"""
agent_keystroke.py
------------------
Agentul de analiza biometrica comportamentala (keystroke dynamics).
Versiunea SQLite: inlocuieste operatiile pe keystrokes.csv.

Algoritmul: Manhattan Scaled Detector (Killourhy & Maxion, 2009)
cu MAD pentru robustete si LOO cross-validation pentru calibrare prag.
"""

import json
import math
import uuid
from datetime import datetime
from utils.database import get_db, insert, execute_query

# ── Constante ──────────────────────────────────────────────────────────────

SKIP_KEYS = {'Control', 'Alt', 'Meta', 'Tab', 'Enter', 'ArrowLeft',
             'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End',
             'PageUp', 'PageDown', 'Escape', 'F1', 'F2', 'F3', 'F4',
             'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'}

AUXILIARY_KEYS      = {'Shift', 'CapsLock', 'Backspace'}
MIN_CHARS           = 4
MIN_ENROLLMENT_SAMPLES = 3
EPSILON             = 1e-6


# ── Utilitati statistice ───────────────────────────────────────────────────

def _median(values):
    if not values:
        return 0.0
    sorted_v = sorted(values)
    mid = len(sorted_v) // 2
    if len(sorted_v) % 2 == 0:
        return (sorted_v[mid - 1] + sorted_v[mid]) / 2
    return sorted_v[mid]


def _mad(values):
    """Median Absolute Deviation — mai robusta decat std la outlieri."""
    if len(values) < 2:
        return EPSILON
    med        = _median(values)
    deviations = [abs(v - med) for v in values]
    result     = _median(deviations)
    return max(result, EPSILON)


# ── Extragere features din secventa de events ──────────────────────────────

def extract_features(cleaned_events):
    """
    Extrage vectorul de 4 caracteristici dintr-o lista de events curatate.
    Ignora flight times marcate 'unreliable' (cand a existat backspace intre taste).
    Returneaza None daca datele sunt insuficiente.
    """
    dwell_times  = []
    flight_times = []

    for e in cleaned_events:
        dw         = e.get('dwellTime')
        fl         = e.get('flightTime')
        unreliable = e.get('unreliable', False)

        if dw is not None and dw > 0:
            dwell_times.append(float(dw))
        if fl is not None and fl >= 0 and not unreliable:
            flight_times.append(float(fl))

    if len(dwell_times) < 3 or len(flight_times) < 2:
        return None

    return {
        'mean_dwell':  sum(dwell_times)  / len(dwell_times),
        'std_dwell':   _mad(dwell_times),
        'mean_flight': sum(flight_times) / len(flight_times),
        'std_flight':  _mad(flight_times),
    }


# ── Incarcare probe de enrollment din DB ───────────────────────────────────

def load_enrollment_samples(user_id, device_id, max_samples=20):
    """
    Incarca probele usable_for_training=1 din baza de date pentru user+device.
    Sorteaza: confidence='normal' inaintea 'low'.
    Returneaza lista de feature dicts.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    rows = execute_query("""
        SELECT final_sequence_json, confidence, recorded_at
        FROM   keystroke_samples
        WHERE  user_id = ?
          AND  device_id = ?
          AND  usable_for_training = 1
          AND  attempt_label IN ('enrollment_genuine', 'test_genuine')
        ORDER BY
          CASE WHEN confidence = 'normal' THEN 0 ELSE 1 END,
          recorded_at
        LIMIT ?
    """, [user_id, device_id, max_samples])

    features_list = []
    for row in rows:
        try:
            events = json.loads(row['final_sequence_json'])
            feats  = extract_features(events)
            if feats is not None:
                features_list.append(feats)
        except Exception:
            continue

    return features_list


# ── Antrenare profil biometric ─────────────────────────────────────────────

def train_manhattan_profile(feature_list):
    """
    Construieste profilul biometric din lista de feature vectors.
    Returneaza dict cu 'mean' si 'variation' (MAD) per caracteristica.
    """
    if not feature_list:
        return None

    feature_names = ['mean_dwell', 'std_dwell', 'mean_flight', 'std_flight']
    profile       = {}

    for fname in feature_names:
        values = [f[fname] for f in feature_list if fname in f]
        if not values:
            profile[fname] = {'mean': 0.0, 'variation': EPSILON}
            continue
        profile[fname] = {
            'mean':      sum(values) / len(values),
            'variation': _mad(values),
        }

    return profile


# ── Scoring Manhattan Scaled ───────────────────────────────────────────────

def score_manhattan_scaled(profile, features):
    """
    Calculeaza distanta Manhattan normalizata fata de profil.
    Formula: score = Σ |sample_i - mean_i| / variation_i
    Scor mic = tastare apropiata de profil (bun).
    Scor mare = tastare suspecta / anomalie.
    """
    if profile is None or features is None:
        return float('inf')

    total = 0.0
    for fname, stats in profile.items():
        sample_val = features.get(fname, stats['mean'])
        deviation  = abs(sample_val - stats['mean'])
        normalized = deviation / stats['variation']
        total     += normalized

    return total


# ── Calibrare prag LOO ─────────────────────────────────────────────────────

def calibrate_threshold(feature_list):
    """
    Leave-One-Out cross-validation pentru calibrarea pragului.
    Fiecare proba e testata fata de profilul construit din restul.
    Pragul = mean(scoruri_LOO) + 2 * mad(scoruri_LOO).
    """
    if len(feature_list) < 3:
        return float('inf')

    loo_scores = []

    for i in range(len(feature_list)):
        train = [f for j, f in enumerate(feature_list) if j != i]
        test  = feature_list[i]

        profile = train_manhattan_profile(train)
        if profile is None:
            continue

        score = score_manhattan_scaled(profile, test)
        if score != float('inf'):
            loo_scores.append(score)

    if not loo_scores:
        return float('inf')

    mean_loo = sum(loo_scores) / len(loo_scores)
    mad_loo  = _mad(loo_scores)

    return mean_loo + 2 * mad_loo


# ── Conversie scor brut → scor 0.0-1.0 ────────────────────────────────────

def _raw_to_keystroke_score(score_raw, threshold):
    """
    Converteste distanta Manhattan (0..inf) in scor de incredere (0.0..1.0).
    - score_raw <= threshold  → scor > 0.5 (match)
    - score_raw = threshold   → scor = 0.5
    - score_raw >> threshold  → scor → 0.0 (mismatch)
    """
    if score_raw is None or threshold is None or threshold <= 0:
        return 0.5

    if score_raw == float('inf'):
        return 0.0

    ratio = score_raw / threshold

    # Decadere exponentiala: 1.0 la ratio=0, 0.5 la ratio=1, ~0 la ratio>>1
    return math.exp(-0.693 * ratio)


# ── Comparare profil (apelata din app.py dupa enrollment) ──────────────────

def compare_profiles(user_id, device_id, ks_raw):
    """
    Returneaza dict cu keystroke_score (0.0-1.0) si metadate de scoring.
    Semnatura simplificata: nu mai primeste calea CSV.
    """
    # 1. Parse + curatare proba curenta
    try:
        if isinstance(ks_raw, str):
            data = json.loads(ks_raw)
        else:
            data = ks_raw

        events = data if isinstance(data, list) else data.get('events', [])

        candidate_buffer = []
        for event in events:
            key = event.get('key', '')
            if key in SKIP_KEYS:
                continue
            elif key == 'Backspace':
                if candidate_buffer:
                    candidate_buffer.pop()
            elif key not in AUXILIARY_KEYS:
                candidate_buffer.append(event)

        if len(candidate_buffer) < MIN_CHARS:
            return {'keystroke_score': 0.5, 'score_raw': None,
                    'threshold': None, 'n_enrollment': 0,
                    'features': None, 'profile': None, 'status': 'insufficient_chars'}
    except Exception:
        return {'keystroke_score': 0.5, 'score_raw': None,
                'threshold': None, 'n_enrollment': 0,
                'features': None, 'profile': None, 'status': 'parse_error'}

    # 2. Extragere features din proba curenta
    current_features = extract_features(candidate_buffer)
    if current_features is None:
        return {'keystroke_score': 0.5, 'score_raw': None,
                'threshold': None, 'n_enrollment': 0,
                'features': None, 'profile': None, 'status': 'insufficient_data'}

    # 3. Incarcare probe de enrollment din DB
    enrollment_features = load_enrollment_samples(user_id, device_id)

    if len(enrollment_features) < MIN_ENROLLMENT_SAMPLES:
        return {
            'keystroke_score': 0.5,
            'score_raw':       None,
            'threshold':       None,
            'n_enrollment':    len(enrollment_features),
            'features':        current_features,
            'profile':         None,
            'status':          'insufficient_data'
        }

    # 4. Antrenare profil
    profile = train_manhattan_profile(enrollment_features)
    if profile is None:
        return {'keystroke_score': 0.5, 'score_raw': None,
                'threshold': None, 'n_enrollment': len(enrollment_features),
                'features': current_features, 'profile': None, 'status': 'profile_error'}

    # 5. Calibrare prag LOO
    threshold = calibrate_threshold(enrollment_features)

    # 6. Scoring
    score_raw = score_manhattan_scaled(profile, current_features)

    # 7. Conversie in scor 0.0-1.0
    keystroke_score = _raw_to_keystroke_score(score_raw, threshold)

    print(f"[KEYSTROKE] raw={score_raw:.3f} threshold={threshold:.3f} "
          f"score={keystroke_score:.3f} (n_enrollment={len(enrollment_features)})")

    return {
        'keystroke_score': keystroke_score,
        'score_raw':       score_raw,
        'threshold':       threshold,
        'n_enrollment':    len(enrollment_features),
        'features':        current_features,
        'profile':         profile,
        'status':          'scored'
    }


def analyze(user_id, device_id, ks_raw):
    """
    Returneaza decizia locala a agentului keystroke.
    Apeleaza compare_profiles() intern si mapeaza scorul la o decizie.
    """
    result = compare_profiles(user_id, device_id, ks_raw)
    score  = result['keystroke_score']
    status = result['status']

    if status in ('insufficient_data', 'enrollment', 'parse_error',
                  'insufficient_chars', 'profile_error'):
        decision = 'insufficient_data'
    elif score >= 0.3:
        decision = 'accept'
    elif score >= 0.1:
        decision = 'uncertain'
    else:
        decision = 'reject'

    result['decision'] = decision
    return result


# ── Salvare proba (apelata din app.py) ─────────────────────────────────────

def save_keystroke_sample(user_id, device_id, login_id, ks_raw,
                          attempt_label='enrollment_genuine'):
    """
    Parseaza, curata si salveaza o proba in baza de date.
    Semnatura simplificata: nu mai primeste calea CSV.

    attempt_label:
      - 'enrollment_genuine' : primele ENROLLMENT_LOGINS loginuri ale proprietarului
      - 'test_genuine'       : loginuri ulterioare ale proprietarului
      - 'test_impostor'      : altcineva incearca loginul (pentru testare FAR)
    """
    try:
        if isinstance(ks_raw, str):
            data = json.loads(ks_raw)
        else:
            data = ks_raw

        if isinstance(data, list):
            events        = data
            has_backspace = any(e.get('key') == 'Backspace' for e in events)
        else:
            events        = data.get('events', [])
            has_backspace = data.get('hasBackspace', False) or any(
                e.get('key') == 'Backspace' for e in events
            )
    except Exception:
        return

    # Curatare secventa (elimina taste speciale, simuleaza backspace)
    candidate_buffer = []
    auxiliary_events = []

    for i, event in enumerate(events):
        key = event.get('key', '')
        if key in SKIP_KEYS:
            continue
        elif key == 'Backspace':
            if candidate_buffer:
                candidate_buffer.pop()
            auxiliary_events.append(event)
        elif key in ('Shift', 'CapsLock'):
            auxiliary_events.append(event)
        else:
            candidate_buffer.append((event, i))

    final_sequence_events = [e for (e, _) in candidate_buffer]
    original_indices      = [i for (_, i) in candidate_buffer]

    if len(final_sequence_events) < MIN_CHARS:
        return

    # Recalculare flight times (unele devin 'unreliable' daca a existat backspace intre ele)
    cleaned_events = []
    for pos, event in enumerate(final_sequence_events):
        cleaned = {
            'key':        event.get('key', ''),
            'position':   pos,
            'downTime':   event.get('downTime'),
            'upTime':     event.get('upTime'),
            'dwellTime':  event.get('dwellTime'),
            'unreliable': False
        }
        if pos == 0:
            cleaned['flightTime'] = None
        else:
            prev_event  = final_sequence_events[pos - 1]
            prev_orig_i = original_indices[pos - 1]
            curr_orig_i = original_indices[pos]
            if curr_orig_i == prev_orig_i + 1:
                cleaned['flightTime'] = event.get('flightTime')
                cleaned['unreliable'] = False
            else:
                prev_up   = prev_event.get('upTime')
                curr_down = event.get('downTime')
                cleaned['flightTime'] = (curr_down - prev_up
                                         if prev_up is not None and curr_down is not None
                                         else None)
                cleaned['unreliable'] = True
        cleaned_events.append(cleaned)

    confidence   = 'low' if has_backspace else 'normal'
    is_truncated = has_backspace

    usable_for_training = (
        1 if (attempt_label in ('enrollment_genuine', 'test_genuine')
              and confidence == 'normal')
        else 0
    )
    features_check        = extract_features(cleaned_events)
    usable_for_evaluation = 1 if features_check is not None else 0

    insert('keystroke_samples', {
        'sample_id':             str(uuid.uuid4()),
        'user_id':               user_id,
        'device_id':             device_id,
        'login_id':              login_id,
        'final_sequence_json':   json.dumps(cleaned_events),
        'auxiliary_json':        json.dumps(auxiliary_events),
        'has_backspace':         int(has_backspace),
        'confidence':            confidence,
        'is_truncated':          int(is_truncated),
        'attempt_label':         attempt_label,
        'usable_for_training':   usable_for_training,
        'usable_for_evaluation': usable_for_evaluation,
        'recorded_at':           datetime.utcnow().isoformat()
    })