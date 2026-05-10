import csv
import json
import math
import uuid
from datetime import datetime

# ---------------------------------------------------------------------------
# CONSTANTE
# ---------------------------------------------------------------------------

SKIP_KEYS = {'Control', 'Alt', 'Meta', 'Tab', 'Enter', 'ArrowLeft',
             'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End',
             'PageUp', 'PageDown', 'Escape', 'F1', 'F2', 'F3', 'F4',
             'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'}

AUXILIARY_KEYS = {'Shift', 'CapsLock', 'Backspace'}
MIN_CHARS = 4
MIN_ENROLLMENT_SAMPLES = 3
EPSILON = 1e-6


# ---------------------------------------------------------------------------
# UTILITĂȚI STATISTICE
# ---------------------------------------------------------------------------

def _std(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)

def _median(values):
    if not values:
        return 0.0
    sorted_v = sorted(values)
    mid = len(sorted_v) // 2
    if len(sorted_v) % 2 == 0:
        return (sorted_v[mid - 1] + sorted_v[mid]) / 2
    return sorted_v[mid]

def _mad(values):
    if len(values) < 2:
        return EPSILON
    med = _median(values)
    deviations = [abs(v - med) for v in values]
    result = _median(deviations)
    return max(result, EPSILON)


# ---------------------------------------------------------------------------
# EXTRAGERE FEATURES
# ---------------------------------------------------------------------------

def extract_features_from_events(cleaned_events):
    """
    Extrage vectorul de 4 caracteristici din secvența curățată de events.
    Ignoră flight times 'unreliable' (marcat când a existat backspace între taste).
    Returnează None dacă datele sunt insuficiente.
    """
    dwell_times = []
    flight_times = []

    for e in cleaned_events:
        dw = e.get('dwellTime')
        fl = e.get('flightTime')
        unreliable = e.get('unreliable', False)

        if dw is not None and dw > 0:
            dwell_times.append(float(dw))
        if fl is not None and fl >= 0 and not unreliable:
            flight_times.append(float(fl))

    if len(dwell_times) < 3 or len(flight_times) < 2:
        return None

    return {
        'mean_dwell':  sum(dwell_times) / len(dwell_times),
        'std_dwell':   _std(dwell_times),
        'mean_flight': sum(flight_times) / len(flight_times),
        'std_flight':  _std(flight_times),
    }


# ---------------------------------------------------------------------------
# ÎNCĂRCARE DATE DIN CSV
# ---------------------------------------------------------------------------

def load_enrollment_samples(csv_path, user_id, device_id, max_samples=20):
    """
    Încarcă probele din CSV pentru user+device.
    Sortează: confidence='normal' înaintea 'low'.
    Returnează lista de feature dicts.
    """
    features_list = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = [r for r in reader
                    if r.get('user_id') == user_id
                    and r.get('device_id') == device_id]
    except Exception:
        return []

    rows.sort(key=lambda r: (
        0 if r.get('confidence', 'normal') == 'normal' else 1,
        r.get('recorded_at') or ''
    ))

    for row in rows[:max_samples]:
        try:
            events = json.loads(row['final_sequence_json'])
            feats = extract_features_from_events(events)
            if feats is not None:
                features_list.append(feats)
        except Exception:
            continue

    return features_list


# ---------------------------------------------------------------------------
# ANTRENARE PROFIL
# ---------------------------------------------------------------------------

def train_manhattan_profile(feature_list):
    """
    Construiește profilul biometric din lista de feature vectors.
    Returnează dict cu 'mean' și 'variation' (MAD) per caracteristică.
    """
    if not feature_list:
        return None

    feature_names = ['mean_dwell', 'std_dwell', 'mean_flight', 'std_flight']
    profile = {}

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


# ---------------------------------------------------------------------------
# SCORING MANHATTAN SCALED
# ---------------------------------------------------------------------------

def score_manhattan_scaled(profile, features):
    """
    Calculează distanța Manhattan normalizată față de profil.

    Formula: score = Σ |sample_i - mean_i| / variation_i

    Scor mic = tastare apropiată de profil.
    Scor mare = tastare suspectă / anomalie.
    """
    if profile is None or features is None: #daca nu exista profil /features => distanta infinita
        return float('inf')

    total = 0.0 #porneste scor de la 0
    for fname, stats in profile.items():  #parcurge fiecare feature din profil
        sample_val = features.get(fname, stats['mean'])
        #Ia valoarea acelui feature din proba curentă. Dacă lipsește, folosește media din profil ca fallback.
        deviation = abs(sample_val - stats['mean'])
        total += deviation / (stats['variation'] + EPSILON)     #sclaeaza diferenta prin variatia naturala a userului
    return total


# ---------------------------------------------------------------------------
# CALIBRARE PRAG
# ---------------------------------------------------------------------------

def calibrate_threshold(feature_list):
    """
    Calculează pragul de decizie prin leave-one-out pe probele de enrollment.

    treshold = mean(scoruri_loo) + 2 * std(scoruri_loo)

    La 2 deviatii standard, ~95% din tastările legitime sunt acceptate (FRR ≤ 5%).
    Returnează 4.0 ca fallback permisiv dacă datele sunt insuficiente.
    """
    if len(feature_list) < MIN_ENROLLMENT_SAMPLES:  #fallback daca nu-s suficiente probe
        return 4.0

    loo_scores = []  #aici se strang scorurile obtinut eprin leave one out
    for i, held_out in enumerate(feature_list):  # codul ia fiecare proba buna si o scoate temporara din training, si o pune in held_out
        rest = [f for j, f in enumerate(feature_list) if j != i] #lista de probe ramase
        if len(rest) < 2:
            continue
        profile = train_manhattan_profile(rest) #profilul manhattan construit din probele ramase
        if profile is None:
            continue
        score = score_manhattan_scaled(profile, held_out)  #cacluc: cat de departe e proba scoasa fata de profilul contruit fara ea
        if not math.isinf(score):
            loo_scores.append(score)   # scorul este salvat in aceasta lista

    if len(loo_scores) < 2:
        return 4.0

    mean_loo = sum(loo_scores) / len(loo_scores)  #media scorurilor legitime
    std_loo = _std(loo_scores)  # deviatia standard a scorurilor legitime
    threshold = mean_loo + 2 * std_loo 

    return max(0.5, min(threshold, 20.0))  # limitele pragului; daca e foarte micc codul il ridica la 0.5
                                            # prea mare => il duce la 20;  apoi e folosit in compare_profiles in treshold = calibrate...


# ---------------------------------------------------------------------------
# CONVERSIE SCOR BRUT → SCOR ORCHESTRATOR
# ---------------------------------------------------------------------------

def _raw_to_keystroke_score(score_raw, threshold):
    """
    Convertește scorul Manhattan brut în scor pentru orchestrator. 

    Formula: keystroke_score = exp(-score_raw / threshold)

    Mapare față de pragurile orchestratorului (0.3 și 0.1):
      score_raw = 0           → 1.00  (match perfect)
      score_raw = threshold   → 0.37  → ALLOW
      score_raw = 2*threshold → 0.14  → 2FA
      score_raw = 3*threshold → 0.05  → RE-ENROLLMENT
    Valorile au fost selectate empiric. Nu sunt rezultatul unor experiente.
    """
    if math.isinf(score_raw) or score_raw < 0: #nu ar trebui sa existe valori negative la manhattan, dar asta e  un check de siguranta.
        return 0.0                             # adica: distanță invalidă → scor biometric minim → comportament suspect
    return math.exp(-score_raw / (threshold + EPSILON))



def compare_profiles(csv_path, user_id, device_id, ks_raw):
    """
    Returnează float 0.0-1.0 compatibil cu orchestratorul.
    Returnează 0.5 (neutru) dacă nu există suficiente date pentru scoring.

    ATENȚIE: semnătură modificată față de stub — primește și device_id.
    """
    # 1. Parse + curățare rapidă a probei curente
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
            return 0.5
    except Exception:
        return 0.5

    # 2. Extragere features din proba curentă
    current_features = extract_features_from_events(candidate_buffer)
    if current_features is None:
        return 0.5

    # 3. Încărcare probe de enrollment
    enrollment_features = load_enrollment_samples(csv_path, user_id, device_id)
    if len(enrollment_features) < MIN_ENROLLMENT_SAMPLES:
        return {
            'keystroke_score': 0.5,
            'score_raw': None,
            'threshold': None,
            'n_enrollment': len(enrollment_features),
            'features': current_features,
            'profile': None,
            'status': 'insufficient_data'
        }

    # 4. Antrenare profil
    profile = train_manhattan_profile(enrollment_features)
    if profile is None:
        return 0.5

    # 5. Calibrare prag
    threshold = calibrate_threshold(enrollment_features)

    # 6. Scoring
    score_raw = score_manhattan_scaled(profile, current_features)

    # 7. Conversie
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


# ---------------------------------------------------------------------------
# SALVARE PROBE (cu câmpuri noi pentru etichete)
# ---------------------------------------------------------------------------

def save_keystroke_sample(csv_path, user_id, device_id, login_id, ks_raw,
                          attempt_label='enrollment_genuine'):
    """
    Parsează, curăță și salvează o probă de keystroke dynamics.

    attempt_label poate fi:
      - 'enrollment_genuine' : primele 20 loginuri ale proprietarului
      - 'test_genuine'       : loginuri ulterioare ale proprietarului
      - 'test_impostor'      : altcineva încearcă loginul (pentru testare FAR)
    """
    try:
        if isinstance(ks_raw, str):
            data = json.loads(ks_raw)
        else:
            data = ks_raw

        if isinstance(data, list):
            events = data
            has_backspace = any(e.get('key') == 'Backspace' for e in events)
        else:
            events = data.get('events', [])
            has_backspace = data.get('hasBackspace', False) or any(
                e.get('key') == 'Backspace' for e in events
            )
    except Exception:
        return

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
                cleaned['flightTime']  = event.get('flightTime')
                cleaned['unreliable']  = False
            else:
                prev_up   = prev_event.get('upTime')
                curr_down = event.get('downTime')
                cleaned['flightTime']  = (curr_down - prev_up
                                          if prev_up is not None and curr_down is not None
                                          else None)
                cleaned['unreliable']  = True
        cleaned_events.append(cleaned)

    confidence = 'low' if has_backspace else 'normal'
    is_truncated = has_backspace

    usable_for_training = (
        1 if (attempt_label in ('enrollment_genuine', 'test_genuine')
              and confidence == 'normal')
        else 0
    )
    features_check = extract_features_from_events(cleaned_events)
    usable_for_evaluation = 1 if features_check is not None else 0

    row = {
        'sample_id':             str(uuid.uuid4()),
        'user_id':               user_id,
        'device_id':             device_id,
        'login_id':              login_id,
        'final_sequence_json':   json.dumps(cleaned_events),
        'auxiliary_json':        json.dumps(auxiliary_events),
        'has_backspace':         has_backspace,
        'confidence':            confidence,
        'is_truncated':          is_truncated,
        'attempt_label':         attempt_label,
        'usable_for_training':   usable_for_training,
        'usable_for_evaluation': usable_for_evaluation,
        'recorded_at':           datetime.utcnow().isoformat()
    }

    import os
    fieldnames = list(row.keys())
    file_exists = os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0
    try:
        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        pass