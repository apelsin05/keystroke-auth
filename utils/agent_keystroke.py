import json
import csv
import uuid
import os
import numpy as np
import joblib
import pandas as pd
from datetime import datetime
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# CONSTANTE

# Taste care nu produc caractere în parolă și trebuie ignorate complet
SKIP_KEYS = {'Control', 'Alt', 'Meta', 'Tab', 'Enter', 'ArrowLeft',
             'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End',
             'PageUp', 'PageDown', 'Escape', 'F1', 'F2', 'F3', 'F4',
             'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'}

# Taste auxiliare — comportament biometric secundar
AUXILIARY_KEYS = {'Shift', 'CapsLock', 'Backspace'}

# Numărul minim de caractere finale pentru ca proba să fie utilă biometric
MIN_CHARS = 4

# Numărul minim de probe necesare pentru antrenarea modelului
MIN_SAMPLES_FOR_TRAINING = 5

# Directorul unde salvez modelele .pkl
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'models')


# PRIVATE HELPER FUNCTIONS

def _parse_and_clean(ks_raw):
    """
    Parsează JSON-ul brut de la browser și returnează secvența curățată.
    Returnează lista de evenimente finale SAU None dacă datele sunt invalide.
 
    Această funcție este folosită atât la salvare și la scoring 
    """
    try:
        if isinstance(ks_raw, str):
            data = json.loads(ks_raw)
        else:
            data = ks_raw
 
        # suporta formatul nou {"events": [...], "hasBackspace": bool} si form vechi [...] (listă simpla)
        if isinstance(data, list):
            events = data
            has_backspace = any(e.get('key') == 'Backspace' for e in events)
        else:
            events = data.get('events', [])
            has_backspace = data.get('hasBackspace', False) or any(
                e.get('key') == 'Backspace' for e in events
            )
 
    except Exception:
        return None, False
 
    # Simulare buffer de tastare: Backspace elimina ultimul caracter
    candidate_buffer = []   # perechi (event, index_original)
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
        return None, has_backspace
 
    # Recalculăm flight times și marcăm perechile nefiabile
    cleaned_events = []
    for pos, event in enumerate(final_sequence_events):
        cleaned = {
            'key':        event.get('key', ''),
            'position':   pos,
            'downTime':   event.get('downTime'),
            'upTime':     event.get('upTime'),
            'dwellTime':  event.get('dwellTime'),
            'unreliable': False,
            'flightTime': None,
        }
 
        if pos > 0:
            prev_event  = final_sequence_events[pos - 1]
            prev_orig_i = original_indices[pos - 1]
            curr_orig_i = original_indices[pos]
 
            if curr_orig_i == prev_orig_i + 1:
                cleaned['flightTime'] = event.get('flightTime')
                cleaned['unreliable'] = False
            else:
                prev_up   = prev_event.get('upTime')
                curr_down = event.get('downTime')
                if prev_up is not None and curr_down is not None:
                    cleaned['flightTime'] = curr_down - prev_up
                cleaned['unreliable'] = True
 
        cleaned_events.append(cleaned)
 
    return cleaned_events, has_backspace
 
def _extract_feature_vector(cleaned_events):
    """
    Din secvența de evenimente curățată, extrage vectorul de 4 caracteristici:
    [mean_dwell, std_dwell, mean_flight, std_flight]
 
    Returnează un numpy array de shape (4,) SAU None dacă nu există suficiente date.
    """
    dwells  = [e['dwellTime']  for e in cleaned_events
               if e.get('dwellTime')  is not None]
    flights = [e['flightTime'] for e in cleaned_events
               if e.get('flightTime') is not None and not e.get('unreliable', False)]
 
    # Avem nevoie de cel puțin 2 valori pentru std (altfel std=0 și normalizarea eșuează)
    if len(dwells) < 2 or len(flights) < 1:
        return None
 
    return np.array([
        np.mean(dwells),
        np.std(dwells),
        np.mean(flights),
        np.std(flights) if len(flights) >= 2 else 0.0
    ])
 
def _model_path(user_id, device_id):
    """Returnează calea completă pentru fișierul .pkl al unui user+device."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    return os.path.join(MODELS_DIR, f'model_{user_id}_{device_id}.pkl')

def _calibrated_sigmoid(raw_score, train_mean, train_std):
    """
    Convert a raw model score to 0.0-1.0 using a calibrated sigmoid.
    Calibration: z-score against training distribution, then sigmoid with scale=1.5.
    A score near the training mean maps to ~0.5; outliers map toward 0.0.
    """
    z = (raw_score - train_mean) / max(train_std, 0.001)
    score = 1.0 / (1.0 + np.exp(-z * 1.5))
    return float(np.clip(score, 0.0, 1.0))


# FUNCTII PUBLICE


def save_keystroke_sample(csv_path, user_id, device_id, login_id, ks_raw):
    """
    Parsează, curăță și salvează o probă de keystroke dynamics.
    Salvează NUMAI secvența finală curățată 
    """

    cleaned_events, has_backspace = _parse_and_clean(ks_raw)
 
    if cleaned_events is None:
        return  # probă invalidă sau prea scurtă
 
    is_truncated = has_backspace
    confidence   = 'low' if has_backspace else 'normal'
 
    row = {
        'sample_id':            str(uuid.uuid4()),
        'user_id':              user_id,
        'device_id':            device_id,
        'login_id':             login_id,
        'final_sequence_json':  json.dumps(cleaned_events),
        'auxiliary_json':       json.dumps([]),  # simplificat față de original
        'has_backspace':        has_backspace,
        'confidence':           confidence,
        'is_truncated':         is_truncated,
        'recorded_at':          datetime.utcnow().isoformat()
    }
 
    fieldnames = list(row.keys())
    try:
        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        pass

def train_model(csv_path, user_id, device_id):
    """
    Antreneaza un model One-Class SVM pe probele de enrollment ale unui user+device.
    Salvează modelul și scalerul împreună într-un singur fișier .pkl.
 
    Returns:
        True  — model antrenat și salvat cu succes
        False — nu există suficiente probe curate pentru antrenare
    """
    
    try:
        df = pd.read_csv(csv_path)
    except Exception:
        return False
 
    df_filtered = df[
        (df['user_id']   == user_id) &
        (df['device_id'] == device_id) &
        (df['login_id']  != 'registration') &   # exclude proba de la înregistrare
        (df['confidence'] == 'normal')           # exclude probele cu backspace
    ]
 
    # 2. Extrage vectorii de caracteristici din fiecare proba valida
    feature_vectors = []
    for _, row in df_filtered.iterrows():
        try:
            cleaned_events = json.loads(row['final_sequence_json'])
            vec = _extract_feature_vector(cleaned_events)
            if vec is not None:
                feature_vectors.append(vec)
        except Exception:
            continue
 
    # 3. Verifica daca exista suficiente probe
    if len(feature_vectors) < MIN_SAMPLES_FOR_TRAINING:
        return False
 
    # 4. Construieste matricea de antrenare: shape (n_samples, 4)
    X = np.array(feature_vectors)
 
    # --- Isolation Forest ---
    scaler_if = StandardScaler()
    X_scaled_if = scaler_if.fit_transform(X)

    model_if = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model_if.fit(X_scaled_if)

    # Calibrate: score all training samples, record distribution
    train_scores_if = model_if.score_samples(X_scaled_if)
    train_mean_if   = float(np.mean(train_scores_if))
    train_std_if    = float(np.std(train_scores_if))

    # --- One-Class SVM ---
    scaler_svm = StandardScaler()
    X_scaled_svm = scaler_svm.fit_transform(X)

    model_svm = OneClassSVM(nu=0.1, kernel='rbf', gamma='scale')
    model_svm.fit(X_scaled_svm)

    # Calibrate: use decision_function on training data
    train_scores_svm = model_svm.decision_function(X_scaled_svm)
    train_mean_svm   = float(np.mean(train_scores_svm))
    train_std_svm    = float(np.std(train_scores_svm))

    bundle = {
        # Isolation Forest
        'model_if':       model_if,
        'scaler_if':      scaler_if,
        'train_mean_if':  train_mean_if,
        'train_std_if':   train_std_if,
        # One-Class SVM
        'model_svm':      model_svm,
        'scaler_svm':     scaler_svm,
        'train_mean_svm': train_mean_svm,
        'train_std_svm':  train_std_svm,
        # Metadata
        'trained_at':     datetime.utcnow().isoformat(),
        'n_samples':      len(feature_vectors),
        'user_id':        user_id,
        'device_id':      device_id,
    }

    path = _model_path(user_id, device_id)
    try:
        joblib.dump(bundle, path)
        return True
    except Exception:
        return False

def compare_profiles(csv_path, user_id, device_id, ks_raw):
    """
    Compară proba curentă de tastare cu profilul învățat pentru acest user+device.
 
    Returns:
        float 0.0–1.0
        - 1.0 = match perfect (sau nu avem model încă DECI FARA PENALIZARE)
        - 0.0 = mismatch total (impostor foarte probabil)
        - valori intermediare = grad de incertitudine
    """
    
    cleaned_events, _ = _parse_and_clean(ks_raw)
 
    
    if cleaned_events is None:
        return 1.0
 
    
    vec = _extract_feature_vector(cleaned_events)
 
    if vec is None:
        return 1.0  
   
    path = _model_path(user_id, device_id)
 
    if not os.path.exists(path):
        # Nu există model — fie enrollment incomplet, fie prima rulare
        # Nu penalizăm utilizatorul pentru o stare normală a sistemului
        return 1.0
 
   
    try:
        bundle = joblib.load(path)
    except Exception:
        return 1.0  # corrupt or incompatible bundle

    # --- Score with Isolation Forest ---
    vec_if     = bundle['scaler_if'].transform(vec.reshape(1, -1))
    raw_if     = bundle['model_if'].score_samples(vec_if)[0]
    score_if   = _calibrated_sigmoid(raw_if, bundle['train_mean_if'], bundle['train_std_if'])

    # --- Score with One-Class SVM ---
    vec_svm    = bundle['scaler_svm'].transform(vec.reshape(1, -1))
    raw_svm    = bundle['model_svm'].decision_function(vec_svm)[0]
    score_svm  = _calibrated_sigmoid(raw_svm, bundle['train_mean_svm'], bundle['train_std_svm'])

    # Average the two calibrated scores
    final_score = (score_if + score_svm) / 2.0

    return float(np.clip(final_score, 0.0, 1.0))