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

def _score_to_float(decision_value):
    """
    Convertește distanța de la frontiera One-Class SVM la un scor 0.0–1.0.
 
    """
    # Sigmoid: 1 / (1 + e^(-x))
    # Scalăm cu 0.5 pentru a face curba mai lină
    score = 1.0 / (1.0 + np.exp(-decision_value * 0.5))
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
    Antrenează un model One-Class SVM pe probele de enrollment ale unui user+device.
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
 
    # 5. Normalizare cu StandardScaler (z-score)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    # 6. Antrenare One-Class SVM
    # nu=0.1 înseamnă: acceptăm că maxim 10% din datele de training
    # pot fi tratate ca outlieri (robustness la probe zgomotoase)
    # kernel='rbf' permite frontiere non-liniare — mai potrivit pentru
    # date biometrice care nu sunt liniar separabile
    model = OneClassSVM(nu=0.1, kernel='rbf', gamma='scale')
    model.fit(X_scaled)
 
    # 7. Save modelul + scalerul împreună
    # Save și metadata pentru debugging și thesis
    bundle = {
        'model':      model,
        'scaler':     scaler,
        'trained_at': datetime.utcnow().isoformat(),
        'n_samples':  len(feature_vectors),
        'user_id':    user_id,
        'device_id':  device_id,
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
        model  = bundle['model']
        scaler = bundle['scaler']
    except Exception:
        return 1.0  # model corupt sau incompatibil, nu penalizeaza
 
    # 6. Normalizare cu ACELAȘI scaler de la antrenare
    vec_scaled = scaler.transform(vec.reshape(1, -1))
 
    # 7. Calculare distanța față de frontieră
    # decision_function > 0 → înăuntrul frontierei (legitim)
    # decision_function < 0 → în afara frontierei (suspect)
    decision_value = model.decision_function(vec_scaled)[0]
 
    # 8. Convertim distanța la scor 0.0–1.0 prin sigmoid
    score = _score_to_float(decision_value)
 
    return score