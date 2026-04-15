import csv
import json
import uuid
from datetime import datetime

# Taste care nu produc caractere în parolă și trebuie ignorate complet
SKIP_KEYS = {'Control', 'Alt', 'Meta', 'Tab', 'Enter', 'ArrowLeft',
             'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End',
             'PageUp', 'PageDown', 'Escape', 'F1', 'F2', 'F3', 'F4',
             'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'}

# Taste auxiliare — comportament biometric secundar, nu poziții în parolă
AUXILIARY_KEYS = {'Shift', 'CapsLock', 'Backspace'}

# Numărul minim de caractere finale pentru ca proba să fie utilă biometric
MIN_CHARS = 4


def save_keystroke_sample(csv_path, user_id, device_id, login_id, ks_raw):
    """
    Parsează, curăță și salvează o probă de keystroke dynamics.
    Salvează NUMAI secvența finală curățată — niciodată date brute.
    """

    # 1. PARSE
    try:
        if isinstance(ks_raw, str):
            data = json.loads(ks_raw)
        else:
            data = ks_raw

        # suportă atât formatul {"events": [...], "hasBackspace": bool}
        # cât și formatul vechi [...] (listă simplă)
        if isinstance(data, list):
            events = data
            has_backspace = any(e.get('key') == 'Backspace' for e in events)
        else:
            events = data.get('events', [])
            has_backspace = data.get('hasBackspace', False) or any(
                e.get('key') == 'Backspace' for e in events
            )

    except Exception:
        return  # date invalide, nu salvăm nimic

    # 2. SEPARARE CANALE: simulăm buffer-ul de tastare
    # candidate_events: evenimente candidate pentru secvența finală
    # auxiliary_events: Shift, Backspace, CapsLock
    candidate_buffer = []   # perechi (event, index_original)
    auxiliary_events = []

    for i, event in enumerate(events):
        key = event.get('key', '')

        if key in SKIP_KEYS:
            continue  # ignorăm complet

        elif key == 'Backspace':
            if candidate_buffer:
                candidate_buffer.pop()  # simulăm ștergerea
            auxiliary_events.append(event)

        elif key in ('Shift', 'CapsLock'):
            auxiliary_events.append(event)

        else:
            # caracter normal care rămâne în parolă
            candidate_buffer.append((event, i))

    final_sequence_events = [e for (e, _) in candidate_buffer]
    original_indices      = [i for (_, i) in candidate_buffer]

    # 3. VALIDARE MINIMĂ — probe prea scurte sunt zgomot, nu semnal
    if len(final_sequence_events) < MIN_CHARS:
        return

    # 4. RECALCULARE FLIGHT TIME + MARCARE NEFIABILĂ
    # Dacă două caractere consecutive în secvența finală NU erau adiacente
    # în secvența originală (un Backspace sau alt eveniment a fost între ele),
    # flight time-ul lor nu este de încredere — îl recalculăm din timestamps
    # brute dar îl marcăm ca unreliable.
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

            # adiacente în original → flight time original e de încredere
            if curr_orig_i == prev_orig_i + 1:
                cleaned['flightTime']  = event.get('flightTime')
                cleaned['unreliable']  = False
            else:
                # nu erau adiacente → recalculăm din timestamps brute
                # dar marcăm ca nefiabil (între ele au fost corecții)
                prev_up   = prev_event.get('upTime')
                curr_down = event.get('downTime')
                if prev_up is not None and curr_down is not None:
                    cleaned['flightTime'] = curr_down - prev_up
                else:
                    cleaned['flightTime'] = None
                cleaned['unreliable'] = True

        cleaned_events.append(cleaned)

    # 5. FLAGS PENTRU PROBĂ
    # is_truncated: proba are backspace-uri — secvența poate fi incompletă
    # confidence: semnal pentru viitorul model ML să cântărească proba
    is_truncated = has_backspace
    confidence   = 'low' if has_backspace else 'normal'

    # 6. SALVARE
    row = {
        'sample_id':            str(uuid.uuid4()),
        'user_id':              user_id,
        'device_id':            device_id,
        'login_id':             login_id,
        'final_sequence_json':  json.dumps(cleaned_events),
        'auxiliary_json':       json.dumps(auxiliary_events),
        'has_backspace':        has_backspace,
        'confidence':           confidence,
        'is_truncated':         is_truncated,
        'recorded_at':          datetime.utcnow().isoformat()
    }

    fieldnames = list(row.keys())
    try:
        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            # scriem header doar dacă fișierul e gol
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        pass


def compare_profiles(csv_path, user_id, ks_raw):
    return True  # stub — Week 3