import uuid
import base64
import numpy as np
from datetime import datetime
from deepface import DeepFace
from utils.database import insert, execute_query, update

# ── Constante ──────────────────────────────────────────────────────────────

MODEL_NAME       = 'Facenet'
THRESHOLD_ACCEPT = 0.30   # distanta cosinus sub care acceptam
THRESHOLD_REJECT = 0.55   # distanta cosinus peste care respingem


# ── Functii private ────────────────────────────────────────────────────────

def _decode_frame(frame_b64):
    """
    Converteste un cadru base64 in array numpy (BGR).
    Returneaza None daca decodificarea esueaza.
    """
    try:
        # elimina prefixul "data:image/jpeg;base64," daca exista
        if ',' in frame_b64:
            frame_b64 = frame_b64.split(',', 1)[1]

        img_bytes = base64.b64decode(frame_b64)
        img_array = np.frombuffer(img_bytes, dtype=np.uint8)

        import cv2
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
        return img
    except Exception:
        return None


def _get_embedding(frame_b64):
    """
    Extrage vectorul de embedding dintr-un cadru base64.
    Foloseste DeepFace cu modelul Facenet.
    Returneaza lista de floats sau None daca nu e detectata nicio fata.
    """
    img = _decode_frame(frame_b64)
    if img is None:
        return None

    try:
        result = DeepFace.represent(
            img_path      = img,
            model_name    = MODEL_NAME,
            enforce_detection = True
        )
        # result e o lista; luam primul (singurul) embedding detectat
        return result[0]['embedding']
    except Exception:
        return None


def _cosine_distance(vec_a, vec_b):
    """
    Calculeaza distanta cosinus intre doi vectori.
    Rezultat intre 0.0 (identici) si 1.0 (total diferiti).
    """
    a = np.array(vec_a)
    b = np.array(vec_b)

    dot     = np.dot(a, b)
    norm_a  = np.linalg.norm(a)
    norm_b  = np.linalg.norm(b)

    if norm_a == 0 or norm_b == 0:
        return 1.0

    similarity = dot / (norm_a * norm_b)
    distance   = 1.0 - similarity
    return float(distance)


# ── Functii publice ────────────────────────────────────────────────────────

def enroll(user_id, frames_base64):
    """
    Inroleaza un utilizator din 3 cadre base64.
    Calculeaza embedding-ul mediu si il salveaza in face_profiles.
    Seteaza face_enabled = 1 in users.

    Returneaza dict cu status si mesaj.
    """
    embeddings = []

    for frame in frames_base64:
        emb = _get_embedding(frame)
        if emb is not None:
            embeddings.append(emb)

    if len(embeddings) < 2:
        return {
            'status':  'error',
            'message': 'Prea putine fete detectate. Incearca din nou cu iluminare mai buna.'
        }

    # Calculam embedding-ul mediu din cadrele valide
    avg_embedding = np.mean(embeddings, axis=0).tolist()

    # Dezactivam profilul vechi daca exista
    existing = execute_query(
        "SELECT profile_id FROM face_profiles WHERE user_id = ? AND is_active = 1",
        [user_id]
    )
    for row in existing:
        update('face_profiles', {'is_active': 0}, {'profile_id': row['profile_id']})

    # Salvam profilul nou
    import json
    insert('face_profiles', {
        'profile_id':     str(uuid.uuid4()),
        'user_id':        user_id,
        'embedding_json': json.dumps(avg_embedding),
        'model_name':     MODEL_NAME,
        'created_at':     datetime.utcnow().isoformat(),
        'is_active':      1
    })

    # Marcam utilizatorul ca inrolat
    update('users', {'face_enabled': 1}, {'user_id': user_id})

    print(f"[FACE] Enrollment reusit pentru user_id={user_id} "
          f"({len(embeddings)} cadre valide din {len(frames_base64)})")

    return {
        'status':  'enrolled',
        'message': 'Profil facial salvat cu succes.'
    }


def analyze(user_id, frame_b64, login_id=None):
    """
    Verifica identitatea unui utilizator la login.
    Compara cadrul primit cu embedding-ul inrolat din face_profiles.

    Returneaza dict cu decizie si distanta, la fel ca agentii keystroke si IP.
    """
    import json

    # Verificam daca utilizatorul are profil facial activ
    rows = execute_query(
        "SELECT embedding_json FROM face_profiles WHERE user_id = ? AND is_active = 1 LIMIT 1",
        [user_id]
    )
    if not rows:
        return {
            'decision': 'opted_out',
            'distance': None,
            'status':   'no_profile'
        }

    stored_embedding = json.loads(rows[0]['embedding_json'])

    # Extragem embedding-ul din cadrul primit
    current_embedding = _get_embedding(frame_b64)
    if current_embedding is None:
        _log_attempt(user_id, login_id, distance=None, decision='uncertain')
        return {
            'decision': 'uncertain',
            'distance': None,
            'status':   'no_face_detected'
        }

    # Calculam distanta cosinus
    distance = _cosine_distance(stored_embedding, current_embedding)

    # Mapam distanta la decizie
    if distance <= THRESHOLD_ACCEPT:
        decision = 'accept'
    elif distance >= THRESHOLD_REJECT:
        decision = 'reject'
    else:
        decision = 'uncertain'

    print(f"[FACE] user_id={user_id} distance={distance:.4f} → {decision}")

    _log_attempt(user_id, login_id, distance, decision)

    return {
        'decision': decision,
        'distance': distance,
        'status':   'scored'
    }


def revoke_enrollment(user_id):
    """
    Dezactiveaza profilul facial al unui utilizator (soft delete).
    Apelat cand utilizatorul debifa opt-in din dashboard.
    Datele raman in baza de date pentru audit.
    """
    update('face_profiles', {'is_active': 0},  {'user_id': user_id})
    update('users',         {'face_enabled': 0}, {'user_id': user_id})

    print(f"[FACE] Enrollment revocat pentru user_id={user_id}")


# ── Logging intern ─────────────────────────────────────────────────────────

def _log_attempt(user_id, login_id, distance, decision):
    """Salveaza fiecare incercare de verificare faciala in face_attempts."""
    insert('face_attempts', {
        'attempt_id':   str(uuid.uuid4()),
        'user_id':      user_id,
        'login_id':     login_id or '',
        'distance':     distance,
        'decision':     decision,
        'attempted_at': datetime.utcnow().isoformat()
    })