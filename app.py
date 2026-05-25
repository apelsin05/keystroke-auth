import os
import json
import uuid
import random
import string
from datetime import datetime, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix

from utils.agent_face import enroll as face_enroll, analyze as face_analyze, revoke_enrollment

import bcrypt
from flask import (
    Flask, jsonify, render_template, request, redirect,
    url_for, session, flash, make_response
)
from flask_session import Session

from utils.database import init_db, insert, fetchone, fetchall, update, delete_where, execute_query
from utils.password_validator import validate_password
from utils.email_sender import (
    send_2fa_email, send_unlawful_login_email,
    send_security_alert_email, send_confirm_identity_email
)
from utils.device_fingerprint import (
    get_device_info, generate_fingerprint_hash, generate_device_token,
    find_device, repair_device_connection, create_device,
    increment_device_login_count
)
from utils.agent_keystroke import compare_profiles, save_keystroke_sample, analyze as ks_analyze
from utils.agent_ip import get_ip_info, score_ip, record_ip, analyze as ip_analyze
from utils.orchestrator import decide
from utils.agent_face import enroll as face_enroll, analyze as face_analyze

# ── App setup ──────────────────────────────────────────────────────────────

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

app.config['SESSION_TYPE']             = 'filesystem'
app.config['SESSION_FILE_DIR']         = os.path.join(os.path.dirname(__file__), 'data', 'sessions')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
Session(app)

# Initializeaza baza de date la pornire
init_db()

# ── Constante ──────────────────────────────────────────────────────────────

ENROLLMENT_LOGINS = 12

# ── Helpers autentificare ──────────────────────────────────────────────────

def generate_2fa_code():
    return ''.join(random.choices(string.digits, k=6))


def find_user_by_email(email):
    row = fetchone('users', {'email': email})
    return dict(row) if row else None


def find_user_by_identifier(identifier):
    rows = execute_query(
        "SELECT * FROM users WHERE email=? OR username=? LIMIT 1",
        [identifier, identifier]
    )
    return dict(rows[0]) if rows else None


def find_user_by_id(user_id):
    row = fetchone('users', {'user_id': user_id})
    return dict(row) if row else None


def mask_2fa_code(code):
    if code is None:
        return ''
    code = str(code)
    if not code:
        return ''
    if len(code) == 1:
        return '*'
    return code[0] + ('*' * (len(code) - 1))


def append_auth_audit(stage, user_id='', email='', session_id='', device_id='',
                      ip_address='', entered_code='', stored_code='', codes_match='',
                      expires_at='', is_expired='', twofa_attempts='', reason='',
                      device_info=''):
    insert('auth_audit', {
        'audit_id':            str(uuid.uuid4()),
        'timestamp':           datetime.utcnow().isoformat(),
        'stage':               stage,
        'user_id':             user_id or '',
        'email':               email or '',
        'session_id':          session_id or '',
        'device_id':           device_id or '',
        'ip_address':          ip_address or '',
        'entered_code_masked': mask_2fa_code(entered_code),
        'stored_code_masked':  mask_2fa_code(stored_code),
        'entered_length':      len(str(entered_code)) if entered_code is not None else 0,
        'stored_length':       len(str(stored_code))  if stored_code  is not None else 0,
        'codes_match':         1 if codes_match is True else (0 if codes_match is False else None),
        'expires_at':          expires_at or '',
        'is_expired':          1 if is_expired is True else (0 if is_expired is False else None),
        'twofa_attempts':      twofa_attempts if twofa_attempts != '' else 0,
        'reason':              reason or '',
        'device_info':         device_info or '',
    })


def log_ml_event(user_id, device_id, login_id, ks_result,
                 ip_score, final_score, decision, login_status, sample_added=False):
    feat = ks_result.get('features') or {}
    prof = ks_result.get('profile') or {}

    def prof_mean(k):
        v = prof.get(k)
        return round(v['mean'], 2) if v else None

    insert('ml_log', {
        'log_id':           str(uuid.uuid4()),
        'timestamp':        datetime.utcnow().isoformat(),
        'event_type':       ks_result.get('status', 'scored'),
        'user_id':          user_id,
        'device_id':        device_id,
        'login_id':         login_id,
        'n_samples':        ks_result.get('n_enrollment'),
        'mean_dwell_ms':    round(feat.get('mean_dwell',  0), 2),
        'std_dwell_ms':     round(feat.get('std_dwell',   0), 2),
        'mean_flight_ms':   round(feat.get('mean_flight', 0), 2),
        'std_flight_ms':    round(feat.get('std_flight',  0), 2),
        'score_raw':        round(ks_result['score_raw'],  3) if ks_result.get('score_raw')  is not None else None,
        'threshold':        round(ks_result['threshold'],  3) if ks_result.get('threshold')  is not None else None,
        'keystroke_score':  round(ks_result['keystroke_score'], 3),
        'ip_score':         round(ip_score,    3),
        'final_score':      round(final_score, 3),
        'decision':         decision,
        'login_status':     login_status,
        'sample_added':     int(sample_added),
        'confirmed':        None,
        'train_mean_dwell': prof_mean('mean_dwell'),
        'train_std_dwell':  prof_mean('std_dwell'),
        'train_mean_flight':prof_mean('mean_flight'),
        'train_std_flight': prof_mean('std_flight'),
        'notes':            'manhattan_scaled'
    })


def format_device_info(device_info_str):
    try:
        import ast
        info = ast.literal_eval(device_info_str)
    except Exception:
        return device_info_str

    ua = info.get('userAgent', '')
    if 'Windows NT 10' in ua:   os_name = 'Windows 10/11'
    elif 'Windows NT 6' in ua:  os_name = 'Windows 7/8'
    elif 'Mac OS X' in ua:      os_name = 'macOS'
    elif 'Android' in ua:       os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua: os_name = 'iOS'
    elif 'Linux' in ua:         os_name = 'Linux'
    else:                       os_name = 'Necunoscut'

    if 'Edg/' in ua:            browser = 'Microsoft Edge'
    elif 'Chrome/' in ua:       browser = 'Google Chrome'
    elif 'Firefox/' in ua:      browser = 'Mozilla Firefox'
    elif 'Safari/' in ua and 'Chrome' not in ua: browser = 'Safari'
    else:                       browser = 'Necunoscut'

    width    = info.get('screenWidth',  '?')
    height   = info.get('screenHeight', '?')
    timezone = info.get('timezone', 'Necunoscuta')

    return (f"Sistem de operare: {os_name}<br>"
            f"Browser: {browser}<br>"
            f"Rezolutie ecran: {width}×{height}<br>"
            f"Fus orar: {timezone}")


def format_device_info_text(device_info_str):
    try:
        import ast
        info = ast.literal_eval(device_info_str)
    except Exception:
        return "Necunoscut"

    ua = info.get('userAgent', '')
    if 'Windows NT 10' in ua or 'Windows NT 11' in ua: os_name = 'Windows 10/11'
    elif 'Windows NT 6' in ua: os_name = 'Windows 7/8'
    elif 'Mac OS X' in ua:     os_name = 'macOS'
    elif 'Android' in ua:      os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua: os_name = 'iOS'
    elif 'Linux' in ua:        os_name = 'Linux'
    else:                      os_name = 'Necunoscut'

    if 'Edg/' in ua:           browser = 'Edge'
    elif 'Chrome/' in ua:      browser = 'Chrome'
    elif 'Firefox/' in ua:     browser = 'Firefox'
    elif 'Safari/' in ua and 'Chrome' not in ua: browser = 'Safari'
    else:                      browser = 'Browser necunoscut'

    return f"{browser} · {os_name}"


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route('/register/step1', methods=['GET', 'POST'])
def register_step1():
    if request.method == 'GET':
        return render_template('register.html')

    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm-password', '')
    ks_raw   = request.form.get('keystrokes_data', '[]')

    errors = validate_password(password)
    if errors:
        flash('Parola nu respecta toate conditiile.', 'error')
        return render_template('register.html')

    if password != confirm:
        flash('Parolele nu se potrivesc.', 'error')
        return render_template('register.html')

    if find_user_by_email(email):
        flash('Exista deja un cont cu acest email.', 'error')
        return render_template('register.html')

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    session['reg_email']         = email
    session['reg_password_hash'] = password_hash
    session['reg_keystrokes']    = ks_raw

    return redirect(url_for('register_step2'))


@app.route('/register/step2', methods=['GET', 'POST'])
def register_step2():
    if 'reg_email' not in session:
        return redirect(url_for('register_step1'))

    if request.method == 'GET':
        return render_template('register_step2.html')

    username          = request.form.get('username', '').strip()
    name              = request.form.get('name', '').strip()
    surname           = request.form.get('surname', '').strip()
    phone             = request.form.get('phone', '').strip()
    keystroke_enabled = 1 if request.form.get('security') else 0

    if not username:
        flash('Username-ul este obligatoriu.', 'error')
        return render_template('register_step2.html')

    user_id = str(uuid.uuid4())
    now     = datetime.utcnow().isoformat()

    insert('users', {
        'user_id':           user_id,
        'email':             session['reg_email'],
        'username':          username,
        'password_hash':     session['reg_password_hash'],
        'name':              name,
        'surname':           surname,
        'phone':             phone,
        'keystroke_enabled': keystroke_enabled,
        'created_at':        now,
    })

    session.pop('reg_email', None)
    session.pop('reg_password_hash', None)
    session.pop('reg_keystrokes', None)

    flash('Cont creat cu succes! Te poti autentifica.', 'success')
    return redirect(url_for('login'))
    
    
@app.route('/register/face', methods=['POST'])
def register_face():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'status': 'error', 'message': 'Neautentificat'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Request invalid'}), 400

    frames = data.get('frames', [])
    if len(frames) != 3:
        return jsonify({'status': 'error', 'message': 'Sunt necesare exact 3 cadre'}), 400

    result = face_enroll(user_id, frames)

    if result['status'] == 'enrolled':
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@app.route('/register/face', methods=['DELETE'])
def revoke_face_api():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'status': 'error', 'message': 'Neautentificat'}), 401
    revoke_enrollment(user_id)   # funcția există deja, importată ca revoke_enrollment
    return jsonify({'status': 'revoked'}), 200

@app.route('/face/enroll', methods=['GET'])
def face_enroll_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = find_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    return render_template('face_enroll.html', user=user)

@app.route('/settings/revoke-face', methods=['POST'])
def revoke_face():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    revoke_enrollment(session['user_id'])
    flash('Profilul facial a fost revocat.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/dev/face', methods=['GET'])
def dev_face():
    if not app.debug:
        return 'Not available in production', 403

    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Dev — Face Test</title></head>
    <body>
      <h2>Test agent facial</h2>
      <video id="video" width="400" autoplay style="transform: scaleX(-1)"></video>
      <button onclick="capture()">Capturează și testează</button>
      <canvas id="canvas" width="400" height="300" style="display:none"></canvas>
      <pre id="result" style="margin-top:20px; background:#f0f0f0; padding:10px"></pre>

      <script>
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(stream => { document.getElementById('video').srcObject = stream; })
          .catch(err => { document.getElementById('result').textContent = 'Camera indisponibila: ' + err; });

        function capture() {
          const video  = document.getElementById('video');
          const canvas = document.getElementById('canvas');
          const ctx = canvas.getContext('2d');
          ctx.translate(400, 0);
          ctx.scale(-1, 1);
          ctx.drawImage(video, 0, 0, 400, 300);
          const frame  = canvas.toDataURL('image/jpeg');

          fetch('/dev/face/analyze', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ frame: frame })
          })
          .then(r => r.json())
          .then(data => {
            document.getElementById('result').textContent = JSON.stringify(data, null, 2);
          });
        }
      </script>
    </body>
    </html>
    """
    return html


@app.route('/dev/face/analyze', methods=['POST'])
def dev_face_analyze():
    if not app.debug:
        return jsonify({'error': 'Not available in production'}), 403

    data = request.get_json()
    if not data or 'frame' not in data:
        return jsonify({'status': 'error', 'message': 'Cadru lipsă'}), 400

    user_id = session.get('user_id', 'a1b2e510-ab70-4421-b692-4de11dd1a1ef')

    result = face_analyze(user_id, data['frame'], login_id='dev-test')
    return jsonify(result), 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    identifier = request.form.get('identifier', '').strip()
    password   = request.form.get('password', '')
    ks_raw     = request.form.get('keystrokes_data', '[]')
    user       = find_user_by_identifier(identifier)

    if not user or not bcrypt.checkpw(
        password.encode('utf-8'),
        user['password_hash'].encode('utf-8')
    ):
        session['failed_password_attempts'] = session.get('failed_password_attempts', 0) + 1
        pw_attempts = session['failed_password_attempts']

        if user:
            insert('security_events', {
                'event_id':         str(uuid.uuid4()),
                'user_id':          user['user_id'],
                'device_id':        '',
                'event_type':       'failed_password',
                'timestamp':        datetime.utcnow().isoformat(),
                'details':          f'attempt {pw_attempts}',
                'confirm_token':    '',
                'token_expires_at': '',
                'resolved':         0,
            })
            if pw_attempts >= 3:
                send_security_alert_email(
                    user['email'], pw_attempts,
                    datetime.utcnow().isoformat()
                )

        flash('Email/username sau parola incorecta.', 'error')
        return render_template('login.html')

    had_failed_password = session.get('failed_password_attempts', 0) >= 1
    session.pop('failed_password_attempts', None)

    device_info_dict = get_device_info(request)
    fingerprint      = generate_fingerprint_hash(device_info_dict)
    incoming_token   = request.form.get('device_token', '').strip()

    # find_device nu mai primeste calea CSV
    status, device = find_device(user['user_id'], fingerprint, incoming_token)
    print(f"[DEVICE DEBUG] status={status} token_received='{incoming_token[:8] if incoming_token else 'EMPTY'}...' fingerprint={fingerprint[:8]}...")

    if status == 'new_device':
        new_token = generate_device_token()
        device    = create_device(user['user_id'], fingerprint, new_token)
        session['new_device_token'] = new_token
    elif status in ('browser_updated', 'token_cleared'):
        new_token = generate_device_token() if status == 'token_cleared' else None
        repair_device_connection(device, status, fingerprint, new_token)
        if status == 'token_cleared':
            session['new_device_token'] = new_token

    # ── Scoring + decizie orchestrator (inainte de 2FA) ─────────────────────
    login_id  = str(uuid.uuid4())
    now       = datetime.utcnow().isoformat()
    user_id   = user['user_id']
    device_id = device['device_id']

    device_login_count_rows = execute_query(
        "SELECT login_count FROM devices WHERE device_id=? LIMIT 1", [device_id]
    )
    device_login_count = int(device_login_count_rows[0]['login_count']) if device_login_count_rows else 0
    print(f"[KS DEBUG] keystroke_enabled={user['keystroke_enabled']} device_login_count={device_login_count} threshold={ENROLLMENT_LOGINS}")

    ks_result = {'keystroke_score': 1.0, 'score_raw': None,
                 'threshold': None, 'n_enrollment': 0,
                 'features': None, 'profile': None,
                 'status': 'enrollment', 'decision': 'insufficient_data'}

    if int(user['keystroke_enabled']) == 1 and device_login_count >= ENROLLMENT_LOGINS:
        ks_result = ks_analyze(user_id, device_id, ks_raw)

    ks_decision   = ks_result.get('decision', 'insufficient_data')
    ip_address    = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ip_info       = get_ip_info(ip_address)
    ip_result     = ip_analyze(user_id, ip_address)
    ip_score      = ip_result['ip_score']
    ip_decision   = ip_result['decision']
    face_decision = 'opted_out'

    orch_result = decide(ks_decision, ip_decision, face_decision)
    decision    = orch_result['decision']

    print(f"[DEBUG] keystroke={ks_result['keystroke_score']:.3f} "
          f"raw={ks_result.get('score_raw')} ip={ip_score:.3f} decision={decision}")

    # ── Cale directa: allow fara 2FA ─────────────────────────────────────────
    if decision == 'allow':
        record_ip(user_id, ip_address, ip_info)
        sample_added = False

        if int(user['keystroke_enabled']) == 1:
            label = 'enrollment_genuine' if device_login_count < ENROLLMENT_LOGINS else 'test_genuine'
            save_keystroke_sample(user_id, device_id, login_id, ks_raw, attempt_label=label)
            sample_added = True

        final_score = ks_result['keystroke_score'] * 0.7 + ip_score * 0.3

        historical_suspicious = False
        failed_count_rows = execute_query(
            "SELECT COUNT(*) as cnt FROM security_events WHERE user_id=? AND event_type='failed_2fa'",
            [user_id]
        )
        if failed_count_rows and failed_count_rows[0]['cnt'] >= 3:
            historical_suspicious = True

        login_status = (
            'active_flagged_suspicious'
            if (had_failed_password or historical_suspicious)
            else 'active'
        )

        if ks_result['keystroke_score'] < 0.3:
            login_status = 'unlawful'
            send_unlawful_login_email(user['email'], format_device_info(str(device_info_dict)), now)

        log_ml_event(user_id, device_id, login_id, ks_result,
                     ip_score, final_score, decision, login_status, sample_added)

        insert('login_attempts', {
            'login_id':        login_id,
            'user_id':         user_id,
            'device_id':       device_id,
            'timestamp':       now,
            'device_info':     str(device_info_dict),
            'location':        f"{ip_info.get('city')}, {ip_info.get('country')}",
            'ip_address':      ip_address,
            'keystroke_score': ks_result['keystroke_score'],
            'ip_score':        ip_score,
            'final_score':     final_score,
            'classification':  ks_result.get('status'),
            'decision':        decision,
            'twofa_passed':    0,
            'status':          login_status,
        })
        insert('sessions', {
            'session_id': login_id,
            'user_id':    user_id,
            'status':     login_status,
            'created_at': now,
        })

        if login_status == 'active_flagged_suspicious':
            confirm_token = str(uuid.uuid4())
            token_expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
            confirm_url   = url_for('confirm_identity', token=confirm_token, _external=True)
            insert('security_events', {
                'event_id':         str(uuid.uuid4()),
                'user_id':          user_id,
                'device_id':        device_id,
                'event_type':       'suspicious_login',
                'timestamp':        now,
                'details':          'flagged la login direct (fara 2FA)',
                'confirm_token':    confirm_token,
                'token_expires_at': token_expires,
                'resolved':         0,
            })
            send_confirm_identity_email(user['email'], confirm_url, now,
                                        format_device_info(str(device_info_dict)))

        increment_device_login_count(device_id)
        new_token = session.pop('new_device_token', None)
        session['user_id']  = user_id
        session['username'] = user['username']
        session.permanent   = True

        response = make_response(redirect(url_for('dashboard')))
        if new_token:
            response.set_cookie('device_token', new_token,
                                max_age=60*60*24*365, httponly=False, samesite='Lax')
        return response

    # ── Cale 2FA: orchestratorul cere verificare suplimentara ─────────────────
    code       = generate_2fa_code()
    session_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(minutes=4)).isoformat()

    insert('twofa_codes', {
        'session_id': session_id,
        'code':       code,
        'expires_at': expires_at,
    })
    send_2fa_email(user['email'], code)

    append_auth_audit(
        stage='2fa_code_generated',
        user_id=user_id,
        email=user['email'],
        session_id=session_id,
        device_id=device_id,
        ip_address=ip_address,
        stored_code=code,
        expires_at=expires_at,
        is_expired=False,
        twofa_attempts=0,
        reason=f'orchestrator_decision={decision}',
        device_info=str(device_info_dict)
    )

    session['pending_user_id']            = user_id
    session['pending_session_id']         = session_id
    session['pending_keystrokes']         = ks_raw
    session['pending_device_id']          = device_id
    session['pending_device_info']        = str(device_info_dict)
    session['twofa_attempts']             = 0
    session['had_failed_password']        = had_failed_password
    session['impostor_sample_saved']      = False
    session['pending_ks_score']           = float(ks_result['keystroke_score'])
    session['pending_ks_score_raw']       = float(ks_result['score_raw']) if ks_result['score_raw'] is not None else None
    session['pending_ks_threshold']       = float(ks_result['threshold']) if ks_result['threshold'] is not None else None
    session['pending_ks_status']          = str(ks_result.get('status', 'enrollment'))
    session['pending_ks_decision']        = str(ks_decision)
    session['pending_ip_score']           = float(ip_score)
    session['pending_ip_city']            = str(ip_info.get('city') or '')
    session['pending_ip_country']         = str(ip_info.get('country') or '')
    session['pending_ip_address']         = ip_address
    session['pending_orchestrator_dec']   = decision
    session['pending_login_id']           = login_id
    session['pending_login_timestamp']    = now
    session['pending_device_login_count'] = int(device_login_count)
    return redirect(url_for('two_fa'))


@app.route('/2fa', methods=['GET', 'POST'])
def two_fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('2fa.html')

    entered_code = request.form.get('code', '').strip()
    session_id   = session.get('pending_session_id')
    user_id      = session.get('pending_user_id', '')
    device_id    = session.get('pending_device_id', '')
    device_info  = session.get('pending_device_info', '')
    ip_address   = request.remote_addr
    user_temp    = find_user_by_id(user_id)
    email_temp   = user_temp['email'] if user_temp else ''

    append_auth_audit(
        stage='2fa_submit_received',
        user_id=user_id, email=email_temp, session_id=session_id,
        device_id=device_id, ip_address=ip_address,
        entered_code=entered_code,
        twofa_attempts=session.get('twofa_attempts', 0),
        reason='user_submitted_code', device_info=device_info
    )

    # Cauta codul in DB
    row = fetchone('twofa_codes', {'session_id': str(session_id)})

    if not row:
        append_auth_audit(stage='2fa_session_not_found', user_id=user_id,
                          email=email_temp, session_id=session_id,
                          device_id=device_id, ip_address=ip_address,
                          entered_code=entered_code,
                          reason='session_id_not_found', device_info=device_info)
        flash('Codul nu a fost gasit. Incearca din nou.', 'error')
        return redirect(url_for('login'))

    stored_code = str(row['code']).zfill(6)
    expires_at  = datetime.fromisoformat(str(row['expires_at']))

    # Verificare expirare
    if datetime.utcnow() > expires_at:
        append_auth_audit(stage='2fa_expired', user_id=user_id, email=email_temp,
                          session_id=session_id, device_id=device_id,
                          ip_address=ip_address, entered_code=entered_code,
                          stored_code=stored_code,
                          codes_match=(entered_code == stored_code),
                          expires_at=expires_at.isoformat(), is_expired=True,
                          twofa_attempts=session.get('twofa_attempts', 0),
                          reason='code_expired', device_info=device_info)

        if not session.get('impostor_sample_saved'):
            impostor_ks  = session.get('pending_keystrokes', '[]')
            impostor_uid = session.get('pending_user_id', '')
            impostor_did = session.get('pending_device_id', '')
            if impostor_uid and impostor_did and impostor_ks != '[]':
                save_keystroke_sample(impostor_uid, impostor_did,
                                      'expired_2fa', impostor_ks,
                                      attempt_label='test_impostor')
                session['impostor_sample_saved'] = True

        delete_where('twofa_codes', {'session_id': str(session_id)})
        for k in ['pending_user_id', 'pending_session_id', 'pending_keystrokes',
                  'pending_device_id', 'pending_device_info', 'twofa_attempts',
                  'had_failed_password', 'impostor_sample_saved']:
            session.pop(k, None)
        flash('Codul a expirat. Te rugam sa te autentifici din nou.', 'error')
        return redirect(url_for('login'))

    # Verificare cod gresit
    if entered_code != stored_code:
        session['twofa_attempts'] = session.get('twofa_attempts', 0) + 1
        attempts = session['twofa_attempts']
        
        reason = 'code_mismatch'
        if len(entered_code) != 6:
            reason = 'entered_code_wrong_length'

        append_auth_audit(stage='2fa_compare_failed', user_id=user_id,
                          email=email_temp, session_id=session_id,
                          device_id=device_id, ip_address=ip_address,
                          entered_code=entered_code, stored_code=stored_code,
                          codes_match=False, expires_at=expires_at.isoformat(),
                          is_expired=False, twofa_attempts=attempts,
                          reason=reason, device_info=device_info)

        if attempts == 1 and not session.get('impostor_sample_saved'):
            impostor_ks  = session.get('pending_keystrokes', '[]')
            impostor_uid = session.get('pending_user_id', '')
            impostor_did = session.get('pending_device_id', '')
            if impostor_uid and impostor_did and impostor_ks != '[]':
                save_keystroke_sample(impostor_uid, impostor_did,
                                      'failed_2fa', impostor_ks,
                                      attempt_label='test_impostor')
                session['impostor_sample_saved'] = True

        insert('security_events', {
            'event_id':         str(uuid.uuid4()),
            'user_id':          user_id,
            'device_id':        device_id,
            'event_type':       'failed_2fa',
            'timestamp':        datetime.utcnow().isoformat(),
            'details':          f'attempt {attempts}',
            'confirm_token':    '',
            'token_expires_at': '',
            'resolved':         0,
        })

        if attempts == 2 and user_temp:
            send_security_alert_email(user_temp['email'], attempts,
                                      datetime.utcnow().isoformat())

        if attempts >= 3:
            append_auth_audit(stage='2fa_locked_out', user_id=user_id,
                              email=email_temp, session_id=session_id,
                              device_id=device_id, ip_address=ip_address,
                              entered_code=entered_code, stored_code=stored_code,
                              codes_match=False, expires_at=expires_at.isoformat(),
                              is_expired=False, twofa_attempts=attempts,
                              reason='three_failed_attempts', device_info=device_info)

            if not session.get('impostor_sample_saved'):
                impostor_ks  = session.get('pending_keystrokes', '[]')
                impostor_uid = session.get('pending_user_id', '')
                impostor_did = session.get('pending_device_id', '')
                if impostor_uid and impostor_did and impostor_ks != '[]':
                    save_keystroke_sample(impostor_uid, impostor_did,
                                          'failed_2fa_lockout', impostor_ks,
                                          attempt_label='test_impostor')

            delete_where('twofa_codes', {'session_id': str(session_id)})
            for k in ['pending_user_id', 'pending_session_id', 'pending_keystrokes',
                      'pending_device_id', 'pending_device_info', 'twofa_attempts',
                      'had_failed_password', 'impostor_sample_saved']:
                session.pop(k, None)

            flash('Prea multe incercari. Te rugam sa te autentifici din nou.', 'error')
            return redirect(url_for('login'))

        flash('Cod incorect.', 'error')
        return render_template('2fa.html')

    # ── Cod corect ─────────────────────────────────────────────────────────

    append_auth_audit(stage='2fa_compare_success', user_id=user_id,
                      email=email_temp, session_id=session_id,
                      device_id=device_id, ip_address=ip_address,
                      entered_code=entered_code, stored_code=stored_code,
                      codes_match=True, expires_at=expires_at.isoformat(),
                      is_expired=False,
                      twofa_attempts=session.get('twofa_attempts', 0),
                      reason='code_valid', device_info=device_info)

    delete_where('twofa_codes', {'session_id': str(session_id)})

    user_id     = session.get('pending_user_id')
    ks_raw      = session.get('pending_keystrokes', '[]')
    device_id   = session.get('pending_device_id')
    device_info = session.get('pending_device_info', '')
    user        = find_user_by_id(user_id)
    attempts    = session.get('twofa_attempts', 0)
    had_failed_password = session.get('had_failed_password', False)

    # Preia rezultatele de scoring calculate deja in login()
    ks_result          = session.get('pending_ks_result', {
                             'keystroke_score': 1.0, 'score_raw': None,
                             'threshold': None, 'n_enrollment': 0,
                             'features': None, 'profile': None,
                             'status': 'enrollment', 'decision': 'insufficient_data'})
    ip_score           = session.get('pending_ip_score', 1.0)
    ip_info            = session.get('pending_ip_info', {})
    ip_address         = session.get('pending_ip_address', request.remote_addr)
    decision           = session.get('pending_orchestrator_dec', '2fa')
    login_id           = session.get('pending_login_id', str(uuid.uuid4()))
    now                = session.get('pending_login_timestamp', datetime.utcnow().isoformat())
    device_login_count = session.get('pending_device_login_count', 0)

    record_ip(user_id, ip_address, ip_info)

    # Salveaza sample keystroke
    sample_added = False
    if user and int(user['keystroke_enabled']) == 1:
        label = 'enrollment_genuine' if device_login_count < ENROLLMENT_LOGINS else 'test_genuine'
        save_keystroke_sample(user_id, device_id, login_id, ks_raw, attempt_label=label)
        sample_added = True

    final_score = ks_result['keystroke_score'] * 0.7 + ip_score * 0.3

    # Verificare istoricul de failed_2fa
    historical_suspicious = False
    failed_count_rows = execute_query(
        "SELECT COUNT(*) as cnt FROM security_events WHERE user_id=? AND event_type='failed_2fa'",
        [user_id]
    )
    if failed_count_rows and failed_count_rows[0]['cnt'] >= 3:
        historical_suspicious = True

    login_status = (
        'active_flagged_suspicious'
        if (attempts >= 1 or had_failed_password or historical_suspicious)
        else 'active'
    )

    if ks_result['keystroke_score'] < 0.3:
        login_status = 'unlawful'
        if user:
            send_unlawful_login_email(user['email'], format_device_info(device_info), now)

    print(f"[DEBUG] keystroke={ks_result['keystroke_score']:.3f} "
          f"raw={ks_result.get('score_raw')} ip={ip_score:.3f} decision={decision}")

    log_ml_event(user_id, device_id, login_id, ks_result,
                 ip_score, final_score, decision, login_status, sample_added)

    if decision == '2fa_reenrollment':
        update('devices', {'login_count': 0, 'enrolled': 0}, {'device_id': device_id})

    insert('login_attempts', {
        'login_id':        login_id,
        'user_id':         user_id,
        'device_id':       device_id,
        'timestamp':       now,
        'device_info':     device_info,
        'location':        f"{ip_info.get('city')}, {ip_info.get('country')}",
        'ip_address':      ip_address,
        'keystroke_score': ks_result['keystroke_score'],
        'ip_score':        ip_score,
        'final_score':     final_score,
        'classification':  ks_result.get('status'),
        'decision':        decision,
        'twofa_passed':    1,
        'status':          login_status,
    })
    insert('sessions', {
        'session_id': login_id,
        'user_id':    user_id,
        'status':     login_status,
        'created_at': now,
    })

    if login_status == 'active_flagged_suspicious':
        confirm_token = str(uuid.uuid4())
        token_expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        confirm_url   = url_for('confirm_identity', token=confirm_token, _external=True)

        insert('security_events', {
            'event_id':         str(uuid.uuid4()),
            'user_id':          user_id,
            'device_id':        device_id,
            'event_type':       'suspicious_login',
            'timestamp':        now,
            'details':          f'{attempts} failed 2FA attempts before success',
            'confirm_token':    confirm_token,
            'token_expires_at': token_expires,
            'resolved':         0,
        })
        if user:
            send_confirm_identity_email(user['email'], confirm_url, now,
                                        format_device_info(device_info))

    if device_id:
        increment_device_login_count(device_id)

    new_token = session.pop('new_device_token', None)
    for k in ['pending_user_id', 'pending_session_id', 'pending_keystrokes',
              'pending_device_id', 'pending_device_info', 'twofa_attempts',
              'had_failed_password', 'impostor_sample_saved',
              'pending_ks_result', 'pending_ip_score', 'pending_ip_info',
              'pending_ip_address', 'pending_orchestrator_dec', 'pending_login_id',
              'pending_login_timestamp', 'pending_device_login_count']:
        session.pop(k, None)

    session['user_id']  = user_id
    session['username'] = user['username'] if user else ''
    session.permanent   = True

    response = make_response(redirect(url_for('dashboard')))
    if new_token:
        response.set_cookie('device_token', new_token,
                            max_age=60*60*24*365, httponly=False, samesite='Lax')
    return response


@app.route('/confirm-identity', methods=['GET'])
def confirm_identity():
    token  = request.args.get('token', '').strip()
    action = request.args.get('response', '').strip()

    if not token:
        return render_template('confirm_identity.html', valid=False, token='')

    rows = execute_query(
        "SELECT * FROM security_events WHERE confirm_token=? LIMIT 1", [token]
    )

    if not rows:
        return render_template('confirm_identity.html', state='invalid')

    record = rows[0]

    if int(record['resolved']) != 0:
        return render_template('confirm_identity.html', state='invalid')

    expires_at = datetime.fromisoformat(record['token_expires_at'])
    if datetime.utcnow() > expires_at:
        return render_template('confirm_identity.html', state='invalid')

    if action == 'confirm':
        update('security_events', {'resolved': 1}, {'confirm_token': token})
        return render_template('confirm_identity.html', state='confirmed')

    if action == 'deny':
        update('security_events', {'resolved': -1}, {'confirm_token': token})
        return render_template('confirm_identity.html', state='denied')

    return render_template('confirm_identity.html', state='pending', token=token)


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = find_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Istoricul loginurilor
    logins = []
    login_rows = execute_query(
        "SELECT * FROM login_attempts WHERE user_id=? ORDER BY timestamp DESC",
        [user_id]
    )
    for row in login_rows:
        loc = str(row['location'] or '')
        logins.append({
            'timestamp': str(row['timestamp'] or '')[:16].replace('T', ' '),
            'location':  loc if loc not in ('', 'nan', 'None, None', 'None') else 'N/A',
            'device':    format_device_info_text(str(row['device_info'] or '')),
            'status':    str(row['status'] or 'active'),
        })

    # Dispozitivele asociate
    devices = []
    device_rows = execute_query(
        "SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC",
        [user_id]
    )
    for row in device_rows:
        login_count = int(row['login_count'] or 0)
        enrolled    = int(row['enrolled']    or 0)
        devices.append({
            'first_seen':   str(row['first_seen'] or '')[:16].replace('T', ' '),
            'last_seen':    str(row['last_seen']  or '')[:16].replace('T', ' '),
            'login_count':  login_count,
            'enrolled':     enrolled,
            'progress_pct': min(int(login_count / 20 * 100), 100),
        })
    
    needs_face_enroll = (
        int(user.get('keystroke_enabled', 0)) == 1 and
        int(user.get('face_enabled', 0)) == 0
    )

    return render_template('dashboard.html', user=user, logins=logins, devices=devices,
                           enrollment_target=20, needs_face_enroll=needs_face_enroll)


@app.route('/settings/toggle-keystroke', methods=['POST'])
def toggle_keystroke():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    row     = fetchone('users', {'user_id': user_id})
    if row:
        current = int(row['keystroke_enabled'] or 0)
        new_val = 0 if current == 1 else 1
        update('users', {'keystroke_enabled': new_val}, {'user_id': user_id})
        msg = ('Autentificarea comportamentala a fost activata.'
               if new_val == 1
               else 'Autentificarea comportamentala a fost dezactivata.')
        flash(msg, 'success')
    else:
        flash('Eroare la actualizarea setarilor.', 'error')

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        execute_query(
            "UPDATE sessions SET status='closed' WHERE user_id=?", [user_id]
        )
        from utils.database import get_db
        get_db().commit()

    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)