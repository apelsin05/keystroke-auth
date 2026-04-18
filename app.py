import os
import json
import uuid
import csv
import random
import string
from datetime import datetime, timedelta

import bcrypt
import pandas as pd
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, make_response, redirect, url_for
)
from flask_session import Session

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
from utils.agent_keystroke import compare_profiles, save_keystroke_sample
from utils.agent_ip import get_ip_info, score_ip, record_ip
from utils.orchestrator import decide

# ── App setup

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

# Server-side session config (stores session data on disk, not in cookie)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'data', 'sessions')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
Session(app)

# ── CSV file paths 

DATA_DIR        = os.path.join(os.path.dirname(__file__), 'data')
USERS_CSV       = os.path.join(DATA_DIR, 'users.csv')
LOGINS_CSV      = os.path.join(DATA_DIR, 'logins.csv')
KEYSTROKES_CSV  = os.path.join(DATA_DIR, 'keystrokes.csv')
TWO_FA_CSV      = os.path.join(DATA_DIR, '2fa_codes.csv')
SESSIONS_CSV    = os.path.join(DATA_DIR, 'sessions.csv')
DEVICES_CSV     = os.path.join(DATA_DIR, 'devices.csv')
SECURITY_CSV = os.path.join(DATA_DIR, 'security_events.csv')
KNOWN_IPS_CSV = os.path.join(DATA_DIR, 'known_ips.csv')

# ── CSV helpers 

def ensure_csv(path, headers):
    """Create a CSV file with headers if it doesn't exist yet."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

def init_csv_files():
    ensure_csv(USERS_CSV,      ['user_id', 'email', 'username', 'password_hash',
                                 'name', 'surname', 'phone', 'keystroke_enabled',
                                 'created_at'])
    ensure_csv(LOGINS_CSV,     ['login_id', 'user_id', 'timestamp', 'device_info',
                                 'location', 'status'])
    ensure_csv(KEYSTROKES_CSV, ['sample_id', 'user_id', 'device_id', 'login_id',
                             'final_sequence_json', 'auxiliary_json',
                             'has_backspace', 'confidence', 'is_truncated',
                             'recorded_at'])
    ensure_csv(TWO_FA_CSV,     ['session_id', 'code', 'expires_at'])
    ensure_csv(SESSIONS_CSV,   ['session_id', 'user_id', 'status', 'created_at'])
    ensure_csv(DEVICES_CSV,    ['device_id', 'user_id', 'fingerprint_hash', 'token',
                                 'first_seen', 'last_seen', 'login_count', 'enrolled'])
    ensure_csv(SECURITY_CSV, ['event_id', 'user_id', 'device_id', 'event_type',
                           'timestamp', 'details', 'confirm_token',
                           'token_expires_at', 'resolved'])
    ensure_csv(KNOWN_IPS_CSV, ['ip_id', 'user_id', 'ip_address', 'country', 'city',
                            'isp', 'first_seen', 'last_seen', 'times_seen', 'trusted'])

# Run on startup
init_csv_files()

# ── ENROLLMENT threshold 

ENROLLMENT_LOGINS = 20   # collect data for first 20 logins before scoring

# ── Utility: generate a 6-digit 2FA code 

def generate_2fa_code():
    return ''.join(random.choices(string.digits, k=6))

# ── Utility: save / read users from CSV ─

def find_user_by_email(email):
    try:
        df = pd.read_csv(USERS_CSV)
        row = df[df['email'] == email]
        return row.iloc[0].to_dict() if not row.empty else None
    except Exception:
        return None

def find_user_by_identifier(identifier):
    """Find by email OR username."""
    try:
        df = pd.read_csv(USERS_CSV)
        row = df[(df['email'] == identifier) | (df['username'] == identifier)]
        return row.iloc[0].to_dict() if not row.empty else None
    except Exception:
        return None

def find_user_by_id(user_id):
    try:
        df = pd.read_csv(USERS_CSV)
        row = df[df['user_id'] == user_id]
        return row.iloc[0].to_dict() if not row.empty else None
    except Exception:
        return None
    

    # pt identificarea tioului de device, in emailul de alerta
def format_device_info(device_info_str):
    """
    Transforma string-ul brut de device info intr-un text lizibil pentru email.
    Extrage: sistem de operare, browser, rezolutie, timezone.
    """
    try:
        # device_info_str e rezultatul lui str(dict), il convertim inapoi
        import ast
        info = ast.literal_eval(device_info_str)
    except Exception:
        return device_info_str  # fallback: returnam ce avem

    ua = info.get('userAgent', '')

    # detectam OS din User-Agent
    if 'Windows NT 10' in ua:
        os_name = 'Windows 10/11'
    elif 'Windows NT 6' in ua:
        os_name = 'Windows 7/8'
    elif 'Mac OS X' in ua:
        os_name = 'macOS'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_name = 'iOS'
    elif 'Linux' in ua:
        os_name = 'Linux'
    else:
        os_name = 'Necunoscut'

    # detectam browser-ul
    if 'Edg/' in ua:
        browser = 'Microsoft Edge'
    elif 'Chrome/' in ua:
        browser = 'Google Chrome'
    elif 'Firefox/' in ua:
        browser = 'Mozilla Firefox'
    elif 'Safari/' in ua and 'Chrome' not in ua:
        browser = 'Safari'
    else:
        browser = 'Necunoscut'

    width    = info.get('screenWidth', '?')
    height   = info.get('screenHeight', '?')
    timezone = info.get('timezone', 'Necunoscuta')

    return (
        f"Sistem de operare: {os_name}<br>"
        f"Browser: {browser}<br>"
        f"Rezolutie ecran: {width}×{height}<br>"
        f"Fus orar: {timezone}"
    )


def format_device_info_text(device_info_str):
    """
    Versiune simpla a lui format_device_info — returneaza text curat,
    folosita in tabelele din dashboard (nu in emailuri).
    Ex: "Chrome · Windows 10/11"
    """
    try:
        import ast
        info = ast.literal_eval(device_info_str)
    except Exception:
        return "Necunoscut"

    ua = info.get('userAgent', '')

    if 'Windows NT 10' in ua or 'Windows NT 11' in ua:
        os_name = 'Windows 10/11'
    elif 'Windows NT 6' in ua:
        os_name = 'Windows 7/8'
    elif 'Mac OS X' in ua:
        os_name = 'macOS'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_name = 'iOS'
    elif 'Linux' in ua:
        os_name = 'Linux'
    else:
        os_name = 'Necunoscut'

    if 'Edg/' in ua:
        browser = 'Edge'
    elif 'Chrome/' in ua:
        browser = 'Chrome'
    elif 'Firefox/' in ua:
        browser = 'Firefox'
    elif 'Safari/' in ua and 'Chrome' not in ua:
        browser = 'Safari'
    else:
        browser = 'Browser necunoscut'

    return f"{browser} · {os_name}"


def append_row(path, row_dict):
    with open(path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row_dict.keys())
        writer.writerow(row_dict)

# ── Routes

@app.route("/")
def home():
    return redirect(url_for("login"))

# ── REGISTER step 1 

@app.route('/register/step1', methods=['GET', 'POST'])
def register_step1():
    if request.method == 'GET':
        return render_template('register.html')

    # POST: receive email, password, keystroke data
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm-password', '')
    ks_raw   = request.form.get('keystrokes_data', '[]')

    # --- server-side validation (never trust client) ---
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

    # --- hash password ---
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # --- store in session until step 2 completes ---
    session['reg_email']         = email
    session['reg_password_hash'] = password_hash
    session['reg_keystrokes']    = ks_raw

    return redirect(url_for('register_step2'))


# ── REGISTER step 2 

@app.route('/register/step2', methods=['GET', 'POST'])
def register_step2():
    # Guard: if step 1 was never completed, send back
    if 'reg_email' not in session:
        return redirect(url_for('register_step1'))

    if request.method == 'GET':
        return render_template('register_step2.html')

    # POST: receive username + optional fields + checkbox
    username           = request.form.get('username', '').strip()
    name               = request.form.get('name', '').strip()
    surname            = request.form.get('surname', '').strip()
    phone              = request.form.get('phone', '').strip()
    keystroke_enabled  = 1 if request.form.get('security') else 0

    if not username:
        flash('Username-ul este obligatoriu.', 'error')
        return render_template('register_step2.html')

    # Build user record
    user_id = str(uuid.uuid4())
    now     = datetime.utcnow().isoformat()

    append_row(USERS_CSV, {
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

    # # Save registration keystroke sample if security is enabled
    # if keystroke_enabled:
    #     sample_id = str(uuid.uuid4())
    #     append_row(KEYSTROKES_CSV, {
    #         'sample_id':     sample_id,
    #         'user_id':       user_id,
    #         'login_id':      'registration',
    #         'keystroke_json': session.get('reg_keystrokes', '[]'),
    #         'recorded_at':   now,
    #     })

    # Clear registration data from session
    session.pop('reg_email', None)
    session.pop('reg_password_hash', None)
    session.pop('reg_keystrokes', None)

    flash('Cont creat cu succes! Te poti autentifica.', 'success')
    return redirect(url_for('login'))


# ── LOGIN 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    identifier = request.form.get('identifier', '').strip()
    password   = request.form.get('password', '')
    ks_raw     = request.form.get('keystrokes_data', '[]')
    user = find_user_by_identifier(identifier)
    if not user or not bcrypt.checkpw(
        password.encode('utf-8'),
        user['password_hash'].encode('utf-8')
    ):
        # incrementam counter-ul de parole gresite in session
        session['failed_password_attempts'] = session.get('failed_password_attempts', 0) + 1
        pw_attempts = session['failed_password_attempts']

        # daca userul exista dar parola e gresita, logam in security_events
        if user:
            append_row(SECURITY_CSV, {
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
            # la 3 parole gresite consecutive, trimitem email de alerta
            if pw_attempts >= 3:
                send_security_alert_email(
                    user['email'], pw_attempts,
                    datetime.utcnow().isoformat()
                )

        flash('Email/username sau parola incorecta.', 'error')
        return render_template('login.html')

    # parola e corecta — retinem daca au existat incercari esuate anterior
    had_failed_password = session.get('failed_password_attempts', 0) >= 1
    session.pop('failed_password_attempts', None)

    device_info_dict = get_device_info(request)
    fingerprint      = generate_fingerprint_hash(device_info_dict)
    incoming_token   = request.form.get('device_token', '').strip()

    status, device = find_device(user['user_id'], fingerprint, incoming_token, DEVICES_CSV)

    if status == 'new_device':
        new_token = generate_device_token()
        device    = create_device(user['user_id'], fingerprint, new_token, DEVICES_CSV)
        session['new_device_token'] = new_token
    elif status in ('browser_updated', 'token_cleared'):
        new_token = generate_device_token() if status == 'token_cleared' else None
        repair_device_connection(device, status, fingerprint, new_token, DEVICES_CSV)
        if status == 'token_cleared':
            session['new_device_token'] = new_token

    code       = generate_2fa_code()
    session_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(minutes=4)).isoformat()
    append_row(TWO_FA_CSV, {
        'session_id': session_id,
        'code':       code,
        'expires_at': expires_at,
    })
    send_2fa_email(user['email'], code)
    session['pending_user_id']         = user['user_id']
    session['pending_session_id']       = session_id
    session['pending_keystrokes']       = ks_raw
    session['pending_device_id']        = device['device_id']
    session['pending_device_info']      = str(device_info_dict)
    session['twofa_attempts']           = 0
    session['had_failed_password']      = had_failed_password
    return redirect(url_for('two_fa'))


# ── 2FA 

@app.route('/2fa', methods=['GET', 'POST'])
def two_fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('2fa.html')

    entered_code = request.form.get('code', '').strip()
    session_id   = session.get('pending_session_id')

    # --- look up the code in the temporary table ---
    try:
        df  = pd.read_csv(TWO_FA_CSV)
        row = df[df['session_id'] == session_id]
    except Exception:
        flash('Eroare la verificarea codului.', 'error')
        return render_template('2fa.html')

    if row.empty:
        flash('Codul nu a fost gasit. Incearca din nou.', 'error')
        return redirect(url_for('login'))

    record     = row.iloc[0]
    expires_at = datetime.fromisoformat(record['expires_at'])

    # --- check expiry ---
    if datetime.utcnow() > expires_at:
        # delete expired row
        df = df[df['session_id'] != session_id]
        df.to_csv(TWO_FA_CSV, index=False)
        flash('Codul a expirat. Te rugam sa te autentifici din nou.', 'error')
        return redirect(url_for('login'))

    # --- check code ---
    if entered_code != str(record['code']):
        session['twofa_attempts'] = session.get('twofa_attempts', 0) + 1
        attempts = session['twofa_attempts']

        append_row(SECURITY_CSV, {
            'event_id':         str(uuid.uuid4()),
            'user_id':          session.get('pending_user_id', ''),
            'device_id':        session.get('pending_device_id', ''),
            'event_type':       'failed_2fa',
            'timestamp':        datetime.utcnow().isoformat(),
            'details':          f'attempt {attempts}',
            'confirm_token':    '',
            'token_expires_at': '',
            'resolved':         0,
        })

        if attempts == 2:
            user_temp = find_user_by_id(session.get('pending_user_id'))
            if user_temp:
                send_security_alert_email(
                    user_temp['email'], attempts,
                    datetime.utcnow().isoformat()
                )

        if attempts >= 3:
            df = df[df['session_id'] != session_id]
            df.to_csv(TWO_FA_CSV, index=False)
            session.pop('pending_user_id', None)
            session.pop('pending_session_id', None)
            session.pop('pending_keystrokes', None)
            session.pop('pending_device_id', None)
            session.pop('pending_device_info', None)
            session.pop('twofa_attempts', None)
            flash('Prea multe incercari. Te rugam sa te autentifici din nou.', 'error')
            return redirect(url_for('login'))

        flash('Cod incorect.', 'error')
        return render_template('2fa.html')

    # --- code is valid: delete it immediately ---
    df = df[df['session_id'] != session_id]
    df.to_csv(TWO_FA_CSV, index=False)


    user_id     = session.get('pending_user_id')
    ks_raw      = session.get('pending_keystrokes', '[]')
    device_id   = session.get('pending_device_id')
    device_info = session.get('pending_device_info', '')
    user        = find_user_by_id(user_id)
    now         = datetime.utcnow().isoformat()
    login_id    = str(uuid.uuid4())
    attempts             = session.get('twofa_attempts', 0)
    had_failed_password  = session.get('had_failed_password', False)

    # verificam si istoricul din security_events: daca userul a avut cel putin
    # 3 failed_2fa in trecut (din sesiuni anterioare), login-ul curent e tot suspicious
    historical_suspicious = False
    try:
        df_sec = pd.read_csv(SECURITY_CSV)
        failed_count = len(df_sec[
            (df_sec['user_id'] == user_id) &
            (df_sec['event_type'] == 'failed_2fa')
        ])
        if failed_count >= 3:
            historical_suspicious = True
    except Exception:
        pass

    login_status = (
        'active_flagged_suspicious'
        if (attempts >= 1 or had_failed_password or historical_suspicious)
        else 'active'
    )

    ip_address = request.remote_addr
    ip_info    = get_ip_info(ip_address)
    ip_score   = score_ip(user_id, ip_address, KNOWN_IPS_CSV)
    record_ip(user_id, ip_address, ip_info, KNOWN_IPS_CSV)

    # implementare scor de risc
    keystroke_score = 1.0  # stub pana la implementarea finala a keystroke capture
    result          = decide(keystroke_score, ip_score)
    print(f"[DEBUG] IP score: {ip_score}, Decision: {result}") #pt debug in consola
    decision        = result['decision']

    # daca decizia e re-enrollment, resetam contorul dispozitivului
    if decision == '2fa_reenrollment':
        try:
            df_dev = pd.read_csv(DEVICES_CSV)
            df_dev.loc[df_dev['device_id'] == device_id, 'login_count'] = 0
            df_dev.loc[df_dev['device_id'] == device_id, 'enrolled']    = 0
            df_dev.to_csv(DEVICES_CSV, index=False)
        except Exception:
            pass

    try:
        df_dev  = pd.read_csv(DEVICES_CSV)
        dev_row = df_dev[df_dev['device_id'] == device_id]
        device_login_count = int(dev_row.iloc[0]['login_count']) if not dev_row.empty else 0
    except Exception:
        device_login_count = 0

    if user and int(user['keystroke_enabled']) == 1:
        if device_login_count < ENROLLMENT_LOGINS:
            save_keystroke_sample(KEYSTROKES_CSV, user_id, device_id, login_id, ks_raw)
        else:
            match = compare_profiles(KEYSTROKES_CSV, user_id, ks_raw)
            if not match:
                login_status = 'unlawful'
                send_unlawful_login_email(user['email'], format_device_info(device_info), now)

    append_row(LOGINS_CSV, {
        'login_id':    login_id,
        'user_id':     user_id,
        'timestamp':   now,
        'device_info': device_info,
        'location':    f"{ip_info.get('city')}, {ip_info.get('country')}",
        'status':      login_status,
    })
    append_row(SESSIONS_CSV, {
        'session_id': login_id,
        'user_id':    user_id,
        'status':     login_status,
        'created_at': now,
    })
    
    if login_status == 'active_flagged_suspicious':
        confirm_token = str(uuid.uuid4())
        token_expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        confirm_url   = url_for('confirm_identity', token=confirm_token, _external=True)

        append_row(SECURITY_CSV, {
            'event_id':         str(uuid.uuid4()),
            'user_id':          user_id,
            'device_id':        device_id,
            'event_type':       'suspicious_login',
            'timestamp':        now,
            'details':          f'{attempts} failed attempts before success',
            'confirm_token':    confirm_token,
            'token_expires_at': token_expires,
            'resolved':         0,
        })

        if user:
            send_confirm_identity_email(user['email'], confirm_url, now, format_device_info(device_info))

    if device_id:
        increment_device_login_count(device_id, DEVICES_CSV)

    new_token = session.pop('new_device_token', None)
    session.pop('pending_user_id', None)
    session.pop('pending_session_id', None)
    session.pop('pending_keystrokes', None)
    session.pop('pending_device_id', None)
    session.pop('pending_device_info', None)
    session.pop('twofa_attempts', None)
    session.pop('had_failed_password', None)
    session['user_id']  = user_id
    session['username'] = user['username'] if user else ''
    session.permanent   = True

    response = make_response(redirect(url_for('dashboard')))
    if new_token:
        response.set_cookie(
            'device_token',
            new_token,
            max_age=60*60*24*365,
            httponly=False,
            samesite='Lax'
        )
    return response


# ── CONFIRM IDENTITY

@app.route('/confirm-identity', methods=['GET'])
def confirm_identity():
    token  = request.args.get('token', '').strip()
    action = request.args.get('response', '').strip()

    if not token:
        return render_template('confirm_identity.html', valid=False, token='')

    try:
        df  = pd.read_csv(SECURITY_CSV)
        row = df[df['confirm_token'] == token]
    except Exception:
        return render_template('confirm_identity.html', valid=False, token='')

    if row.empty:
        return render_template('confirm_identity.html', state='invalid')

    record = row.iloc[0]

    if int(record['resolved']) != 0:
        return render_template('confirm_identity.html', state='invalid')

    expires_at = datetime.fromisoformat(record['token_expires_at'])
    if datetime.utcnow() > expires_at:
        return render_template('confirm_identity.html', state='invalid')

    if action == 'confirm':
        df.loc[df['confirm_token'] == token, 'resolved'] = 1
        df.to_csv(SECURITY_CSV, index=False)
        return render_template('confirm_identity.html', state='confirmed')

    if action == 'deny':
        df.loc[df['confirm_token'] == token, 'resolved'] = -1
        df.to_csv(SECURITY_CSV, index=False)
        return render_template('confirm_identity.html', state='denied')

    return render_template('confirm_identity.html', state='pending', token=token)


# ── DASHBOARD

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = find_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Istoricul logarilor (logins.csv, filtrat pe user_id, ordine descrescatoare)
    logins = []
    try:
        df_logins = pd.read_csv(LOGINS_CSV)
        df_user_logins = df_logins[df_logins['user_id'] == user_id].copy()
        df_user_logins = df_user_logins.sort_values('timestamp', ascending=False)
        for _, row in df_user_logins.iterrows():
            loc = str(row.get('location', ''))
            logins.append({
                'timestamp': str(row.get('timestamp', ''))[:16].replace('T', ' '),
                'location':  loc if loc not in ('', 'nan', 'None, None', 'None') else 'N/A',
                'device':    format_device_info_text(str(row.get('device_info', ''))),
                'status':    str(row.get('status', 'active')),
            })
    except Exception:
        pass

    # Dispozitivele asociate (devices.csv, filtrat pe user_id)
    devices = []
    try:
        df_devices = pd.read_csv(DEVICES_CSV)
        df_user_devices = df_devices[df_devices['user_id'] == user_id].copy()
        df_user_devices = df_user_devices.sort_values('last_seen', ascending=False)
        for _, row in df_user_devices.iterrows():
            login_count = int(row.get('login_count', 0))
            enrolled    = int(row.get('enrolled', 0))
            devices.append({
                'first_seen':   str(row.get('first_seen', ''))[:16].replace('T', ' '),
                'last_seen':    str(row.get('last_seen', ''))[:16].replace('T', ' '),
                'login_count':  login_count,
                'enrolled':     enrolled,
                'progress_pct': min(int(login_count / 20 * 100), 100),
            })
    except Exception:
        pass

    return render_template('dashboard.html', user=user, logins=logins, devices=devices,
                           enrollment_target=20)


@app.route('/settings/toggle-keystroke', methods=['POST'])
def toggle_keystroke():
    """Activeaza / dezactiveaza autentificarea comportamentala."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    try:
        df = pd.read_csv(USERS_CSV)
        current = int(df.loc[df['user_id'] == user_id, 'keystroke_enabled'].values[0])
        new_val = 0 if current == 1 else 1
        df.loc[df['user_id'] == user_id, 'keystroke_enabled'] = new_val
        df.to_csv(USERS_CSV, index=False)
        if new_val == 1:
            flash('Autentificarea comportamentala a fost activata.', 'success')
        else:
            flash('Autentificarea comportamentala a fost dezactivata.', 'success')
    except Exception:
        flash('Eroare la actualizarea setarilor.', 'error')

    return redirect(url_for('dashboard'))


# ── LOGOUT 

@app.route('/logout')
def logout():
    user_id = session.get('user_id')

    # mark session as closed in sessions.csv
    if user_id:
        try:
            df = pd.read_csv(SESSIONS_CSV)
            df.loc[df['user_id'] == user_id, 'status'] = 'closed'
            df.to_csv(SESSIONS_CSV, index=False)
        except Exception:
            pass

    session.clear()
    return redirect(url_for('login'))


