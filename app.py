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
    url_for, session, flash
)
from flask_session import Session

from utils.password_validator import validate_password
from utils.email_sender import send_2fa_email, send_unlawful_login_email
from utils.device_fingerprint import get_device_info
from utils.keystroke_processor import compare_profiles, save_keystroke_sample

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
                                 'login_count', 'created_at'])
    ensure_csv(LOGINS_CSV,     ['login_id', 'user_id', 'timestamp', 'device_info',
                                 'location', 'status'])
    ensure_csv(KEYSTROKES_CSV, ['sample_id', 'user_id', 'login_id', 'keystroke_json',
                                 'recorded_at'])
    ensure_csv(TWO_FA_CSV,     ['session_id', 'code', 'expires_at'])
    ensure_csv(SESSIONS_CSV,   ['session_id', 'user_id', 'status', 'created_at'])

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

def increment_login_count(user_id):
    df = pd.read_csv(USERS_CSV)
    df.loc[df['user_id'] == user_id, 'login_count'] += 1
    df.to_csv(USERS_CSV, index=False)

def append_row(path, row_dict):
    with open(path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row_dict.keys())
        writer.writerow(row_dict)

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
        'login_count':       0,
        'created_at':        now,
    })

    # Save registration keystroke sample if security is enabled
    if keystroke_enabled:
        sample_id = str(uuid.uuid4())
        append_row(KEYSTROKES_CSV, {
            'sample_id':     sample_id,
            'user_id':       user_id,
            'login_id':      'registration',
            'keystroke_json': session.get('reg_keystrokes', '[]'),
            'recorded_at':   now,
        })

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

    # --- verify password ---
    if not user or not bcrypt.checkpw(
        password.encode('utf-8'),
        user['password_hash'].encode('utf-8')
    ):
        flash('Email/username sau parola incorecta.', 'error')
        return render_template('login.html')

    # --- get device info for session logging ---
    device_info = get_device_info(request)

    # --- generate and send 2FA code ---
    code       = generate_2fa_code()
    session_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(minutes=4)).isoformat()

    append_row(TWO_FA_CSV, {
        'session_id': session_id,
        'code':       code,
        'expires_at': expires_at,
    })

    send_2fa_email(user['email'], code)

    # --- store login context in session for 2FA route to use ---
    session['pending_user_id']    = user['user_id']
    session['pending_session_id'] = session_id
    session['pending_keystrokes'] = ks_raw
    session['pending_device']     = device_info

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
        flash('Cod incorect.', 'error')
        return render_template('2fa.html')

    # --- code is valid: delete it immediately ---
    df = df[df['session_id'] != session_id]
    df.to_csv(TWO_FA_CSV, index=False)

    # --- resolve user and keystroke data ---
    user_id     = session.get('pending_user_id')
    ks_raw      = session.get('pending_keystrokes', '[]')
    device_info = session.get('pending_device', '')
    user        = find_user_by_id(user_id)
    now         = datetime.utcnow().isoformat()
    login_id    = str(uuid.uuid4())
    login_status = 'active'

    # --- keystroke check (only if user has security enabled) ---
    if user and int(user['keystroke_enabled']) == 1:
        login_count = int(user['login_count'])

        if login_count < ENROLLMENT_LOGINS:
            # Enrollment mode: save sample, always let through
            save_keystroke_sample(KEYSTROKES_CSV, user_id, login_id, ks_raw)

        else:
            # Scoring mode: compare against stored profile
            match = compare_profiles(KEYSTROKES_CSV, user_id, ks_raw)
            if not match:
                login_status = 'unlawful'
                send_unlawful_login_email(user['email'], device_info, now)

    # --- save login record ---
    append_row(LOGINS_CSV, {
        'login_id':    login_id,
        'user_id':     user_id,
        'timestamp':   now,
        'device_info': device_info,
        'location':    '',          # location enrichment: future task
        'status':      login_status,
    })

    # --- save keystroke sample for enrollment logins ---
    if user and int(user['keystroke_enabled']) == 1:
        if int(user['login_count']) < ENROLLMENT_LOGINS:
            pass  # already saved above

    # --- save active session record ---
    append_row(SESSIONS_CSV, {
        'session_id': login_id,
        'user_id':    user_id,
        'status':     login_status,
        'created_at': now,
    })

    # --- increment login count ---
    increment_login_count(user_id)

    # --- set user as logged in ---
    session.pop('pending_user_id', None)
    session.pop('pending_session_id', None)
    session.pop('pending_keystrokes', None)
    session.pop('pending_device', None)

    session['user_id']  = user_id
    session['username'] = user['username'] if user else ''
    session.permanent   = True

    return redirect(url_for('dashboard'))


# ── DASHBOARD

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = find_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)


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


# ── Entry point 

if __name__ == '__main__':
    app.run(debug=True)