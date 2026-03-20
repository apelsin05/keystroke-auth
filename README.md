# Keystroke Dynamics Authentication System

> Bachelor's thesis project — B.Eng. Computer Science & Information Technology  
> "Dunărea de Jos" University of Galați, Faculty FACIEE, 2025–2026  
> **Status: Work in Progress** - Major changes and database incoming 

---

## Overview

This system implements a **behavioural biometric authentication layer** based on keystroke dynamics. It replaces traditional two-factor authentication with a passive, continuous identity verification mechanism derived from the user's typing rhythm.

The core hypothesis: each user exhibits statistically consistent inter-key timing patterns when typing a known passphrase. These patterns constitute a biometric profile that can be used to detect credential theft or session hijacking, even after successful password entry.

---

## Authentication pipeline

```
[Password entry + keystroke capture]
        │
        ▼
[bcrypt credential verification]
        │
        ▼
[TOTP-style 2FA — 6-digit code, 4-minute TTL, sent via email]
        │
        ▼
[Keystroke profile comparison]
        │
     ┌──┴──┐
   MATCH  MISMATCH
     │       │
  grant    flag as 'unlawful'
  access   + alert email to registered address
```

Authentication succeeds only if all three layers pass: password, 2FA code, and keystroke profile match.

---

## Keystroke profiling

### Enrollment phase

The first **20 logins** operate in enrollment mode. Keystroke samples are collected and stored without scoring. This builds a sufficient baseline profile for each user.

The threshold is defined as:
```python
ENROLLMENT_LOGINS = 20
```

### Scoring phase

After enrollment, each login compares the live keystroke sample against the stored profile via `utils/keystroke_processor.py`. The comparison logic (`compare_profiles`) determines whether the typing pattern is consistent with the registered user.

If the match fails, the login is flagged with `status = 'unlawful'` and the registered email receives an anomaly alert including device fingerprint and timestamp.

---

## Data model

All persistent state is stored in flat CSV files under `data/`. No external database dependency.

| File | Contents |
|---|---|
| `users.csv` | User records: UUID, email, username, bcrypt hash, keystroke opt-in flag, login count |
| `keystrokes.csv` | Raw keystroke samples: per-login JSON payloads, linked to user and login IDs |
| `logins.csv` | Login audit log: timestamp, device info, session status (`active` / `unlawful`) |
| `2fa_codes.csv` | Ephemeral 2FA tokens: session-scoped, expire after 4 minutes, deleted on use |
| `sessions.csv` | Session lifecycle records: created and closed on logout |

Keystroke data is stored as JSON arrays per login event, keyed by `sample_id` and `user_id`.

---

## Security implementation details

- **Password hashing**: bcrypt with per-user salt via `bcrypt.gensalt()`
- **Session storage**: server-side filesystem sessions (`flask-session`), not client-side cookies
- **Session lifetime**: 2-hour TTL via `PERMANENT_SESSION_LIFETIME`
- **2FA tokens**: single-use, 4-minute expiry, deleted immediately on successful verification
- **Device fingerprinting**: captured at login via `utils/device_fingerprint.py`, stored in login audit log
- **Anomaly alerting**: unlawful login events trigger an email to the registered address via `utils/email_sender.py`
- **Input validation**: server-side password validation enforced independently of client via `utils/password_validator.py`

---

## Registration flow

Two-step process. Step 1 collects email, password, and a keystroke sample from the password field. Step 2 collects username and optional profile fields. The user may opt in or out of keystroke-based authentication at registration.

Intermediate state is held in the server-side session between steps. On completion, the keystroke sample from Step 1 is committed as the first enrollment record if the feature is enabled.

---

## Project structure

```
keystroke-auth/
├── app.py                          # Flask application, all routes
├── requirements.txt
├── static/                         # CSS, SCSS, JS assets
├── templates/                      # Jinja2 HTML templates
│   ├── login.html
│   ├── register.html
│   ├── register_step2.html
│   ├── 2fa.html
│   └── dashboard.html
├── utils/
│   ├── keystroke_processor.py      # Profile construction and comparison logic
│   ├── device_fingerprint.py       # Request-based device info extraction
│   ├── email_sender.py             # 2FA and anomaly alert delivery
│   └── password_validator.py       # Server-side password policy enforcement
└── data/                           # Auto-initialised CSV data store
```

---

## Stack

```
Python 3 · Flask · flask-session · bcrypt · pandas · Jinja2 · SCSS
```

---

## Running locally

```bash
git clone https://github.com/apelsin05/keystroke-auth
cd keystroke-auth
pip install -r requirements.txt
python app.py
```

The `data/` directory and all CSV files are initialised automatically on first run.

---

## Research context

This implementation is the technical component of a bachelor's thesis investigating **behavioural biometric authentication** as a replacement for conventional 2FA in web applications. The research scope includes:

- Keystroke dynamics as a continuous authentication signal
- Enrollment convergence and false rejection rate under varying sample sizes
- Comparison with TOTP-based 2FA in the context of European banking security standards (PSD2, EBA guidelines on Strong Customer Authentication)

The cross-platform extension (Android) is under development as a parallel workstream.

---

> ⚠️ This is a research prototype. Not intended for production deployment in its current state.
