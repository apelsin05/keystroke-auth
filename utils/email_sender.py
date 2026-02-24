def send_2fa_email(email, code):
    print(f"[2FA] Send to {email}: {code}")

def send_unlawful_login_email(email, device_info, timestamp):
    print(f"[ALERT] Unlawful login on {email} at {timestamp}")