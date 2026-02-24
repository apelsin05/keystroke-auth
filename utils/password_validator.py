def validate_password(password):
    errors = []
    if len(password) < 8: errors.append('too short')
    if not any(c.isupper() for c in password): errors.append('no uppercase')
    if not any(c.islower() for c in password): errors.append('no lowercase')
    if not any(c.isdigit() for c in password): errors.append('no digit')
    if not any(c in '!@#$%^&*()_+-=[]{};\':"|,.<>/?' for c in password): errors.append('no special char')
    return errors