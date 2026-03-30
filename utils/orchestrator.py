def decide(keystroke_score, ip_score):
    """
    Combină scorul keystroke cu scorul IP și returnează decizia finală.
    
    Args:
        keystroke_score: float 0.0-1.0 (din agent_keystroke.py)
        ip_score: float 0.0 sau 1.0 (din agent_ip.py)
    
    Returns:
        dict: {
            'decision': 'allow' | '2fa' | '2fa_reenrollment',
            'final_score': float,
            'keystroke_score': float,
            'ip_score': float
        }
    """
    final_score = (keystroke_score * 0.7) + (ip_score * 0.3)
    
    if keystroke_score < 0.1:
        # Mismatch sever, re-enrollment obligatoriu
        decision = '2fa_reenrollment'
    elif keystroke_score < 0.3:
        # Mismatch suspect, cere 2FA
        decision = '2fa'
    elif ip_score == 0.0:
        # Keystroke OK, dar IP nou, cere 2FA
        decision = '2fa'
    else:
        # Keystroke OK + IP cunoscut, permite
        decision = 'allow'
    
    return {
        'decision': decision,
        'final_score': final_score,
        'keystroke_score': keystroke_score,
        'ip_score': ip_score
    }