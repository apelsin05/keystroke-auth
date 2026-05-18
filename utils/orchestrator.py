"""
orchestrator.py
---------------
Combina deciziile locale ale agentilor si returneaza decizia finala.

Principiu: orchestratorul primeste DECIZII, nu scoruri.
Aritmetica pe scoruri a fost inlocuita cu un risk matrix explicit.
"""


def decide(ks_decision, ip_decision, face_decision='opted_out'):
    """
    Risk matrix pentru decizia finala de autentificare.

    Parametri:
        ks_decision   : 'accept' | 'uncertain' | 'reject' | 'insufficient_data'
        ip_decision   : 'accept' | 'uncertain'
        face_decision : 'accept' | 'uncertain' | 'reject' | 'opted_out'

    Returneaza dict cu:
        'decision'      : 'allow' | '2fa' | '2fa_reenrollment'
        'ks_decision'   : decizia keystroke primita
        'ip_decision'   : decizia ip primita
        'face_decision' : decizia faciala primita
        'reason'        : explicatie scurta (pentru log si debug)
    """

    # Enrollment in curs. nu avem profil format, nu penalizam
    if ks_decision == 'insufficient_data':
        return _result('allow', ks_decision, ip_decision, face_decision,
                       'enrollment in curs, fara profil format')

    # Mismatch sever la keystroke. re-enrollment obligatoriu
    if ks_decision == 'reject':
        return _result('2fa_reenrollment', ks_decision, ip_decision, face_decision,
                       'keystroke: mismatch sever')

    # Ambii agenti principali accepta. acces direct
    if ks_decision == 'accept' and ip_decision == 'accept':
        return _result('allow', ks_decision, ip_decision, face_decision,
                       'keystroke + ip: accept')

    # Keystroke accept, IP incert. facial poate rezolva situatia
    if ks_decision == 'accept' and ip_decision == 'uncertain':
        if face_decision == 'accept':
            return _result('allow', ks_decision, ip_decision, face_decision,
                           'keystroke + facial: accept, ip nou ignorat')
        return _result('2fa', ks_decision, ip_decision, face_decision,
                       'keystroke accept, ip nou, facial insuficient')

    # Keystroke incert, IP accept.facial poate rezolva situatia
    if ks_decision == 'uncertain' and ip_decision == 'accept':
        if face_decision == 'accept':
            return _result('allow', ks_decision, ip_decision, face_decision,
                           'ip + facial: accept, keystroke incert ignorat')
        return _result('2fa', ks_decision, ip_decision, face_decision,
                       'keystroke incert, ip accept, facial insuficient')

    # Ambii incerți.2FA obligatoriu indiferent de facial
    return _result('2fa', ks_decision, ip_decision, face_decision,
                   'keystroke + ip: ambii incerti')


def _result(decision, ks, ip, face, reason):
    return {
        'decision':      decision,
        'ks_decision':   ks,
        'ip_decision':   ip,
        'face_decision': face,
        'reason':        reason,
    }