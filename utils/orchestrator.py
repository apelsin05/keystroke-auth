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
        face_decision : 'accept' | 'uncertain' | 'reject' | 'opted_out' | 'pending'

    Returneaza dict cu:
        'decision'      : 'allow' | '2fa' | '2fa_reenrollment' | 'consult_face'
        'ks_decision'   : decizia keystroke primita
        'ip_decision'   : decizia ip primita
        'face_decision' : decizia faciala primita
        'reason'        : explicatie scurta (pentru log si debug)
    """

    # Enrollment in curs.
    if ks_decision == 'insufficient_data':
        return _result('2fa', ks_decision, ip_decision, face_decision,
                    'enrollment in curs, fara profil format, verificare obligatorie')

    # Mismatch sever la keystroke — agentul facial poate confirma sau infirma identitatea.
    # Daca facial nu a fost inca consultat, il consultam inainte de a lua decizia finala.
    # Daca facial accepta → allow (identitate confirmata biometric).
    # Daca facial respinge → 2fa (posibil impostor; esecul 2FA va stoca datele ca impostor).
    # Altfel (opted_out, uncertain) → 2fa_reenrollment (profilul KS trebuie refacut).
    if ks_decision == 'reject':
        if face_decision == 'pending':
            return _result('consult_face', ks_decision, ip_decision, face_decision,
                           'keystroke reject — consultare agent facial pentru confirmare identitate')
        if face_decision == 'accept':
            return _result('allow', ks_decision, ip_decision, face_decision,
                           'keystroke reject, identitate confirmata facial — acces permis')
        if face_decision == 'reject':
            return _result('2fa', ks_decision, ip_decision, face_decision,
                           'keystroke + facial: ambele resping — posibil impostor, 2FA obligatoriu')
        return _result('2fa_reenrollment', ks_decision, ip_decision, face_decision,
                       'keystroke: mismatch sever, facial indisponibil — re-enrollment necesar')

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
        if face_decision == 'pending':
            return _result('consult_face', ks_decision, ip_decision, face_decision,
                        'keystroke nesigur — consultare agent facial necesara')
        if face_decision == 'accept':
            return _result('allow', ks_decision, ip_decision, face_decision,
                        'ip + facial: accept, keystroke incert ignorat')
        return _result('2fa', ks_decision, ip_decision, face_decision,
                    'keystroke incert, ip accept, facial insuficient')

    # Ambii incerți.2FA obligatoriu indiferent de facial
    if face_decision == 'pending':
        return _result('consult_face', ks_decision, ip_decision, face_decision,
                    'keystroke nesigur — consultare agent facial necesara')
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