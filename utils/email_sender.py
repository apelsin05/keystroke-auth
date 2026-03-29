import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
 
load_dotenv()
 
EMAIL_ADDRESS  = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def _send(to_email, subject, body_html):
    """
    Functie interna de trimitere. Toate functiile publice o apeleaza pe aceasta.
    Foloseste Gmail SMTP pe portul 587 cu STARTTLS - prtotocolul recomandat pentru emailuri.
    Daca .env nu e configurat, afiseaza in terminal (fallback pentru dezvoltare).
    """
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print(f"[EMAIL STUB] To: {to_email} | Subject: {subject}")
        print(body_html)
        return
 
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = EMAIL_ADDRESS
    msg['To']      = to_email
    msg.attach(MIMEText(body_html, 'html'))
 
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
    except Exception as e:
        #  daca emailul esueaza logheaza eroarea, nu arunca exceptie inca
        print(f"[EMAIL ERROR] {e}")

def send_2fa_email(to_email, code):
    subject = "Codul tau de verificare"
    body = f"""
    <p>Codul tau de verificare in doi pasi este:</p>
    <h2 style="letter-spacing: 8px;">{code}</h2>
    <p>Codul este valabil <strong>4 minute</strong>.</p>
    <p>Daca nu esti tu cel care a initiat aceasta autentificare, ignora acest email.</p>
    """
    _send(to_email, subject, body)
 
 
def send_unlawful_login_email(to_email, device_info, timestamp):
    """
    Trimis cand profilul biometric nu se potriveste,
    dar userul a trecut totusi de 2FA.
    """
    subject = "Autentificare neobisnuita detectata"
    body = f"""
    <p>Am detectat o autentificare suspicioasa in contul tau. Esti chiar tu?</p>
    <p><strong>Data/ora:</strong> {timestamp}</p>
    <p><strong>Dispozitiv:</strong> {device_info}</p>
    <p>Daca aceasta autentificare nu iti apartine, iti recomandam sa iti schimbi parola imediat.</p>
    """
    _send(to_email, subject, body)
       
def send_security_alert_email(to_email, attempt_count, timestamp):
    """
    Trimis cand se inregistreaza 2 coduri 2FA gresite consecutive.
    Atentioneaza userul ca cineva incearca sa ii acceseze contul.
    """
    subject = "Alerta de securitate: mai multe incercari esuate de autentificare."
    body = f"""
    <p>Am detectat <strong>{attempt_count} incercari esuate</strong> de introducere
    a codului de verificare in contul tau.</p>
    <p><strong>Data/ora:</strong> {timestamp}</p>
    <p>Daca nu esti tu cel care incearca sa se autentifice, contul tau ar putea fi
    vizat de un atac. Iti recomandam sa iti schimbi parola.</p>
    <p>Daca esti tu, verifica codul primit si incearca din nou.</p>
    """
    _send(to_email, subject, body)

def send_confirm_identity_email(to_email, confirm_url, timestamp, device_info):
    """
    Trimis dupa un login reusit care a avut si greseli la 2FA.
    Cere userului sa confirme daca autentificarea i-a apartinut.
    """
    subject = "Ai fost tu? Confirma autentificarea"
    body = f"""
    <p>O autentificare in contul tau a fost finalizata dupa mai multe incercari esuate.</p>
    <p><strong>Data/ora:</strong> {timestamp}</p>
    <p><strong>Dispozitiv:</strong> {device_info}</p>
    <p>Daca aceasta autentificare iti apartine, apasa butonul de mai jos:</p>
    <p><a href="{confirm_url}" style="
        background:#48baf3; color:#35286f; padding:10px 20px;
        border-radius:50px; text-decoration:none; font-weight:bold;">
        Da, am fost eu
    </a></p>
    <p>Daca NU recunosti aceasta autentificare, acceseaza linkul de mai jos
    pentru a restrictiona accesul de pe acel dispozitiv:</p>
    <p><a href="{confirm_url}?response=deny">Nu am fost eu</a></p>
    """
    _send(to_email, subject, body)