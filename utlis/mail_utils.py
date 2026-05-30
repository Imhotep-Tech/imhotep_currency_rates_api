from flask import session
from imhotep_mail import send_mail
import secrets
from config import Config

def send_verification_mail_code(user_mail):
    verification_code = secrets.token_hex(4)
    smtp_server = 'smtp.gmail.com'
    smtp_port = 465
    username = 'imhotepfinance@gmail.com'
    password =  Config.MAIL_PASSWORD

    # Sending an email to a Gmail address
    to_email = f"{user_mail}"
    subject = 'Email Verification'
    body = f'Your verification code is: {verification_code}'
    is_html = False

    success, error = send_mail(smtp_server, smtp_port, username, password, to_email, subject, body, is_html)
    if error:
        print("Error on sending the code ",error)

    session["verification_code"] = verification_code