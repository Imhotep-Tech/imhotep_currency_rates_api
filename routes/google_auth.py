from flask import Blueprint, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth, OAuthError
from extensions import oauth, db
import uuid
import os
from werkzeug.security import generate_password_hash, check_password_hash
from imhotep_mail import send_mail
from config import CSRFForm

google_auth_bp = Blueprint('google_auth', __name__)

@google_auth_bp.route("/register_google")
def login_google():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_auth.authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@google_auth_bp.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    try:
        # create the google oauth client
        token = google.authorize_access_token()
        # Access token from google (needed to get user info)
        resp = google.get('userinfo')
        # userinfo contains stuff u specificed in the scrope
        user_info = resp.json()
        user = oauth.google.userinfo()# uses openid endpoint to fetch user info

        user_mail = user_info["email"]
        user_username = user_mail.split('@')[0]
        user_mail_verify = user_info["verified_email"]

        existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?",user_mail)

        if existing_mail:
            user = db.execute("SELECT user_id FROM users WHERE LOWER(user_mail) = ?",user_mail)

            session["logged_in"] = True
            session["user_id"] = user
            session.permanent = True
            return redirect("/home")

        session["user_mail"] = user_mail
        session["user_mail_verify"] = user_mail_verify

        existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?",user_username)

        if existing_username:
            #error_existing = "Username is already in use. Please choose another one."
            return render_template("add_username_google_login.html",form = CSRFForm())

        session["user_username"] = user_username
        return render_template('add_password_google_login.html',form = CSRFForm())

    except OAuthError as error:
        # Catch the OAuthError and handle it
        if error.error == 'access_denied':
            error_message = "Google login was canceled. Please try again."
            return render_template("login.html", error=error_message,form = CSRFForm())
        else:
            error_message = "An error occurred. Please try again."
            return render_template("login.html", error=error_message,form = CSRFForm())
        
@google_auth_bp.route("/add_password_google_login", methods=["POST"])
def add_password_google_login():

    user_password = request.form.get("user_password")

    hashed_password = generate_password_hash(user_password)

    user_username = session.get("user_username")
    user_mail = session.get("user_mail")

    api_key = str(uuid.uuid4())

    db.execute("INSERT INTO users (user_username, user_password, user_mail, user_mail_verify, api_key) VALUES ( ?, ?, ?, ?, ?)",
                user_username,hashed_password,user_mail, "verified", api_key)

    user_id = db.execute("SELECT user_id FROM users WHERE user_username = ?", user_username)

    smtp_server = 'smtp.gmail.com'
    smtp_port = 465
    username = 'imhotepfinance@gmail.com'  # Replace with your Gmail email address
    password =  os.getenv('MAIL_PASSWORD')    # Replace with the app password generated from Google account settings

    # Sending an email to a Gmail address
    to_email = f"{user_mail}"
    subject = 'Welcome To Imhotep Exchange Rate API'
    body = f'Welcome {user_username} To Imhotep Exchange Rate API'
    is_html = False

    success, error = send_mail(smtp_server, smtp_port, username, password, to_email, subject, body, is_html)
    if error:
        print("Error on sending the code ",error)

    session["logged_in"] = True
    session["user_id"] = user_id
    session.permanent = True
    return redirect("/home")

@google_auth_bp.route("/add_username_google_login", methods=["POST"])
def add_username_google_login():

    user_username = request.form.get("user_username")

    existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?",
        user_username)
    
    if existing_username:
        error_existing = "Username is already in use. Please choose another one."
        return render_template("add_username_google_login.html", error=error_existing,form = CSRFForm())

    session["user_username"] = user_username
    return render_template('add_password_google_login.html',form = CSRFForm())
