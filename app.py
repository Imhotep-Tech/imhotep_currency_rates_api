from flask import render_template, redirect, Flask, session, request, make_response, url_for, jsonify
from imhotep_mail import send_mail
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from sqlalchemy import text
import requests
from datetime import date, timedelta, now, datetime
from sqlalchemy.exc import OperationalError
from flask_session import Session
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import json
from cs50 import SQL

#define the app
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('secret_key')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'myapp_session:'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session timeout with each request

sess = Session(app)

@app.before_request
def refresh_session():
    session.permanent = True  # Keep the session permanent for every request

db = SQL(os.getenv("DATABASE_URL"))

csrf = CSRFProtect(app)

class CSRFForm(FlaskForm):
    pass

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True  # Ensure cookies are only sent over HTTPS
)

# Define your CSP policy
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net",  # Allow Bootstrap and Font Awesome
        "https://cdn.tailwindcss.com",  # Allow Tailwind CSS CDN
        "'unsafe-inline'",  # Allow inline scripts (needed for some Bootstrap features)
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",  # Allow inline styles (necessary for Bootstrap)
        "https://cdn.jsdelivr.net",  # Allow Bootstrap CSS
        "https://cdnjs.cloudflare.com"  # Allow Font Awesome
    ],
    'font-src': [
        "'self'", 
        "https://cdnjs.cloudflare.com",  # Allow Font Awesome fonts
        "https://fonts.gstatic.com"  # If using Google Fonts
    ],
    'img-src': ["'self'", "data:"],  # Add any other domains as necessary
    'connect-src': ["'self'"],  # Add any other domains for AJAX calls if necessary
}


# Set up Talisman with the CSP configuration
Talisman(app, content_security_policy=csp)

limiter = Limiter(
    get_remote_address,  # This will limit based on the IP address of the requester
    app=app,
    default_limits=["250 per day", "75 per hour"]  # Set default rate limits
)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

CURRENCY_API_URL = os.getenv("CURRENCY_API_URL")

@app.after_request
def add_header(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

@app.after_request
def remove_csp_header(response):
    if 'Content-Security-Policy' in response.headers:
        del response.headers['Content-Security-Policy']
    return response

@app.after_request
def set_content_type_options(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error_handle.html', error_code = "404", error_description = "We can't find that page."), 404

@app.errorhandler(400)
def session_expired(error):
    return render_template('error_handle.html', error_code = "400", error_description= "Session Expired."), 400

@app.errorhandler(429)
def request_amount_exceed(error):
    return render_template('error_handle.html', error_code = "429", error_description= "You exceeded the Maximum amount of requests! Please Try Again Later"), 429

@app.errorhandler(405)
def page_not_found(error):
    return render_template('error_handle.html', error_code = "405", error_description = "Method Not Allowed."), 405

'''@app.errorhandler(Exception)
def server_error(error):
    return render_template('error_handle.html', error_code = "500", error_description = "Something went wrong."), 500

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error_handle.html', error_code = "500", error_description="Something Went Wrong."), 500'''

def send_verification_mail_code(user_mail):
    verification_code = secrets.token_hex(4)
    smtp_server = 'smtp.gmail.com'
    smtp_port = 465
    username = 'imhotepfinance@gmail.com'  # Replace with your Gmail email address
    password =  os.getenv('MAIL_PASSWORD')    # Replace with the app password generated from Google account settings

    # Sending an email to a Gmail address
    to_email = f"{user_mail}"
    subject = 'Email Verification'
    body = f'Your verification code is: {verification_code}'
    is_html = False

    success, error = send_mail(smtp_server, smtp_port, username, password, to_email, subject, body, is_html)
    if error:
        print("Error on sending the code ",error)

    session["verification_code"] = verification_code

def logout():
        session.permanent = False
        session["logged_in"] = False
        session.clear()

def security_check(user_id, check_pass):
    password_db = db.execute("SELECT user_password FROM users WHERE user_id = ?", user_id)

    if check_password_hash(password_db, check_pass):
        return True
    else:
        return False
    
@app.route("/", methods=["GET"])
def index():
    if session.get("logged_in"):
        return redirect("/home")
    else:
        return render_template("login.html", form=CSRFForm())

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "GET":
        return render_template("register.html", form=CSRFForm())
    
    user_username = (request.form.get("user_username").strip()).lower()
    user_password = request.form.get("user_password")
    user_mail = request.form.get("user_mail").lower()

    if "@" in user_username:
        error = "username should not have @"
        return render_template("register.html", error=error, form=CSRFForm())

    if "@" not in user_mail:
        error = "mail should have @"
        return render_template("register.html", error=error, form=CSRFForm())

    existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?", user_username)
    if existing_username:
        error_existing = "Username is already in use. Please choose another one. or "
        return render_template("register.html", error=error_existing, form=CSRFForm())

    existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?", user_mail)
    
    if existing_mail:
        error_existing = "Mail is already in use. Please choose another one. or "
        return render_template("register.html", error=error_existing, form=CSRFForm())

    try:
        last_user_id = db.execute("SELECT MAX(user_id) FROM users")
        user_id = last_user_id + 1
    except:
        user_id = 1

    session["user_id"] = user_id
    hashed_password = generate_password_hash(user_password)

    send_verification_mail_code(user_mail)

    db.execute("INSERT INTO users (user_id, user_username, user_password, user_mail, user_mail_verify) VALUES (?, ?, ?, ?, ?)",
                user_id ,user_username, hashed_password,user_mail, "not_verified")

    return render_template("mail_verify.html", user_mail=user_mail, user_username=user_username, form=CSRFForm())

@app.route("/mail_verification", methods=["POST", "GET"])
def mail_verification():
    if request.method == "GET":
        return render_template("mail_verify.html", form=CSRFForm())
    else:

        verification_code = request.form.get("verification_code").strip()
        user_id = session.get("user_id")
        user_mail = request.form.get("user_mail")
        user_username = request.form.get("user_username")
        if verification_code == session.get("verification_code"):
            db.execute("UPDATE users SET user_mail_verify = ? WHERE user_id = ?", "verified", user_id)

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

            success="Email verified successfully. You can now log in."
            return render_template("login.html", success=success, form=CSRFForm())

        else:
            error="Invalid verification code."
            return render_template("mail_verify.html", error=error, form=CSRFForm())

@app.route("/register_google")
def login_google():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
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
            return render_template("add_username_google_login.html", form=CSRFForm())

        session["user_username"] = user_username
        return render_template('add_password_google_login.html', form=CSRFForm())

    except OAuthError as error:
        # Catch the OAuthError and handle it
        if error.error == 'access_denied':
            error_message = "Google login was canceled. Please try again."
            return render_template("login.html", error=error_message, form=CSRFForm())
        else:
            error_message = "An error occurred. Please try again."
            return render_template("login.html", error=error_message, form=CSRFForm())
        
@app.route("/add_password_google_login", methods=["POST"])
def add_password_google_login():

    user_password = request.form.get("user_password")

    hashed_password = generate_password_hash(user_password)

    user_username = session.get("user_username")
    user_mail = session.get("user_mail")

    try:
        last_user_id = db.execute("SELECT MAX(user_id) FROM users")

        user_id = last_user_id + 1
    except:
        user_id = 1

    db.execute("INSERT INTO users (user_id, user_username, user_password, user_mail, user_mail_verify) VALUES (?, ?, ?, ?, ?)",
               user_id , user_username,hashed_password,user_mail, "verified")

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

@app.route("/add_username_google_login", methods=["POST"])
def add_username_google_login():

    user_username = request.form.get("user_username")

    existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?",
        user_username)
    
    if existing_username:
        error_existing = "Username is already in use. Please choose another one."
        return render_template("add_username_google_login.html", form=CSRFForm(), error=error_existing)

    session["user_username"] = user_username
    return render_template('add_password_google_login.html', form=CSRFForm())

@app.route("/login", methods=["POST"])
#@limiter.limit("5 per minute")
def login():
    user_username_mail = (request.form.get("user_username_mail").strip()).lower()
    user_password = request.form.get("user_password")

    if "@" in user_username_mail:
        try:
            login_db = db.execute("SELECT user_password, user_mail_verify FROM users WHERE LOWER(user_mail) = ?",user_username_mail)

            password_db = login_db[0]["user_password"]
            user_mail_verify = login_db[0]["user_mail_verify"]

            if check_password_hash(password_db, user_password):

                if user_mail_verify == "verified":
                    user = db.execute("SELECT user_id FROM users WHERE LOWER(user_mail) = ? AND user_password = ?"
                                        ,user_username_mail, password_db)

                    session["logged_in"] = True
                    session["user_id"] = user
                    session.permanent = True
                    return redirect("/home")
                else:
        
                    error_verify = "Your mail isn't verified"
                    return render_template("login.html", error_verify=error_verify, form=CSRFForm())
            else:

                print("password_db: ", password_db)
                print("user_password: ",user_password)

                error = "Your username or password are incorrect!"
                return render_template("login.html", error=error, form=CSRFForm())
        except:
            error = "Your E-mail or password are incorrect!"
            return render_template("login.html", error=error, form=CSRFForm())
    else:
        try:
            login_db = db.execute("SELECT user_password, user_mail_verify FROM users WHERE LOWER(user_username) = ?", user_username_mail)

            password_db = login_db[0]["user_password"]
            user_mail_verify = login_db[0]["user_mail_verify"]

            if check_password_hash(password_db, user_password):
                if user_mail_verify == "verified":
                    user = db.execute("SELECT user_id FROM users WHERE LOWER(user_username) = ? AND user_password = ?",
                        user_username_mail, password_db)

                    session["logged_in"] = True
                    session["user_id"] = user
                    session.permanent = True
                    return redirect("/home")
                else:
                    error_verify = "Your mail isn't verified"
                    return render_template("login.html", error_verify=error_verify, form=CSRFForm())
            else:
                error = "Your username or password are incorrect!"
                return render_template("login.html", error=error, form=CSRFForm())
        except:
            error = "Your username or password are incorrect!"
            return render_template("login.html", error=error, form=CSRFForm())

@app.route("/manual_mail_verification", methods=["POST", "GET"])
def manual_mail_verification():
    if request.method == "GET":
        return render_template("manual_mail_verification.html", form=CSRFForm())
    else:
        user_mail = (request.form.get("user_mail").strip()).lower()
        try:
            mail_verify_db = db.execute("SELECT user_id, user_mail_verify FROM users WHERE user_mail = ?",user_mail)

            user_id = mail_verify_db[0]
            mail_verify = mail_verify_db[1]
        except:
            error_not = "This mail isn't used on the webapp!"
            return render_template("manual_mail_verification.html", error_not = error_not, form=CSRFForm())

        if mail_verify == "verified":
            error = "This Mail is already used and verified"
            return render_template("login.html", error=error, form=CSRFForm())
        else:
            session["user_id"] = user_id
            send_verification_mail_code(user_mail)
            return render_template("mail_verify.html", form=CSRFForm())

@app.route("/forget_password",methods=["POST", "GET"])
def forget_password():
    if request.method == "GET":
        return render_template("forget_password.html", form=CSRFForm())
    else:

        user_mail = request.form.get("user_mail")
        try:
            db.execute("SELECT user_mail FROM users WHERE user_mail = ?", user_mail)

            temp_password = secrets.token_hex(4)

            smtp_server = 'smtp.gmail.com'
            smtp_port = 465
            username = 'imhotepfinance@gmail.com'  # Replace with your Gmail email address
            password =  os.getenv('MAIL_PASSWORD')    # Replace with the app password generated from Google account settings

            # Sending an email to a Gmail address
            to_email = user_mail
            subject = 'Reset Password'
            body = f'Your temporary Password is: {temp_password}'
            is_html = False

            success, error = send_mail(smtp_server, smtp_port, username, password, to_email, subject, body, is_html)
            if error:
                print("Error on sending the code ",error)

            hashed_password = generate_password_hash(temp_password)
            db.execute("UPDATE users SET user_password = ? WHERE user_mail = ?",hashed_password, user_mail)

            success="The Mail is sent check Your mail for your new password"
            return render_template("login.html", success=success, form=CSRFForm())
        except:
            error = "This Email isn't saved"
            return render_template("forget_password.html", error = error, form=CSRFForm())

@app.route("/logout", methods=["GET", "POST"])
def logout_route():
        logout()
        return redirect("/login_page")
