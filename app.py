from flask import render_template, redirect, Flask, session, request, make_response, url_for, jsonify
from imhotep_mail import send_mail
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import requests
from datetime import date, timedelta, datetime
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
import uuid

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
    
    if password_db:
        password_db = password_db[0]["user_password"]

    if check_password_hash(password_db, check_pass):
        return True
    else:
        return False

def select_user_data(user_id):
        user_info = db.execute("SELECT user_username, user_mail FROM users WHERE user_id = ?",user_id)

        if user_info:
            user_username = user_info[0]["user_username"]
            user_mail = user_info[0]["user_mail"]
        else:
            user_username = " "
            user_mail = " "

        return user_username, user_mail

# Function to fetch and save new currency data from the external API
def fetch_currency_data():
    response = requests.get(CURRENCY_API_URL)
    if response.status_code == 200:
        data = response.json()
        timestamp = datetime.now()
        
        api_data_db = db.execute("SELECT * FROM api_data")

        if api_data_db:
            db.execute("UPDATE api_data SET base_currency = ?, last_updated_at = ?, json_data = ?",
                "USD", timestamp, json.dumps(data))
        else:
            # Insert the API data into the 'api_data' table
            db.execute("INSERT INTO api_data (base_currency, last_updated_at, json_data) VALUES (?, ?, ?)",
                    "USD", timestamp, json.dumps(data))

        # Get the last inserted API data ID
        api_data_id = db.execute("SELECT id FROM api_data ORDER BY id DESC LIMIT 1")[0]["id"]

        # Clear the currencies table to avoid duplicates
        db.execute("DELETE FROM currencies")

        # Save each currency rate in the 'currencies' table
        for currency_code, details in data["data"].items():
            db.execute("INSERT INTO currencies (api_data_id, currency_code, rate) VALUES (?, ?, ?)",
                       api_data_id, currency_code, details["value"])

        print(f"Currency data successfully fetched and saved at {timestamp}")
        return True
    return False

# Helper function to get the latest rates from the database
def get_latest_rates():
    # Get the most recent API data from the 'api_data' table
    latest_data = db.execute("SELECT * FROM api_data ORDER BY last_updated_at DESC LIMIT 1")

    if not latest_data:
        print("No data found in the 'api_data' table.")
        return None, None

    latest_data = latest_data[0]  # Get the first result

    # Fetch the related currency rates from the 'currencies' table
    currencies = db.execute("SELECT currency_code, rate FROM currencies WHERE api_data_id = ?", latest_data["id"])

    if not currencies:
        print(f"No currency data found for api_data_id {latest_data['id']}.")
        return latest_data, None

    return latest_data, currencies

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

    api_key = str(uuid.uuid4())

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

    hashed_password = generate_password_hash(user_password)

    send_verification_mail_code(user_mail)

    db.execute("INSERT INTO users (user_username, user_password, user_mail, user_mail_verify, api_key) VALUES (?, ?, ?, ?, ?)",
                 user_username, hashed_password ,user_mail, "not_verified", api_key)
    
    user_id = db.execute("SELECT user_id FROM users WHERE user_username = ?", user_username)[0]["user_id"]

    session["user_id"] = user_id

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
        return redirect("/")

@app.route('/home')
def home():
    if not session.get("logged_in"):
        return redirect("/login")
    
    try:
        user_id = session.get("user_id")[0]["user_id"]
        print("user_id = ",user_id)
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error, form=CSRFForm())
    
    api_key_db = db.execute("SELECT api_key, user_username FROM users WHERE user_id = ?", user_id)
    
    if api_key_db:
        api_key = api_key_db[0]["api_key"]
        user_username = api_key_db[0]["user_username"]
    else:
        api_key = str(uuid.uuid4())
        user_username = " "
    return render_template('home.html', api_key=api_key, user_username=user_username)

@app.route("/settings/personal_info", methods=["GET", "POST"])
def personal_info():
    if not session.get("logged_in"):
        return redirect("/login_page")

    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error, form=CSRFForm())

    user_username_db = db.execute("SELECT user_username FROM users WHERE user_id = ?", user_id)
    
    if user_username_db:
        user_username = user_username_db[0]["user_username"]
    else:
        user_username = " "
    
    if request.method == "GET":
        user_username, user_mail = select_user_data(user_id)
        return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, form=CSRFForm())
    else:

        user_username = request.form.get("user_username")
        user_mail = request.form.get("user_mail")

        if "@" in user_username:
            error_existing = "username should not have @"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing, form=CSRFForm())

        if "@" not in user_mail:
            error_existing = "mail should have @"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing, form=CSRFForm())

        user_username_mail_db = db.execute("SELECT user_mail, user_username FROM users WHERE user_id = ?",user_id)
        
        user_mail_db = user_username_mail_db[0]["user_mail"]
        user_username_db = user_username_mail_db[0]["user_username"]

        if user_mail != user_mail_db and user_username != user_username_db:

            existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?",user_mail)

            existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = :user_username" ,user_username)

            if existing_mail:
                error_existing = "Mail is already in use. Please choose another one."
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing, form=CSRFForm())

            if existing_username:
                error_existing = "Username is already in use. Please choose another one."
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail , error=error_existing, form=CSRFForm())

            send_verification_mail_code(user_mail)
            return render_template("mail_verify_change_mail.html", user_mail=user_mail, user_username=user_username, user_mail_db=user_mail_db, form=CSRFForm())

        if user_mail != user_mail_db:
            existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?", user_mail)

            if existing_mail:
                error_existing = "Mail is already in use. Please choose another one. or "
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing, form=CSRFForm())

            send_verification_mail_code(user_mail)
            return render_template("mail_verify_change_mail.html", user_mail=user_mail, user_username=user_username, user_mail_db=user_mail_db, form=CSRFForm())

        if user_username != user_username_db:
            existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?", user_username)

            if existing_username:
                error_existing = "Username is already in use. Please choose another one. or "
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing, form=CSRFForm())

            db.execute("UPDATE users SET user_username = ? WHERE user_id = ?",user_username, user_id)
 
            done = "User Name Changed Successfully!"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, done = done, form=CSRFForm())

    user_username, user_mail = select_user_data(user_id)
    return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, form=CSRFForm())

@app.route("/settings/personal_info/mail_verification", methods=["POST"])
def mail_verification_change_mail():
    if not session.get("logged_in"):
        return redirect("/login_page")
    
    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error, form=CSRFForm())

    verification_code = request.form.get("verification_code").strip()
    user_mail = request.form.get("user_mail")
    user_username = request.form.get("user_username")
    user_mail_db = request.form.get("user_mail_db")

    if verification_code == session.get("verification_code"):
        db.execute("UPDATE users SET user_mail_verify = ?, user_mail = ?, user_username = ? WHERE user_id = ?", "verified", user_mail, user_username, user_id)

        done = "User Mail Changed Successfully!"
        user_username, user_mail = select_user_data(user_id)
        return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, done = done, form=CSRFForm())
    else:
        error="Invalid verification code."
        return render_template("mail_verify_change_mail.html", error=error,user_username=user_username, form=CSRFForm())


@app.route("/settings/security_check", methods=["POST", "GET"])
def security_check_password():
    if not session.get("logged_in"):
        return redirect("/login_page")

    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error, form=CSRFForm())

    if request.method == "GET":
        return render_template("check_pass.html", form=CSRFForm())
    else:

        check_pass = request.form.get("check_pass")
        security = security_check(user_id, check_pass)

        if security:
            return render_template("change_pass.html", user_id = user_id, form=CSRFForm())
        else:
            error = "This password is incorrect!"
            return render_template("check_pass.html", error = error, form=CSRFForm())

@app.route("/settings/security", methods=["POST"])
def security():
    if not session.get("logged_in"):
        return redirect("/login_page")
    else:

        try:
            user_id = session.get("user_id")[0]["user_id"]
        except OperationalError:
                error = "Welcome Back"
                return render_template('error.html', error=error, form=CSRFForm())
        
        new_password = request.form.get("new_password")

        user_mail = db.execute("SELECT user_mail FROM users WHERE user_id = ?",user_id)

        hashed_password = generate_password_hash(new_password)
        
        db.execute("UPDATE users SET user_password = ? WHERE user_id = ?", hashed_password, user_id)

        success = "You password has been changed successfully!"
        return render_template("home.html", success = success, form=CSRFForm())

# Route to fetch the latest currency rates
@app.route('/latest_rates/<string:api_key>/<string:base_currency>', methods=['GET'])
def latest_rates(api_key, base_currency='USD'):
    # Convert base_currency to uppercase
    base_currency = base_currency.upper()

    # Validate the API key
    user = db.execute("SELECT * FROM users WHERE api_key = ?", api_key)
    if not user:
        return jsonify({"error": "Invalid API key"}), 401

    # Get the current time and the latest data from the database
    current_time = datetime.now()
    latest_data, currencies = get_latest_rates()

    # If no data exists or the last update was more than 3 hours ago, fetch new data
    if latest_data is None or (current_time - datetime.fromisoformat(latest_data["last_updated_at"])) > timedelta(hours=3):
        fetch_success = fetch_currency_data()
        if fetch_success:
            latest_data, currencies = get_latest_rates()
        else:
            return jsonify({"error": "Failed to fetch currency data from external API"}), 500

    if currencies is None:
        return jsonify({"error": "No currency data found in the database"}), 500

    # Format the response
    rates = {currency["currency_code"]: currency["rate"] for currency in currencies}

    # Adjust rates based on the requested base currency
    if base_currency != 'USD':
        if base_currency not in rates:
            return jsonify({"error": f"Base currency {base_currency} not found"}), 400
        # Calculate conversion rates relative to the requested base currency
        base_rate = rates[base_currency]
        adjusted_rates = {currency_code: rate / base_rate for currency_code, rate in rates.items()}
        rates = adjusted_rates

    return jsonify({
        "meta": {
            "base_currency": base_currency,
            "last_updated_at": latest_data["last_updated_at"]
        },
        "data": rates
    })

@app.route("/version")
def version():
    return render_template("version.html", form=CSRFForm())

@app.route('/sitemap.xml')
def sitemap():
    pages = []

    ten_days_ago = (datetime.now() - timedelta(days=10)).date().isoformat()
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            pages.append(
                ["https://imhotepexchangeratesapi.pythonanywhere.com/" + str(rule.rule), ten_days_ago]
            )

    sitemap_xml = render_template('sitemap.xml', pages=pages)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"

    return response