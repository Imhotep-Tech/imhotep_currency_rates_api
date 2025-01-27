from flask import Blueprint, request, render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from utlis.mail_utils import send_verification_mail_code
from config import Config, CSRFForm
from imhotep_mail import send_mail
import uuid

register_bp = Blueprint('register', __name__)

@register_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html",form = CSRFForm())
    
    username = request.form.get("user_username").strip().lower()
    password = request.form.get("user_password")
    email = request.form.get("user_mail").lower()

    # Check if username or email already exists
    existing_user = db.execute("SELECT * FROM users WHERE user_username = ? OR user_mail = ?", username, email)
    if existing_user:
        return render_template("register.html", error="Username or email already in use", form = CSRFForm())

    # Hash password and insert user into the database
    hashed_password = generate_password_hash(password)
    api_key = str(uuid.uuid4())

    db.execute("INSERT INTO users (user_username, user_password, user_mail, user_mail_verify, api_key) VALUES ( ?, ?, ?, ?, ?)",
                username,hashed_password,email, "not_verified", api_key)

    user_id = db.execute("SELECT user_id FROM users WHERE user_username = ?", username)

    session["user_id"] = user_id

    # Send verification email
    send_verification_mail_code(email)

    return render_template("mail_verify.html", user_mail=email, user_username=username, form = CSRFForm())

@register_bp.route("/mail_verification", methods=["POST", "GET"])
def mail_verification():
    if request.method == "GET":
        return render_template("mail_verify.html", form = CSRFForm())

    verification_code = request.form.get("verification_code").strip()
    user_id = session.get("user_id")

    user_mail = request.form.get("user_mail")
    user_username = request.form.get("user_username")
    if verification_code == session.get("verification_code"):
        db.execute("UPDATE users SET user_mail_verify = ? WHERE user_id = ?", "verified", user_id[0]["user_id"])

        smtp_server = 'smtp.gmail.com'
        smtp_port = 465
        username = 'imhotepfinance@gmail.com'
        password = Config.MAIL_PASSWORD     

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

    else:
        error="Invalid verification code."
        return render_template("mail_verify.html", error=error, form = CSRFForm())
    
@register_bp.route("/manual_mail_verification", methods=["POST", "GET"])
def manual_mail_verification():
    if request.method == "GET":
        return render_template("manual_mail_verification.html", form = CSRFForm())
    else:
        user_mail = (request.form.get("user_mail").strip()).lower()
        mail_verify_db = db.execute("SELECT user_id, user_mail_verify FROM users WHERE user_mail = ?",user_mail)

        if not mail_verify_db:
            error_not = "This mail isn't used on the webapp!"
            return render_template("manual_mail_verification.html", error_not = error_not, form = CSRFForm())
        
        new_mail_verify_db = mail_verify_db[0]
        mail_verify = new_mail_verify_db["user_mail_verify"]

        if mail_verify == "verified":
            error = "This Mail is already used and verified"
            return render_template("login.html", error=error, form = CSRFForm())
        else:
            session["user_id"] = mail_verify_db
            send_verification_mail_code(user_mail)
            return render_template("mail_verify.html", form = CSRFForm())