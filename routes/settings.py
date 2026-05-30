from flask import render_template, redirect,session, request,Blueprint
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import OperationalError
from flask_limiter import Limiter
from extensions import db
from utlis.mail_utils import send_verification_mail_code
from utlis.settings_utils import select_user_data, security_check
from config import CSRFForm

settings_bp = Blueprint('settings', __name__)

@settings_bp.route("/settings/personal_info", methods=["GET", "POST"])
def personal_info():
    if not session.get("logged_in"):
        return redirect("/login_page")

    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error,form = CSRFForm())

    user_username_db = db.execute("SELECT user_username FROM users WHERE user_id = ?", user_id)
    
    if user_username_db:
        user_username = user_username_db[0]["user_username"]
    else:
        user_username = " "
    
    if request.method == "GET":
        user_username, user_mail = select_user_data(user_id)
        return render_template("personal_info.html", user_username=user_username, user_mail=user_mail,form = CSRFForm())
    else:

        user_username = request.form.get("user_username")
        user_mail = request.form.get("user_mail")

        if "@" in user_username:
            error_existing = "username should not have @"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing,form = CSRFForm())

        if "@" not in user_mail:
            error_existing = "mail should have @"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing,form = CSRFForm())

        user_username_mail_db = db.execute("SELECT user_mail, user_username FROM users WHERE user_id = ?",user_id)
        
        user_mail_db = user_username_mail_db[0]["user_mail"]
        user_username_db = user_username_mail_db[0]["user_username"]

        if user_mail != user_mail_db and user_username != user_username_db:

            existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?",user_mail)

            existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?" ,user_username)

            if existing_mail:
                error_existing = "Mail is already in use. Please choose another one."
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing,form = CSRFForm())

            if existing_username:
                error_existing = "Username is already in use. Please choose another one."
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail , error=error_existing,form = CSRFForm())

            send_verification_mail_code(user_mail)
            return render_template("mail_verify_change_mail.html", user_mail=user_mail, user_username=user_username, user_mail_db=user_mail_db,form = CSRFForm())

        if user_mail != user_mail_db:
            existing_mail = db.execute("SELECT user_mail FROM users WHERE LOWER(user_mail) = ?", user_mail)

            if existing_mail:
                error_existing = "Mail is already in use. Please choose another one. or "
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing,form = CSRFForm())

            send_verification_mail_code(user_mail)
            return render_template("mail_verify_change_mail.html", user_mail=user_mail, user_username=user_username, user_mail_db=user_mail_db,form = CSRFForm())

        if user_username != user_username_db:
            existing_username = db.execute("SELECT user_username FROM users WHERE LOWER(user_username) = ?", user_username)

            if existing_username:
                error_existing = "Username is already in use. Please choose another one. or "
                user_username, user_mail = select_user_data(user_id)
                return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, error=error_existing,form = CSRFForm())

            db.execute("UPDATE users SET user_username = ? WHERE user_id = ?",user_username, user_id)
 
            done = "User Name Changed Successfully!"
            user_username, user_mail = select_user_data(user_id)
            return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, done = done,form = CSRFForm())

    user_username, user_mail = select_user_data(user_id)
    return render_template("personal_info.html", user_username=user_username, user_mail=user_mail,form = CSRFForm())

@settings_bp.route("/settings/personal_info/mail_verification", methods=["POST"])
def mail_verification_change_mail():
    if not session.get("logged_in"):
        return redirect("/login_page")
    
    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error,form = CSRFForm())

    verification_code = request.form.get("verification_code").strip()
    user_mail = request.form.get("user_mail")
    user_username = request.form.get("user_username")
    user_mail_db = request.form.get("user_mail_db")

    if verification_code == session.get("verification_code"):
        db.execute("UPDATE users SET user_mail_verify = ?, user_mail = ?, user_username = ? WHERE user_id = ?", "verified", user_mail, user_username, user_id)

        done = "User Mail Changed Successfully!"
        user_username, user_mail = select_user_data(user_id)
        return render_template("personal_info.html", user_username=user_username, user_mail=user_mail, done = done,form = CSRFForm())
    else:
        error="Invalid verification code."
        return render_template("mail_verify_change_mail.html", error=error,user_username=user_username,form = CSRFForm())


@settings_bp.route("/settings/security_check", methods=["POST", "GET"])
def security_check_password():
    if not session.get("logged_in"):
        return redirect("/login_page")

    try:
        user_id = session.get("user_id")[0]["user_id"]
    except OperationalError:
            error = "Welcome Back"
            return render_template('error.html', error=error,form = CSRFForm())

    if request.method == "GET":
        return render_template("check_pass.html",form = CSRFForm())
    else:

        check_pass = request.form.get("check_pass")
        security = security_check(user_id, check_pass)

        if security:
            return render_template("change_pass.html", user_id = user_id,form = CSRFForm())
        else:
            error = "This password is incorrect!"
            return render_template("check_pass.html", error = error,form = CSRFForm())

@settings_bp.route("/settings/security", methods=["POST"])
def security():
    if not session.get("logged_in"):
        return redirect("/login_page")
    else:

        try:
            user_id = session.get("user_id")[0]["user_id"]
        except OperationalError:
                error = "Welcome Back"
                return render_template('error.html', error=error,form = CSRFForm())
        
        new_password = request.form.get("new_password")

        user_mail = db.execute("SELECT user_mail FROM users WHERE user_id = ?",user_id)

        hashed_password = generate_password_hash(new_password)
        
        db.execute("UPDATE users SET user_password = ? WHERE user_id = ?", hashed_password, user_id)

        success = "You password has been changed successfully!"
        return render_template("home.html", success = success,form = CSRFForm())
