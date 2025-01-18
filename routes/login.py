from flask import Blueprint, request, render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from config import Config, CSRFForm
from imhotep_mail import send_mail
import secrets

login_bp = Blueprint('login', __name__)

def logout():
        session.permanent = False
        session["logged_in"] = False
        session.clear()

@login_bp.route("/login", methods=["POST"])
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
                    return render_template("login.html", error_verify=error_verify,form = CSRFForm())
            else:

                print("password_db: ", password_db)
                print("user_password: ",user_password)

                error = "Your username or password are incorrect!"
                return render_template("login.html", error=error,form = CSRFForm())
        except:
            error = "Your E-mail or password are incorrect!"
            return render_template("login.html", error=error,form = CSRFForm())
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
            else:
                error = "Your username or password are incorrect!"
                return render_template("login.html", error=error,form = CSRFForm())
        except:
            error = "Your username or password are incorrect!"
            return render_template("login.html", error=error,form = CSRFForm())
        
@login_bp.route("/forget_password",methods=["POST", "GET"])
def forget_password():
    if request.method == "GET":
        return render_template("forget_password.html",form = CSRFForm())
    else:

        user_mail = request.form.get("user_mail")
        try:
            db.execute("SELECT user_mail FROM users WHERE user_mail = ?", user_mail)

            temp_password = secrets.token_hex(4)

            smtp_server = 'smtp.gmail.com'
            smtp_port = 465
            username = 'imhotepfinance@gmail.com'  # Replace with your Gmail email address
            password =  Config.MAIL_PASSWORD    # Replace with the app password generated from Google account settings

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
            return render_template("login.html", success=success,form = CSRFForm())
        except:
            error = "This Email isn't saved"
            return render_template("forget_password.html", error = error,form = CSRFForm())
        
@login_bp.route("/logout", methods=["GET", "POST"])
def logout_route():
        logout()
        return redirect("/")