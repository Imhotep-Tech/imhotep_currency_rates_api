from flask import Blueprint, request, render_template, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from config import Config, CSRFForm
from imhotep_mail import send_mail
import secrets

login_bp = Blueprint('login', __name__)

def logout():
    """Clear the session and log the user out."""
    session.permanent = False
    session["logged_in"] = False
    session.clear()

@login_bp.route("/login", methods=["POST", "GET"])
def login():
    """Handle user login."""
    if request.method == "GET":
        return render_template("login.html", form=CSRFForm())

    # Get form data
    user_username_mail = (request.form.get("user_username_mail").strip()).lower()
    user_password = request.form.get("user_password")

    # Determine if the input is an email or username
    is_email = "@" in user_username_mail

    try:
        # Query the database based on email or username
        if is_email:
            login_db = db.execute(
                "SELECT user_password, user_mail_verify FROM users WHERE LOWER(user_mail) = ?",
                user_username_mail
            )
        else:
            login_db = db.execute(
                "SELECT user_password, user_mail_verify FROM users WHERE LOWER(user_username) = ?",
                user_username_mail
            )

        if not login_db:
            raise ValueError("User not found")

        password_db = login_db[0]["user_password"]
        user_mail_verify = login_db[0]["user_mail_verify"]

        # Check if the password is correct
        if not check_password_hash(password_db, user_password):
            raise ValueError("Incorrect password")

        # Check if the email is verified
        if user_mail_verify != "verified":
            error_verify = "Your email isn't verified"
            return render_template("login.html", error_verify=error_verify, form=CSRFForm())

        # Fetch the user ID
        if is_email:
            user = db.execute(
                "SELECT user_id FROM users WHERE LOWER(user_mail) = ? AND user_password = ?",
                user_username_mail, password_db
            )
        else:
            user = db.execute(
                "SELECT user_id FROM users WHERE LOWER(user_username) = ? AND user_password = ?",
                user_username_mail, password_db
            )

        # Set session variables
        session["logged_in"] = True
        session["user_id"] = user[0]["user_id"]
        session.permanent = True

        # Redirect to the home page
        return redirect("/home")

    except ValueError as e:
        # Handle specific errors
        error = str(e)
        return render_template("login.html", error=error, form=CSRFForm())

    except Exception as e:
        # Handle unexpected errors
        print(f"Unexpected error: {e}")
        error = "An unexpected error occurred. Please try again later."
        return render_template("login.html", error=error, form=CSRFForm())

@login_bp.route("/forget_password", methods=["POST", "GET"])
def forget_password():
    """Handle password reset requests."""
    if request.method == "GET":
        return render_template("forget_password.html", form=CSRFForm())

    user_mail = request.form.get("user_mail")
    try:
        # Check if the email exists in the database
        db.execute("SELECT user_mail FROM users WHERE user_mail = ?", user_mail)

        # Generate a temporary password
        temp_password = secrets.token_hex(4)
        hashed_password = generate_password_hash(temp_password)

        # Update the user's password in the database
        db.execute("UPDATE users SET user_password = ? WHERE user_mail = ?", hashed_password, user_mail)

        # Send the temporary password via email
        smtp_server = 'smtp.gmail.com'
        smtp_port = 465
        username = 'imhotepfinance@gmail.com'  # Replace with your Gmail email address
        password = Config.MAIL_PASSWORD  # Replace with the app password generated from Google account settings

        to_email = user_mail
        subject = 'Reset Password'
        body = f'Your temporary Password is: {temp_password}'
        is_html = False

        success, error = send_mail(smtp_server, smtp_port, username, password, to_email, subject, body, is_html)
        if error:
            print("Error on sending the code:", error)
            raise Exception("Failed to send email")

        # Notify the user that the email has been sent
        success = "The email has been sent. Check your inbox for your new password."
        return render_template("login.html", success=success, form=CSRFForm())

    except Exception as e:
        # Handle errors
        print(f"Error in forget_password: {e}")
        error = "This email isn't registered."
        return render_template("forget_password.html", error=error, form=CSRFForm())

@login_bp.route("/logout", methods=["GET", "POST"])
def logout_route():
    """Handle user logout."""
    logout()
    return redirect("/")