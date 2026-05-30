from flask import Blueprint, render_template, redirect, session
from extensions import db
import uuid
from sqlalchemy.exc import OperationalError
from config import CSRFForm

user_bp = Blueprint('user', __name__)

@user_bp.route('/home')
def home():
    if not session.get("logged_in"):
        return redirect("/")
    
    try:
        user_id = session.get("user_id")
        if isinstance(user_id, list):
            user_id = user_id[0]["user_id"]
        print("user_id = ",user_id)
    except (OperationalError, TypeError, KeyError):
        error = "Welcome Back"
        return render_template('error.html', error=error,form = CSRFForm())
    
    api_key_db = db.execute("SELECT api_key, user_username FROM users WHERE user_id = ?", user_id)
    
    if api_key_db:
        api_key = api_key_db[0]["api_key"]
        user_username = api_key_db[0]["user_username"]
    else:
        api_key = str(uuid.uuid4())
        user_username = " "
    return render_template('home.html', api_key=api_key, user_username=user_username,form = CSRFForm())