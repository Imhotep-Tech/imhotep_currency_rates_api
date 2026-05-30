from flask import Blueprint, render_template, request, jsonify
import requests
from config import CSRFForm
import os
import uuid
from extensions import db, csrf

before_sign_bp = Blueprint('before_sign', __name__)

@before_sign_bp.route('/before_sign')
def before_sign():        
    api_key = os.environ.get("Test_API_URL")
    return render_template('before_sign.html',form = CSRFForm(),api_key=api_key)

@before_sign_bp.route('/api/get_guest_key', methods=['POST'])
@csrf.exempt
def get_guest_key():
    guest_id = uuid.uuid4().hex[:12]
    guest_username = f"guest_{guest_id}"
    guest_mail = f"guest_{guest_id}@imhotep-rates.free"
    api_key = str(uuid.uuid4())
    
    db.execute(
        "INSERT INTO users (user_username, user_password, user_mail, user_mail_verify, api_key) VALUES (?, ?, ?, ?, ?)",
        guest_username,
        "guest_nopass",
        guest_mail,
        "guest",
        api_key
    )
    
    return jsonify({
        "api_key": api_key,
        "username": guest_username
    })

