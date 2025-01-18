from flask import Blueprint, render_template, request
import requests
from config import CSRFForm
import os

before_sign_bp = Blueprint('before_sign', __name__)

@before_sign_bp.route('/before_sign')
def before_sign():        
    api_key = os.environ.get("Test_API_URL")
    return render_template('before_sign.html',form = CSRFForm(),api_key=api_key)
