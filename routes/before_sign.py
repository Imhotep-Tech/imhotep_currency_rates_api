from flask import Blueprint, render_template
from config import CSRFForm

before_sign_bp = Blueprint('before_sign', __name__)

@before_sign_bp.route('/before_sign')
def before_sign():        
    return render_template('before_sign.html',form = CSRFForm())