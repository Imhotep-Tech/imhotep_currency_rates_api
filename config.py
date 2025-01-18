import os
from datetime import timedelta
from flask_wtf import FlaskForm

class Config:
    SECRET_KEY = os.getenv('secret_key')
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)
    SESSION_COOKIE_SECURE = True
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'myapp_session:'
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TYPE = 'filesystem'
    DATABASE_URL = os.getenv("DATABASE_URL")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    CURRENCY_API_URL = os.getenv("CURRENCY_API_URL")

class CSRFForm(FlaskForm):
    pass