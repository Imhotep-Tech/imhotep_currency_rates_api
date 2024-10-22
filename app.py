from flask import render_template, redirect, Flask, session, request, make_response, url_for
from imhotep_mail import send_mail
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from sqlalchemy import text
import requests
from datetime import date, timedelta
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

#define the app
app = Flask(__name__)