from flask import Flask, session, redirect, render_template, make_response
from datetime import datetime, timedelta
from config import Config, CSRFForm
from extensions import init_extensions
from routes.api import api_bp
from routes.error_handlers import errors_bp
from routes.google_auth import google_auth_bp
from routes.login import login_bp
from routes.register import register_bp
from routes.settings import settings_bp
from routes.user import user_bp
from routes.before_sign import before_sign_bp
from flask_talisman import Talisman

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    init_extensions(app)

    # Register blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(google_auth_bp)
    app.register_blueprint(login_bp)
    app.register_blueprint(register_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(before_sign_bp)

    return app

app = create_app()

# Define your CSP policy
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://cdn.tailwindcss.com",
        "https://unpkg.com",
        "'unsafe-inline'",
        "'unsafe-eval'",
    ],
    'style-src': [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://cdn.tailwindcss.com",
        "https://fonts.googleapis.com",
        "'unsafe-inline'",
    ],
    'font-src': [
        "'self'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.gstatic.com",
        "data:",
    ],
    'img-src': [
        "'self'",
        "data:",
    ],
    'connect-src': [
        "'self'",
    ],
}

# Initialize Talisman with the CSP configuration
talisman = Talisman(app, content_security_policy=csp)

@app.after_request
def add_header(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# Remove previous CSP stripping to allow CSP to be sent with Tailwind whitelisted

@app.after_request
def set_content_type_options(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route("/", methods=["GET"])
def index():
    if session.get("logged_in"):
        return redirect("/home")
    else:
        return redirect("/before_sign")

@app.route("/version")
def version():
    return render_template("version.html",form=CSRFForm())

@app.route("/terms")
def terms():
    return render_template("terms.html",form=CSRFForm())

@app.route("/privacy")
def privacy():
    return render_template("privacy.html",form=CSRFForm())

@app.route('/sitemap.xml')
def sitemap():
    pages = []

    ten_days_ago = (datetime.now() - timedelta(days=10)).date().isoformat()
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            pages.append(
                ["https://imhotepexchangeratesapi.pythonanywhere.com/" + str(rule.rule), ten_days_ago]
            )

    sitemap_xml = render_template('sitemap.xml', pages=pages)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"

    return response

if __name__ == "__main__":
    app.run(debug=True)