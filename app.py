"""
CST8919 Assignment 1 - Securing and Monitoring an Authenticated Flask App
Auth0 SSO (Lab 1) + structured security logging for Azure Monitor / KQL (Lab 2).
"""

import json
import logging
import sys
from functools import wraps
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# ---------------------------------------------------------------------------
# Reverse-proxy awareness  (CRITICAL for Azure App Service)
# ---------------------------------------------------------------------------
# App Service terminates TLS at its front-end and forwards to the container
# over plain HTTP. Without ProxyFix, url_for(..., _external=True) builds an
# "http://" callback URL, and Auth0 rejects it with "Callback URL mismatch".
# ProxyFix trusts X-Forwarded-Proto / -Host / -For so Flask reconstructs the
# real https:// URL and the real client IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ---------------------------------------------------------------------------
# Session cookie hardening
# ---------------------------------------------------------------------------
# SameSite is "Lax", NOT "Strict", on purpose. The Auth0 callback is a
# cross-site redirect back into our app; "Strict" would withhold the session
# cookie on that request and silently break login.
# SECURE must be False locally (http://localhost) and True on Azure (https).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env.get("COOKIE_SECURE", "false").lower() == "true",
)

# ---------------------------------------------------------------------------
# Logging  (CRITICAL - this is what the whole assignment is graded on)
# ---------------------------------------------------------------------------
# Flask's app.logger inherits the root logger's level, which defaults to
# WARNING. That means app.logger.info() produces NOTHING unless we set the
# level ourselves. We attach an explicit handler writing to STDOUT, because
# Azure App Service (Linux) captures container stdout/stderr into the
# AppServiceConsoleLogs table.
#
# Log shape - one line, fixed space-separated key=value pairs:
#   LOGIN_SUCCESS       user_id=auth0|68a... email=x@y.com ip=1.2.3.4
#   PROTECTED_ACCESS    user_id=auth0|68a... email=x@y.com path=/protected ip=...
#   UNAUTHORIZED_ACCESS user_id=anonymous    email=unknown  path=/protected ip=...
#
# Fixed keys are the whole point: they make the KQL extract() regex stable.
# A free-form message would be painful to parse and would break on any change.
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
app.logger.handlers.clear()
app.logger.addHandler(_handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False

# ---------------------------------------------------------------------------
# Auth0 / OIDC client
# ---------------------------------------------------------------------------
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def client_ip() -> str:
    """Real caller IP. Behind App Service's proxy, remote_addr is the proxy,
    so the true client is the first entry in X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def requires_auth(f):
    """Authorization gate. Logs every rejected attempt BEFORE redirecting,
    so unauthorized access is visible in Log Analytics."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            app.logger.warning(
                "UNAUTHORIZED_ACCESS user_id=anonymous email=unknown path=%s ip=%s",
                request.path, client_ip(),
            )
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    user = session.get("user")
    return render_template(
        "home.html",
        user=user,
        pretty=json.dumps(user, indent=2) if user else None,
    )


@app.route("/health")
def health():
    """Unauthenticated liveness probe - used by test-app.http and Azure warm-up."""
    return {"status": "ok", "service": "cst8919-assignment1"}, 200


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    userinfo = token.get("userinfo", {}) or {}

    # Store ONLY the identity claims we need - never the raw access/ID tokens.
    # The Flask session cookie is SIGNED but NOT ENCRYPTED, so anything placed
    # here is base64-readable by whoever holds the browser.
    session["user"] = {
        "user_id": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
    }

    app.logger.info(
        "LOGIN_SUCCESS user_id=%s email=%s ip=%s",
        session["user"]["user_id"], session["user"]["email"], client_ip(),
    )
    return redirect("/")


@app.route("/protected")
@requires_auth
def protected():
    user = session["user"]
    app.logger.info(
        "PROTECTED_ACCESS user_id=%s email=%s path=%s ip=%s",
        user["user_id"], user["email"], request.path, client_ip(),
    )
    return render_template("protected.html", user=user)


@app.route("/logout")
def logout():
    user = session.get("user") or {}
    app.logger.info(
        "LOGOUT user_id=%s email=%s ip=%s",
        user.get("user_id", "anonymous"), user.get("email", "unknown"), client_ip(),
    )
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN") + "/v2/logout?" + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    # Local development only. Azure App Service runs this through gunicorn.
    # debug=False always - the Werkzeug debugger is remote code execution
    # if it is ever reachable from outside your machine.
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)), debug=False)