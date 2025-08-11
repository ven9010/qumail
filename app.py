from flask import Flask, render_template, request, redirect, url_for, session
from encryption import quantum_aes_encrypt, otp_encrypt
from key_manager import fetch_quantum_key
from database import store_key, get_key
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText
import base64
import os
import traceback
import logging

app = Flask(__name__)
app.secret_key = "qumail-secret-123"  # Fixed secret key

# Allow insecure transport for local HTTP testing (remove in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

@app.route("/")
def index():
    logger.debug("Accessing index route")
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    logger.debug("Accessing login route")
    return redirect(url_for("compose"))

@app.route("/auth/gmail")
def auth_gmail():
    try:
        logger.debug("Starting auth_gmail route")
        flow = Flow.from_client_secrets_file(
            "credentials.json",
            scopes=SCOPES,
            redirect_uri="http://localhost:5000/auth/gmail/callback"
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true"
        )
        session["state"] = state
        logger.debug(f"Generated authorization_url: {authorization_url}")
        logger.debug(f"Stored state in session: {state}")
        return redirect(authorization_url)
    except Exception as e:
        error_msg = f"Error in auth_gmail: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        return f"<h1>Error in Authorization</h1><pre>{error_msg}</pre>", 500

@app.route("/auth/gmail/callback")
def auth_gmail_callback():
    try:
        logger.debug("Starting auth_gmail_callback route")
        logger.debug(f"Full request URL: {request.url}")
        logger.debug(f"Query params: {request.args}")
        state = session.get("state")
        logger.debug(f"Retrieved session state: {state}")
        if not state:
            error_msg = "Error: No state in session"
            logger.error(error_msg)
            return f"<h1>Error</h1><pre>{error_msg}</pre>", 400
        logger.debug("Creating Flow instance...")
        flow = Flow.from_client_secrets_file(
            "credentials.json",
            scopes=SCOPES,
            state=state,
            redirect_uri="http://localhost:5000/auth/gmail/callback"
        )
        logger.debug("Fetching token...")
        flow.fetch_token(authorization_response=request.url)
        logger.debug("Token fetched successfully")
        credentials = flow.credentials
        logger.debug(f"Credentials obtained: {credentials.token[:10]}... (token snippet)")
        session["credentials"] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }
        logger.debug("Credentials saved to session")
        return redirect(url_for("compose"))
    except Exception as e:
        error_msg = f"Error in auth_gmail_callback: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        return f"<h1>Error in Callback</h1><pre>{error_msg}</pre>", 500

@app.route("/compose")
def compose():
    logger.debug("Reached compose route")
    return render_template("compose.html")

@app.route("/send_email", methods=["POST"])
def send_email():
    try:
        logger.debug("Starting send_email route")
        recipient = request.form["recipient"]
        subject = request.form["subject"]
        body = request.form["body"]
        attachment = request.files.get("attachment")
        security_level = int(request.form["security"])
        key_id = None
        if security_level in [2, 3]:
            quantum_key, key_id = fetch_quantum_key()
            store_key(key_id, quantum_key)
        if security_level == 2:
            body = quantum_aes_encrypt(body, quantum_key).hex()
        else:
            key_bytes = bytes.fromhex(quantum_key)[:len(body)]
            body = otp_encrypt(body, key_bytes).hex()
        logger.debug(f"Prepared email: {body} (Security Level {security_level}, Key ID: {key_id})")
        message = MIMEText(body)
        message["to"] = recipient
        message["subject"] = subject
        message["X-Quantum-Key-ID"] = key_id if key_id else "None"
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        credentials = session.get("credentials")
        if not credentials:
            logger.debug("No credentials in session, redirecting to auth_gmail")
            return redirect(url_for("auth_gmail"))
        creds = Credentials(**credentials)
        service = build("gmail", "v1", credentials=creds)
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        logger.debug("Email sent successfully")
        return f"Email sent: {body} (Security Level {security_level}, Key ID: {key_id})"
    except Exception as e:
        error_msg = f"Error in send_email: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        return f"<h1>Error in Sending Email</h1><pre>{error_msg}</pre>", 500

@app.route("/inbox")
def inbox():
    logger.debug("Accessing inbox route")
    return render_template("inbox.html")

@app.route("/<path:path>")
def catch_all(path):
    logger.debug(f"Catch-all route triggered for path: {path}")
    return f"Unknown route: {path}", 404

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)