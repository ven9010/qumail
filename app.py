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

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Replace with a random string (e.g., "qumail-secret-123")

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    return redirect(url_for("compose"))

@app.route("/auth/gmail")
def auth_gmail():
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
    return redirect(authorization_url)

@app.route("/auth/gmail/callback")
def auth_gmail_callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        state=state,
        redirect_uri="http://localhost:5000/auth/gmail/callback"
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }
    return redirect(url_for("compose"))

@app.route("/compose")
def compose():
    return render_template("compose.html")

@app.route("/send_email", methods=["POST"])
def send_email():
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

    # Prepare email
    message = MIMEText(body)
    message["to"] = recipient
    message["subject"] = subject
    message["X-Quantum-Key-ID"] = key_id if key_id else "None"
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    # Send email via Gmail API
    credentials = session.get("credentials")
    if not credentials:
        return redirect(url_for("auth_gmail"))
    creds = Credentials(**credentials)
    service = build("gmail", "v1", credentials=creds)
    service.users().messages().send(userId="me", body={"raw": raw}).execute()

    return f"Email sent: {body} (Security Level {security_level}, Key ID: {key_id})"

@app.route("/inbox")
def inbox():
    return render_template("inbox.html")

if __name__ == "__main__":
    app.run(debug=True)