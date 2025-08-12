from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from encryption import quantum_aes_encrypt, otp_encrypt, quantum_aes_decrypt, otp_decrypt
from key_manager import fetch_quantum_key
from database import store_key, get_key
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64
import os
import traceback
import logging
import uuid

app = Flask(__name__)
app.secret_key = "qumail-secret-123"  # Fixed secret key

# Session cookie settings for local testing (remove or adjust in production)
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS for localhost
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Optional: For consistent URL generation
app.config['SERVER_NAME'] = '127.0.0.1:5000'

# Allow insecure transport for local HTTP testing (remove in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/gmail.readonly"]  # Add readonly for IMAP

# Temporary directory for decrypted attachments
ATTACHMENT_DIR = 'static/attachments'
os.makedirs(ATTACHMENT_DIR, exist_ok=True)

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
            redirect_uri="http://127.0.0.1:5000/auth/gmail/callback"
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true"
        )
        session.permanent = True  # Make session permanent
        session["state"] = state
        session.modified = True  # Force session update
        logger.debug(f"Generated authorization_url: {authorization_url}")
        logger.debug(f"Stored state in session: {state}")
        logger.debug(f"Session keys after storing state: {session.keys()}")
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
        logger.debug(f"Session keys after storing state: {session.keys()}")
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
            redirect_uri="http://127.0.0.1:5000/auth/gmail/callback"
        )
        logger.debug("Fetching token...")
        flow.fetch_token(authorization_response=request.url)
        logger.debug("Token fetched successfully")
        credentials = flow.credentials
        logger.debug(f"Credentials obtained: {credentials.token[:10]}... (token snippet)")
        session.permanent = True  # Make session permanent
        session["credentials"] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }
        session.modified = True  # Force session update
        logger.debug("Credentials saved to session")
        logger.debug(f"Session keys after saving credentials: {session.keys()}")
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
        quantum_key = None
        attachment_data = b''
        attachment_filename = ''
        if attachment:
            attachment_data = attachment.read()
            attachment_filename = attachment.filename
        body_bytes = body.encode('utf-8')
        if security_level in [2, 3]:
            key_id = uuid.uuid4().hex  # Always generate unique key_id locally
            quantum_key, _ = fetch_quantum_key()  # Fetch one key for both AES and OTP
            store_key(key_id, quantum_key)
            logger.debug(f"Using key_id: {key_id}, quantum_key snippet: {quantum_key[:50]}...")
            # Encrypt body
            if security_level == 2:
                encrypted_body = quantum_aes_encrypt(body_bytes, quantum_key)
                body = encrypted_body.hex()
            elif security_level == 3:
                encrypted_body = otp_encrypt(body_bytes, quantum_key)
                body = encrypted_body.hex()
            # Encrypt attachment if needed
            if attachment:
                if security_level == 2:
                    attachment_data = quantum_aes_encrypt(attachment_data, quantum_key)
                elif security_level == 3:
                    attachment_data = otp_encrypt(attachment_data, quantum_key)
        # Prepare email with multipart for attachment
        message = MIMEMultipart()
        message["to"] = recipient
        message["subject"] = subject
        message["X-Quantum-Key-ID"] = key_id if key_id else "None"
        message["X-Security-Level"] = str(security_level)
        message.attach(MIMEText(body, "plain"))
        # Handle attachment
        if attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment_data)
            encoders.encode_base64(part)
            # Keep original filename for email, but we'll strip .enc in inbox if added
            part.add_header("Content-Disposition", f"attachment; filename={attachment_filename}")
            message.attach(part)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        credentials = session.get("credentials")
        if not credentials:
            logger.debug("No credentials in session, redirecting to auth_gmail")
            return redirect(url_for("auth_gmail"))
        creds = Credentials(**credentials)
        service = build("gmail", "v1", credentials=creds)
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        logger.debug("Email sent successfully")
        return "Email sent successfully!"
    except Exception as e:
        error_msg = f"Error in send_email: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        return f"<h1>Error in Sending Email</h1><pre>{error_msg}</pre>", 500

@app.route("/inbox")
def inbox():
    logger.debug("Accessing inbox route")
    credentials = session.get("credentials")
    if not credentials:
        return redirect(url_for("auth_gmail"))
    creds = Credentials(**credentials)
    service = build("gmail", "v1", credentials=creds)
    # Fetch 10 recent messages
    results = service.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])
    emails = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        headers = msg_data["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        from_email = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
        date = next((h["value"] for h in headers if h["name"] == "Date"), "Unknown")
        key_id = next((h["value"] for h in headers if h["name"] == "X-Quantum-Key-ID"), None)
        security_level = next((h["value"] for h in headers if h["name"] == "X-Security-Level"), None)
        body = ""
        attachments = []
        # Extract body and attachments
        payload = msg_data["payload"]
        if "parts" in payload:
            for part in payload["parts"]:
                if part["mimeType"] == "text/plain" and "data" in part["body"]:
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                elif "filename" in part and part["body"].get("size", 0) > 0:
                    if "data" in part["body"]:
                        attachment_data = base64.urlsafe_b64decode(part["body"]["data"])
                    else:
                        # Fetch attachment if attachmentId is present (for larger attachments)
                        attach_response = service.users().messages().attachments().get(
                            userId="me",
                            messageId=msg["id"],
                            id=part["body"]["attachmentId"]
                        ).execute()
                        attachment_data = base64.urlsafe_b64decode(attach_response["data"])
                    attachments.append({
                        "filename": part["filename"],
                        "data": attachment_data
                    })
        elif "data" in payload["body"]:
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
        # Decrypt body if key_id exists and security_level is 2 or 3
        if key_id and security_level in ['2', '3']:
            key_data = get_key(key_id)
            if key_data:
                quantum_key = key_data[0]
                logger.debug(f"Decrypting body with key_id: {key_id}, quantum_key snippet: {quantum_key[:50]}...")
                try:
                    body_bytes = bytes.fromhex(body)
                    if security_level == '2':
                        decrypted_bytes = quantum_aes_decrypt(body_bytes, quantum_key)
                    elif security_level == '3':
                        decrypted_bytes = otp_decrypt(body_bytes, quantum_key)
                    body = decrypted_bytes.decode('utf-8')
                except ValueError as ve:
                    logger.error(f"ValueError in body decryption: {str(ve)}")
                    body = f"Decryption failed (ValueError): {str(ve)}. Possibly incorrect key or data format."
                except Exception as e:
                    logger.error(f"Unexpected error in body decryption: {str(e)}")
                    body = f"Decryption failed: {str(e)}. Check logs for details."
        # Decrypt attachments if key_id exists and security_level is 2 or 3
        for attach in attachments:
            # Strip .enc from filename if present
            original_filename = attach["filename"].rstrip('.enc') if attach["filename"].endswith('.enc') else attach["filename"]
            attach["filename"] = original_filename
            if key_id and security_level in ['2', '3']:
                key_data = get_key(key_id)
                if key_data:
                    quantum_key = key_data[0]
                    logger.debug(f"Decrypting attachment {attach['filename']} with key_id: {key_id}")
                    try:
                        if security_level == '2':
                            attach["data"] = quantum_aes_decrypt(attach["data"], quantum_key)
                        elif security_level == '3':
                            attach["data"] = otp_decrypt(attach["data"], quantum_key)
                    except ValueError as ve:
                        logger.error(f"ValueError in attachment decryption {attach['filename']}: {str(ve)}")
                        attach["data"] = b"Decryption failed (ValueError): " + str(ve).encode()
                    except Exception as e:
                        logger.error(f"Unexpected error in attachment decryption {attach['filename']}: {str(e)}")
                        attach["data"] = b"Decryption failed: " + str(e).encode()
            # Save decrypted attachment to disk for serving
            attach_id = str(uuid.uuid4())
            safe_filename = attach_id + '_' + attach["filename"].replace('/', '_').replace('\\', '_')
            file_path = os.path.join(ATTACHMENT_DIR, safe_filename)
            with open(file_path, 'wb') as f:
                f.write(attach["data"])
            attach["url"] = url_for('download_attachment', filename=safe_filename)
            del attach["data"]  # Remove data to save memory
        emails.append({
            "subject": subject,
            "from": from_email,
            "date": date,
            "body": body,
            "attachments": attachments
        })
    return render_template("inbox.html", emails=emails)

@app.route("/attachments/<filename>")
def download_attachment(filename):
    return send_from_directory(ATTACHMENT_DIR, filename)

@app.route("/<path:path>")
def catch_all(path):
    logger.debug(f"Catch-all route triggered for path: {path}")
    return f"Unknown route: {path}", 404

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)