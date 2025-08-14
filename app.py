# app.py (fixed end-to-end; Yahoo OAuth URL + session flow robust; removed Apple support; updated for MS and template changes)
from flask import Flask, render_template, request, redirect, url_for, session, flash
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
import smtplib
import imaplib
import email as pyemail
import msal
import requests
from requests_oauthlib import OAuth2Session
from werkzeug.middleware.proxy_fix import ProxyFix
from typing import Optional, Any

# ---- Flask app ----
app = Flask(__name__)
app.secret_key = "qumail-secret-123"  # replace for production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---- Scopes & constants ----
GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly"
]
MICROSOFT_SCOPES = ["https://graph.microsoft.com/Mail.Send", "https://graph.microsoft.com/Mail.Read"]
# Yahoo scopes MUST be passed to OAuth2Session or the request is invalid.
# (Keep them as a list; requests-oauthlib formats them correctly.)
YAHOO_SCOPES = ["mail-r", "mail-w"]
MICROSOFT_CLIENT_ID = "aca9b84b-cd69-46f5-93d7-4b027c4d3883"
MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/common"
# Your Yahoo app creds
YAHOO_CLIENT_ID = "dj0yJmk9Q2FEYTNSY1gwVUVWJmQ9WVdrOVUyTnlRbnB1Y1hnbWNHbzlNQT09JnM9Y29uc3VtZXJzZWNyZXQmc3Y9MCZ4PTk1"
YAHOO_CLIENT_SECRET = "152d2cc287f6bf8939081684d2ee1cfc445ad0f7"
YAHOO_AUTH_URL = "https://api.login.yahoo.com/oauth2/request_auth"
YAHOO_TOKEN_URL = "https://api.login.yahoo.com/oauth2/get_token"

# ---- Helpers ----
def get_ngrok_url() -> str:
    """Return https ngrok public URL if available, else localhost fallback."""
    try:
        resp = requests.get('http://localhost:4040/api/tunnels', timeout=2)
        tunnels = resp.json().get('tunnels', [])
        for t in tunnels:
            if t.get('proto') == 'https' and t.get('public_url'):
                logger.debug(f"Ngrok public URL found: {t.get('public_url')}")
                return t.get('public_url')
        raise RuntimeError("no https ngrok tunnel found")
    except Exception as e:
        logger.debug(f"get_ngrok_url() failed: {e}; using fallback http://127.0.0.1:5000")
        return "http://127.0.0.1:5000"

NGROK_URL = get_ngrok_url()
app.config['SESSION_COOKIE_SECURE'] = NGROK_URL.startswith('https')
logger.debug(f"Using NGROK_URL={NGROK_URL}; SESSION_COOKIE_SECURE={app.config['SESSION_COOKIE_SECURE']}")

def _normalize_key(key_obj: Any) -> Optional[str]:
    """Normalize key to string from tuple/bytes/str."""
    if key_obj is None:
        return None
    if isinstance(key_obj, tuple):
        if not key_obj:
            return None
        candidate = key_obj[0]
        if isinstance(candidate, bytes):
            try:
                return candidate.decode('utf-8')
            except Exception:
                return candidate.hex()
        return str(candidate)
    if isinstance(key_obj, bytes):
        try:
            return key_obj.decode('utf-8')
        except Exception:
            return key_obj.hex()
    return str(key_obj)

def decrypt_flex(ciphertext: Any, quantum_key: Any, is_text: bool = True):
    """Try multiple encodings before calling quantum_aes_decrypt."""
    qk = _normalize_key(quantum_key)
    if qk is None:
        raise ValueError("quantum_key is None or invalid")
    last_exc = None
    if isinstance(ciphertext, (bytes, bytearray)):
        try:
            return quantum_aes_decrypt(bytes(ciphertext), qk, is_text=is_text)
        except Exception as e:
            last_exc = e
        try:
            decoded = base64.b64decode(bytes(ciphertext))
            return quantum_aes_decrypt(decoded, qk, is_text=is_text)
        except Exception as e2:
            last_exc = e2
    if isinstance(ciphertext, str):
        s = ciphertext.strip()
        try:
            return quantum_aes_decrypt(s, qk, is_text=is_text)
        except Exception as e_hex:
            last_exc = e_hex
        try:
            s2 = ''.join(s.split())
            return quantum_aes_decrypt(s2, qk, is_text=is_text)
        except Exception as e_hex2:
            last_exc = e_hex2
        try:
            b = base64.b64decode(s)
            return quantum_aes_decrypt(b, qk, is_text=is_text)
        except Exception as e_b64:
            last_exc = e_b64
        try:
            b2 = base64.urlsafe_b64decode(s)
            return quantum_aes_decrypt(b2, qk, is_text=is_text)
        except Exception as e_url:
            last_exc = e_url
    try:
        return quantum_aes_decrypt(ciphertext, qk, is_text=is_text)
    except Exception as e_final:
        logger.error(f"decrypt_flex final failure (last_exc={last_exc}): {e_final}")
        raise e_final

# ---- Routes / Auth flows ----
@app.route("/")
def index():
    logger.debug("Accessing index route")
    logger.debug(f"Session in index: {session}")
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    logger.debug("Accessing login route")
    email_addr = request.form["email"]
    domain = email_addr.split('@')[-1].lower()
    if 'gmail' in domain:
        session['provider'] = 'google'
    elif 'yahoo' in domain:
        session['provider'] = 'yahoo'
    elif 'outlook' in domain or 'hotmail' in domain:
        session['provider'] = 'microsoft'
    else:
        flash("Unsupported email provider")
        return redirect(url_for("index"))
    session['user_email'] = email_addr  # used by SMTP/IMAP flows
    session.modified = True
    logger.debug(f"Session after login: {session}")
    return redirect(url_for("auth_provider", provider=session['provider']))

@app.route("/auth/<provider>")
def auth_provider(provider):
    logger.debug(f"Session in auth_provider: {session}")
    if provider == 'google':
        return auth_google()
    elif provider == 'yahoo':
        return auth_yahoo()
    elif provider == 'microsoft':
        return auth_microsoft()
    return "Invalid provider", 400

# ---- Google ----
def auth_google():
    try:
        redirect_uri = get_ngrok_url() + "/auth/gmail/callback"
        logger.debug(f"Google redirect_uri = {redirect_uri}")
        flow = Flow.from_client_secrets_file(
            "credentials.json",
            scopes=GOOGLE_SCOPES,
            redirect_uri=redirect_uri
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true"
        )
        session.permanent = True
        session["google_state"] = state
        session.modified = True
        logger.debug(f"Redirecting to Google auth: {authorization_url}")
        return redirect(authorization_url)
    except Exception as e:
        logger.exception("Error starting Google auth")
        return f"<h1>Error in Google Auth</h1><pre>{e}</pre>", 500

@app.route("/auth/gmail/callback")
def auth_google_callback():
    try:
        state = session.get("google_state")
        if not state:
            return "No state in session for Google callback", 400
        redirect_uri = get_ngrok_url() + "/auth/gmail/callback"
        flow = Flow.from_client_secrets_file(
            "credentials.json",
            scopes=GOOGLE_SCOPES,
            state=state,
            redirect_uri=redirect_uri
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
        session['provider'] = 'google'
        session.pop("google_state", None)
        session.modified = True
        logger.debug("Google callback stored credentials in session")
        return redirect(url_for("compose"))
    except Exception:
        logger.exception("Error in Google callback")
        return f"<h1>Error in Google Callback</h1><pre>{traceback.format_exc()}</pre>", 500

# ---- Yahoo (fixed) ----
@app.route("/auth/yahoo")
def auth_yahoo():
    try:
        redirect_uri = get_ngrok_url() + "/auth/yahoo/callback"
        logger.debug(f"Yahoo redirect_uri = {redirect_uri}")
        # Use only valid scopes you’ve enabled in Yahoo Developer Console
        oauth = OAuth2Session(
            client_id=YAHOO_CLIENT_ID,
            scope=["mail-r", "mail-w"],  # add "sdpp-w" only if granted in console
            redirect_uri=redirect_uri
        )
        authorization_url, state = oauth.authorization_url(YAHOO_AUTH_URL)
        session.permanent = True
        session["yahoo_state"] = state
        session.modified = True
        logger.debug(f"Redirecting to Yahoo auth: {authorization_url}")
        return redirect(authorization_url)
    except Exception:
        logger.exception("Error starting Yahoo auth")
        return f"<h1>Error in Yahoo Auth</h1><pre>{traceback.format_exc()}</pre>", 500

@app.route("/auth/yahoo/callback")
def auth_yahoo_callback():
    try:
        state = session.get("yahoo_state")
        if not state:
            return "No state in session for Yahoo callback", 400
        redirect_uri = get_ngrok_url() + "/auth/yahoo/callback"
        logger.debug(f"Yahoo callback redirect_uri = {redirect_uri}")
        oauth = OAuth2Session(
            client_id=YAHOO_CLIENT_ID,
            scope=["mail-r", "mail-w"],
            state=state,
            redirect_uri=redirect_uri
        )
        token = oauth.fetch_token(
            token_url=YAHOO_TOKEN_URL,
            client_secret=YAHOO_CLIENT_SECRET,
            authorization_response=request.url,
            include_client_id=True
        )
        session["credentials"] = token
        session['provider'] = 'yahoo'
        # Fetch email from Yahoo’s OpenID Connect userinfo endpoint
        try:
            resp = oauth.get("https://api.login.yahoo.com/openid/v1/userinfo")
            if resp.status_code == 200:
                data = resp.json()
                email = data.get("email")
                if email:
                    session['user_email'] = email
        except Exception:
            logger.warning("Could not fetch Yahoo email")
        session.pop("yahoo_state", None)
        session.modified = True
        logger.debug(f"Yahoo callback stored credentials; session now: {session}")
        return redirect(url_for("compose"))
    except Exception:
        logger.exception("Error in Yahoo callback")
        return f"<h1>Error in Yahoo Callback</h1><pre>{traceback.format_exc()}</pre>", 500

# ---- Microsoft ----
def auth_microsoft():
    try:
        redirect_uri = get_ngrok_url() + "/auth/microsoft/callback"
        logger.debug(f"MS redirect_uri = {redirect_uri}")
        msal_app = msal.PublicClientApplication(MICROSOFT_CLIENT_ID, authority=MICROSOFT_AUTHORITY)
        flow = msal_app.initiate_auth_code_flow(MICROSOFT_SCOPES, redirect_uri=redirect_uri)
        session.permanent = True
        session["ms_flow"] = flow
        session.modified = True
        return redirect(flow["auth_uri"])
    except Exception:
        logger.exception("Error starting Microsoft auth")
        return f"<h1>Error in Microsoft Auth</h1><pre>{traceback.format_exc()}</pre>", 500

@app.route("/auth/microsoft/callback")
def auth_microsoft_callback():
    try:
        flow = session.get("ms_flow")
        if not flow:
            return "No flow in session for Microsoft callback", 400
        msal_app = msal.PublicClientApplication(MICROSOFT_CLIENT_ID, authority=MICROSOFT_AUTHORITY)
        result = msal_app.acquire_token_by_auth_code_flow(flow, request.args)
        if "error" in result:
            return f"Microsoft auth error: {result['error']}", 400
        session["credentials"] = result
        session['provider'] = 'microsoft'
        session.pop("ms_flow", None)
        session.modified = True
        logger.debug("Microsoft callback stored credentials")
        return redirect(url_for("compose"))
    except Exception:
        logger.exception("Error in Microsoft callback")
        return f"<h1>Error in Microsoft Callback</h1><pre>{traceback.format_exc()}</pre>", 500

@app.route("/compose")
def compose():
    if 'provider' not in session:
        return redirect(url_for("index"))
    return render_template("compose.html")

# ---- Sending email ----
@app.route("/send_email", methods=["POST"])
def send_email():
    try:
        recipient = request.form["recipient"]
        subject = request.form["subject"]
        body = request.form["body"]
        attachment = request.files.get("attachment")
        security_level = int(request.form["security"])
        key_id = None
        if security_level in [2, 3]:
            fetched = fetch_quantum_key()
            quantum_key = None
            if isinstance(fetched, tuple):
                if len(fetched) >= 2:
                    quantum_key, key_id = fetched[0], fetched[1]
                elif len(fetched) == 1:
                    quantum_key = fetched[0]
            else:
                quantum_key = fetched
            if isinstance(quantum_key, tuple):
                quantum_key = quantum_key[0] if quantum_key else None
            if isinstance(quantum_key, bytes):
                try:
                    quantum_key = quantum_key.decode('utf-8')
                except Exception:
                    quantum_key = quantum_key.hex()
            if quantum_key is None:
                raise RuntimeError("Failed to obtain quantum key")
            store_key(key_id, quantum_key)
            if security_level == 2:
                body = quantum_aes_encrypt(body, quantum_key).hex()
            elif security_level == 3:
                try:
                    key_bytes = bytes.fromhex(quantum_key)
                except Exception:
                    key_bytes = quantum_key.encode('utf-8')
                key_bytes = key_bytes[:len(body.encode())]
                body = otp_encrypt(body, key_bytes).hex()
        provider = session.get('provider')
        credentials = session.get('credentials')
        if not credentials:
            return redirect(url_for('auth_provider', provider=provider))
        if provider == 'google':
            send_google(recipient, subject, body, attachment, key_id, security_level, credentials)
        elif provider == 'yahoo':
            send_yahoo(recipient, subject, body, attachment, key_id, security_level, credentials)
        elif provider == 'microsoft':
            send_microsoft(recipient, subject, body, attachment, key_id, security_level, credentials)
        return "Email sent successfully!"
    except Exception:
        logger.exception("Error in send_email")
        return f"<h1>Error Sending Email</h1><pre>{traceback.format_exc()}</pre>", 500

def send_google(recipient, subject, body, attachment, key_id, security_level, credentials):
    creds = Credentials(**credentials)
    service = build("gmail", "v1", credentials=creds)
    message = MIMEMultipart()
    message["to"] = recipient
    message["subject"] = subject
    message["X-Quantum-Key-ID"] = key_id if key_id else "None"
    message["X-Security-Level"] = str(security_level)
    message.attach(MIMEText(body))
    if attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={attachment.filename}")
        message.attach(part)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()

def send_yahoo(recipient, subject, body, attachment, key_id, security_level, credentials):
    token = credentials.get('access_token') if isinstance(credentials, dict) else getattr(credentials, 'access_token', None)
    server = smtplib.SMTP("smtp.mail.yahoo.com", 587)
    server.starttls()
    server.ehlo()
    user_email = session.get('user_email')
    if not user_email:
        raise RuntimeError("User email missing from session; please log in again.")
    if token:
        auth_str = f"user={user_email}\1auth=Bearer {token}\1\1"
        try:
            server.docmd('AUTH', 'XOAUTH2 ' + base64.b64encode(auth_str.encode()).decode())
        except Exception as e:
            logger.error(f"XOAUTH2 SMTP auth failed: {e}. Trying password login fallback.")
            if isinstance(credentials, dict) and credentials.get('password'):
                server.login(user_email, credentials.get('password'))
            elif isinstance(credentials, dict) and credentials.get('password'):
                server.login(user_email, credentials.get('password'))
    msg = MIMEMultipart()
    msg['From'] = user_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg['X-Quantum-Key-ID'] = key_id if key_id else "None"
    msg['X-Security-Level'] = str(security_level)
    msg.attach(MIMEText(body))
    if attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={attachment.filename}")
        msg.attach(part)
    try:
        server.sendmail(user_email, recipient, msg.as_string())
    finally:
        try:
            server.quit()
        except Exception:
            pass

def send_microsoft(recipient, subject, body, attachment, key_id, security_level, credentials):
    token = credentials.get('access_token') if isinstance(credentials, dict) else getattr(credentials, 'access_token', None)
    headers = {'Authorization': f"Bearer {token}", 'Content-Type': 'application/json'}
    data = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": recipient}}],
            "internetMessageHeaders": [
                {"name": "X-Quantum-Key-ID", "value": key_id if key_id else "None"},
                {"name": "X-Security-Level", "value": str(security_level)}
            ]
        }
    }
    if attachment:
        data["message"]["attachments"] = [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": attachment.filename,
            "contentType": attachment.mimetype,
            "contentBytes": base64.b64encode(attachment.read()).decode()
        }]
    response = requests.post("https://graph.microsoft.com/v1.0/me/sendMail", headers=headers, json=data)
    if response.status_code != 202:
        raise Exception(f"Microsoft send failed: {response.text}")

# ---- Inbox ----
@app.route("/inbox")
def inbox():
    provider = session.get('provider')
    credentials = session.get('credentials')
    if not credentials:
        return redirect(url_for('auth_provider', provider=provider))
    try:
        emails = []
        if provider == 'google':
            emails = fetch_google_inbox(credentials)
        elif provider == 'yahoo':
            emails = fetch_yahoo_inbox(credentials)
        elif provider == 'microsoft':
            emails = fetch_microsoft_inbox(credentials)
        return render_template("inbox.html", emails=emails)
    except Exception:
        logger.exception("Error fetching inbox")
        return f"<h1>Error Fetching Inbox</h1><pre>{traceback.format_exc()}</pre>", 500

def fetch_google_inbox(credentials):
    creds = Credentials(**credentials)
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", []) or []
    emails = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        payload = msg_data.get('payload', {}) or {}
        headers = payload.get('headers', []) or []
        subject = next((h['value'] for h in headers if h.get('name') == 'Subject'), 'No Subject')
        from_header = next((h['value'] for h in headers if h.get('name') == 'From'), 'Unknown')
        key_id = next((h['value'] for h in headers if h.get('name') == 'X-Quantum-Key-ID'), None)
        body = ''
        attachments = []
        def _extract_parts(part):
            nonlocal body, attachments
            mime = part.get('mimeType', '')
            if mime == 'text/plain':
                body_data = part.get('body', {}).get('data', '')
                if body_data:
                    try:
                        body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                    except Exception:
                        body = base64.urlsafe_b64decode(body_data)
            if mime.startswith('multipart') and part.get('parts'):
                for p in part.get('parts', []):
                    _extract_parts(p)
            if part.get('filename'):
                attach_id = part.get('body', {}).get('attachmentId')
                if attach_id:
                    attach_data = service.users().messages().attachments().get(userId="me", messageId=msg['id'], id=attach_id).execute()
                    attach_content = base64.urlsafe_b64decode(attach_data.get('data', ''))
                    attachments.append({'name': part.get('filename'), 'content': attach_content})
        if 'parts' in payload:
            for part in payload.get('parts', []):
                _extract_parts(part)
        else:
            body_data = payload.get('body', {}).get('data', '')
            if body_data:
                try:
                    body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                except Exception:
                    body = base64.urlsafe_b64decode(body_data)
        if key_id and key_id != 'None':
            raw_key_obj = get_key(key_id)
            logger.debug(f"get_key({key_id}) returned: {repr(raw_key_obj)}")
            quantum_key = _normalize_key(raw_key_obj)
            logger.debug(f"normalized quantum_key preview: {repr(quantum_key)[:80]}")
            if quantum_key:
                try:
                    if body:
                        logger.debug(f"Attempting to decrypt message body id={msg.get('id')}")
                        body = decrypt_flex(body, quantum_key, is_text=True)
                    for attach in attachments:
                        try:
                            attach['content'] = decrypt_flex(attach['content'], quantum_key, is_text=False)
                        except Exception as e_attach:
                            logger.error(f"Attachment decrypt failed for {attach.get('name')}: {e_attach}")
                except Exception as e:
                    logger.error(f"Decryption failed for message {msg.get('id')}: {e}")
                    body = f"[decryption failed] {body}"
        emails.append({"subject": subject, "from": from_header, "body": body, "attachments": attachments})
    return emails

def fetch_yahoo_inbox(credentials):
    logger.debug(f"fetch_yahoo_inbox: credentials keys = {list(credentials.keys()) if isinstance(credentials, dict) else type(credentials)}")
    emails = []
    access_token = None
    password = None
    if isinstance(credentials, dict):
        access_token = credentials.get('access_token') or credentials.get('token')
        password = credentials.get('password')
    user_email = session.get('user_email')
    if not user_email:
        logger.error("fetch_yahoo_inbox: no session user_email found")
        return emails
    imap = None
    try:
        imap_host = "imap.mail.yahoo.com"
        imap_port = 993
        imap = imaplib.IMAP4_SSL(imap_host, imap_port)
        logger.debug("Connected to Yahoo IMAP")
        if access_token:
            auth_string_plain = f"user={user_email}\1auth=Bearer {access_token}\1\1"
            tried = False
            try:
                logger.debug("Trying XOAUTH2 IMAP auth with base64-encoded string")
                b64 = base64.b64encode(auth_string_plain.encode()).decode()
                imap.authenticate('XOAUTH2', lambda x: b64)
                logger.debug("XOAUTH2 IMAP auth succeeded (base64)")
                tried = True
            except Exception as e_base:
                logger.debug(f"XOAUTH2 base64 authenticate failed: {e_base}")
            if not tried:
                try:
                    logger.debug("Trying XOAUTH2 IMAP auth with raw bytes return")
                    imap.authenticate('XOAUTH2', lambda x: auth_string_plain.encode())
                    logger.debug("XOAUTH2 IMAP auth succeeded (raw bytes)")
                    tried = True
                except Exception as e_raw:
                    logger.debug(f"XOAUTH2 raw authenticate failed: {e_raw}")
            if not tried:
                if password:
                    logger.debug("XOAUTH2 failed, falling back to LOGIN with password")
                    imap.login(user_email, password)
                else:
                    raise RuntimeError("XOAUTH2 IMAP auth failed and no password available for fallback")
        else:
            if password:
                imap.login(user_email, password)
            else:
                raise RuntimeError("No access_token or password available for Yahoo IMAP auth")
        imap.select("INBOX")
        typ, data = imap.search(None, "ALL")
        if typ != 'OK':
            logger.error("IMAP search failed")
            imap.logout()
            return emails
        uids = data[0].split()
        last_n = 10
        target_uids = uids[-last_n:] if len(uids) >= last_n else uids
        for uid in reversed(target_uids):
            try:
                typ, msg_data = imap.fetch(uid, '(RFC822)')
                if typ != 'OK' or not msg_data or not msg_data[0]:
                    logger.debug(f"Skipping UID {uid}: fetch returned {typ}")
                    continue
                raw_bytes = msg_data[0][1]
                msg = pyemail.message_from_bytes(raw_bytes)
                subject = msg.get('Subject', 'No Subject')
                from_header = msg.get('From', 'Unknown')
                key_id = msg.get('X-Quantum-Key-ID')
                body = ""
                attachments = []
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        filename = part.get_filename()
                        payload = part.get_payload(decode=True)
                        if filename:
                            attachments.append({"name": filename, "content": payload})
                        elif ctype == 'text/plain' and body == "":
                            if isinstance(payload, (bytes, bytearray)):
                                body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                            elif isinstance(payload, str):
                                body = payload
                else:
                    payload = msg.get_payload(decode=True)
                    if isinstance(payload, (bytes, bytearray)):
                        body = payload.decode(msg.get_content_charset() or 'utf-8', errors='replace')
                    elif isinstance(payload, str):
                        body = payload
                if key_id and key_id != 'None':
                    raw_key = get_key(key_id)
                    qk = _normalize_key(raw_key)
                    if qk:
                        try:
                            if body:
                                body = decrypt_flex(body, qk, is_text=True)
                            for attach in attachments:
                                try:
                                    attach['content'] = decrypt_flex(attach['content'], qk, is_text=False)
                                except Exception as e_attach:
                                    logger.error(f"Attachment decrypt failed for {attach.get('name')}: {e_attach}")
                        except Exception as e_decrypt:
                            logger.error(f"Decryption failed for message UID {uid}: {e_decrypt}")
                            body = f"[decryption failed] {body}"
                emails.append({"subject": subject, "from": from_header, "body": body, "attachments": attachments})
            except Exception as ex_msg:
                logger.error(f"Failed to process UID {uid}: {ex_msg}")
                continue
        try:
            imap.close()
        except Exception:
            pass
        imap.logout()
        return emails
    except Exception:
        logger.exception("fetch_yahoo_inbox error")
        try:
            if imap:
                imap.logout()
        except Exception:
            pass
        return emails

def fetch_microsoft_inbox(credentials):
    return []

# ---- Catch-all ----
@app.route("/<path:path>")
def catch_all(path):
    logger.debug(f"Catch-all route: {path}")
    return f"Unknown route: {path}", 404

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)