import os
import json
import base64
import io
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email import policy
from email.parser import BytesParser
from flask import Flask, url_for, session, redirect, render_template, request, flash, send_file
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from models import db
import key_manager
import crypto_utils

load_dotenv()
app = Flask(__name__, instance_relative_config=True)

# --- Configuration ---
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise ValueError("No SECRET_KEY set for Flask application.")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'qumail.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.instance_path, exist_ok=True)
db.init_app(app)
oauth = OAuth(app)

# --- CLI Command ---
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        key_manager.populate_key_bank_if_empty()
    print("Database has been successfully initialized.")

# --- OAuth Provider Configurations ---
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile https://mail.google.com/'}
)
oauth.register(
    name='microsoft',
    client_id=os.getenv('MICROSOFT_CLIENT_ID'),
    client_secret=os.getenv('MICROSOFT_CLIENT_SECRET'),
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    client_kwargs={'scope': 'User.Read Mail.ReadWrite Mail.Send'}
)
oauth.register(
    name='yahoo',
    client_id=os.getenv('YAHOO_CLIENT_ID'),
    client_secret=os.getenv('YAHOO_CLIENT_SECRET'),
    access_token_url='https://api.login.yahoo.com/oauth2/get_token',
    authorize_url='https://api.login.yahoo.com/oauth2/request_auth',
    api_base_url='https://mail.yahooapis.com/v1/',
    client_kwargs={'scope': 'openid profile email mail-r mail-w'}
)

# --- Helper Functions ---
def find_gmail_body_data(payload):
    """Recursively search for the text/plain body data in a Gmail payload."""
    if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
        return payload['body']['data']
    if 'parts' in payload:
        for part in payload['parts']:
            found_data = find_gmail_body_data(part)
            if found_data:
                return found_data
    return ''

# --- Routes ---
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('inbox'))
    return render_template('login.html')

@app.route('/login/<provider>')
def login(provider):
    base_url = os.getenv('APP_BASE_URL')
    redirect_uri = f"{base_url}/auth/{provider}/callback"
    return oauth.create_client(provider).authorize_redirect(redirect_uri)

@app.route('/auth/<provider>/callback')
def authorize(provider):
    if 'user' in session:
        return redirect(url_for('inbox'))
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = None
    if provider == 'google':
        user_info = client.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token).json()
    elif provider == 'microsoft':
        user_info = client.get('me?$select=displayName,mail,userPrincipalName', token=token).json()
    session['user'] = {'provider': provider, 'info': user_info, 'token': token}
    return redirect(url_for('inbox'))

@app.route('/inbox')
def inbox():
    if 'user' not in session:
        return redirect(url_for('inbox'))
    
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data.get('token')
    if not token:
        return redirect(url_for('logout'))

    messages = []
    try:
        if provider == 'google':
            resp = oauth.google.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20', token=token)
            resp.raise_for_status()
            message_ids = resp.json().get('messages', []) or []
            for msg_summary in message_ids:
                msg_id = msg_summary['id']
                msg_resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full", token=token).json()
                payload = msg_resp.get('payload', {})
                headers = payload.get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                snippet = msg_resp.get('snippet', '')
                message_details = {'id': msg_id, 'subject': subject, 'sender': sender, 'snippet': snippet, 'attachment': None}

                body_data = find_gmail_body_data(payload)
                try:
                    body_text = base64.urlsafe_b64decode(body_data).decode('utf-8')
                    json_payload = json.loads(body_text)
                    if 'key_id' in json_payload: # It's a QuMail message
                        q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                        if q_key_record:
                            decrypted_body = ""
                            level = json_payload['security_level']
                            ciphertext = base64.b64decode(json_payload['ciphertext'])
                            if level == 2:
                                decrypted_body = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(json_payload['nonce']), q_key_record.key_data).decode('utf-8')
                            elif level == 3:
                                decrypted_body = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data).decode('utf-8')
                            
                            message_details['subject'] = subject.replace("[QuMail Encrypted] ", "")
                            message_details['snippet'] = f"🛡️ [DECRYPTED] {decrypted_body[:100]}"
                            if "attachment" in json_payload:
                                message_details['attachment'] = json_payload['attachment']
                except Exception: # Not a QuMail message, check for normal attachment
                    if 'parts' in payload:
                        for part in payload['parts']:
                            if part.get('filename'):
                                message_details['attachment'] = {'filename': part.get('filename')}
                                break
                messages.append(message_details)
        
        elif provider == 'microsoft':
            resp = oauth.microsoft.get('me/mailfolders/inbox/messages?$top=20&$select=id,subject,from,body,hasAttachments', token=token)
            resp.raise_for_status()
            for msg in resp.json().get('value', []):
                snippet = msg.get('body', {}).get('content', '')
                message_details = {'id': msg['id'], 'subject': msg.get('subject', 'No Subject'), 'sender': msg.get('from', {}).get('emailAddress', {}).get('name', 'Unknown Sender'), 'snippet': snippet, 'attachment': None}

                try:
                    json_payload = json.loads(snippet)
                    if 'key_id' in json_payload: # It's a QuMail message
                        q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                        if q_key_record:
                            decrypted_body = ""
                            level = json_payload['security_level']
                            ciphertext = base64.b64decode(json_payload['ciphertext'])
                            if level == 2:
                                decrypted_body = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(json_payload['nonce']), q_key_record.key_data).decode('utf-8')
                            elif level == 3:
                                decrypted_body = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data).decode('utf-8')
                            
                            message_details['subject'] = message_details['subject'].replace("[QuMail Encrypted] ", "")
                            message_details['snippet'] = f"🛡️ [DECRYPTED] {decrypted_body[:100]}"
                            if "attachment" in json_payload:
                                message_details['attachment'] = json_payload['attachment']
                except Exception: # Not a QuMail message, check for normal attachment
                    if msg.get('hasAttachments'):
                        message_details['attachment'] = {'filename': 'attachment'}
                messages.append(message_details)
    except Exception as e:
        print(f"!!! Error fetching emails: {e} !!!")
    return render_template('inbox.html', user=user_data, messages=messages)
    
@app.route('/compose')
def compose():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('compose.html')
    
@app.route('/send_email', methods=['POST'])
def send_email():
    if 'user' not in session:
        return redirect(url_for('index'))

    to_address = request.form.get('to')
    subject = request.form.get('subject')
    body = request.form.get('body')
    security_level = int(request.form.get('security_level'))
    attachment = request.files.get('attachment')
    
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data.get('token')
    sender_email = user_data['info'].get('email') or user_data['info'].get('mail') or user_data['info'].get('userPrincipalName')

    try:
        if security_level == 1:
            if provider == 'google':
                message = MIMEMultipart()
                message['to'], message['from'], message['subject'] = to_address, sender_email, subject
                message.attach(MIMEText(body, 'plain'))
                if attachment and attachment.filename:
                    part = MIMEApplication(attachment.read(), Name=attachment.filename)
                    part['Content-Disposition'] = f'attachment; filename="{attachment.filename}"'
                    message.attach(part)
                payload = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
                oauth.google.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', json=payload, token=token)
            elif provider == 'microsoft':
                payload = {'message': {'subject': subject, 'body': {'contentType': 'Text', 'content': body}, 'toRecipients': [{'emailAddress': {'address': to_address}}], 'attachments': []}, 'saveToSentItems': 'true'}
                if attachment and attachment.filename:
                    payload['message']['attachments'].append({
                        '@odata.type': '#microsoft.graph.fileAttachment', 'name': attachment.filename, 'contentBytes': base64.b64encode(attachment.read()).decode('utf-8')})
                oauth.microsoft.post('https://graph.microsoft.com/v1.0/me/sendMail', json=payload, token=token)
            flash("Email sent successfully!", "success")
        else: # LEVEL 2 & 3
            q_key_record = key_manager.get_unused_key()
            if not q_key_record:
                flash("Failed to send: No quantum keys available.", "error")
                return redirect(url_for('compose'))
            
            quantum_key = q_key_record.key_data
            encrypted_payload = {"key_id": q_key_record.id, "security_level": security_level}
            
            if security_level == 2:
                body_ciphertext, body_nonce = crypto_utils.encrypt_aes(body.encode('utf-8'), quantum_key)
                encrypted_payload["ciphertext"] = base64.b64encode(body_ciphertext).decode('utf-8')
                encrypted_payload["nonce"] = base64.b64encode(body_nonce).decode('utf-8')
                if attachment and attachment.filename:
                    att_ciphertext, att_nonce = crypto_utils.encrypt_aes(attachment.read(), quantum_key)
                    encrypted_payload["attachment"] = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8')}
            
            elif security_level == 3:
                body_ciphertext, body_nonce, enc_session_key = crypto_utils.encrypt_hybrid_otp(body.encode('utf-8'), quantum_key)
                encrypted_payload["nonce"] = base64.b64encode(body_nonce).decode('utf-8')
                encrypted_payload["ciphertext"] = base64.b64encode(body_ciphertext).decode('utf-8')
                encrypted_payload["session_key"] = base64.b64encode(enc_session_key).decode('utf-8')
                if attachment and attachment.filename:
                    att_ciphertext, att_nonce, att_enc_session_key = crypto_utils.encrypt_hybrid_otp(attachment.read(), quantum_key)
                    encrypted_payload["attachment"] = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8'), "session_key": base64.b64encode(att_enc_session_key).decode('utf-8')}
            
            final_body = json.dumps(encrypted_payload)
            final_subject = f"[QuMail Encrypted] {subject}"
            
            if provider == 'google':
                message = EmailMessage()
                message.set_content(final_body)
                message['To'], message['From'], message['Subject'] = to_address, sender_email, final_subject
                payload = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
                oauth.google.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', json=payload, token=token)
            elif provider == 'microsoft':
                payload = {'message': {'subject': final_subject, 'body': {'contentType': 'Text', 'content': final_body}, 'toRecipients': [{'emailAddress': {'address': to_address}}]}, 'saveToSentItems': 'true'}
                oauth.microsoft.post('https://graph.microsoft.com/v1.0/me/sendMail', json=payload, token=token)
            
            key_manager.mark_key_as_used(q_key_record)
            flash(f"Level {security_level} encrypted email sent successfully!", "success")
            
    except ValueError as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('compose'))
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "error")
    return redirect(url_for('inbox'))

@app.route('/download_attachment/<provider>/<message_id>')
def download_attachment(provider, message_id):
    if 'user' not in session: return redirect(url_for('index'))
    token = session['user']['token']
    try:
        body_text, is_encrypted = '', False
        if provider == 'google':
            msg_resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()
            raw_email_data = base64.urlsafe_b64decode(msg_resp['raw'])
            parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email_data)
            body_part = parsed_email.get_body(preferencelist=('plain',))
            body_text = body_part.get_content()
            try:
                json.loads(body_text)
                is_encrypted = True
            except: is_encrypted = False

            if is_encrypted:
                payload = json.loads(body_text)
                q_key_record = key_manager.get_key_by_id(payload['key_id'])
                attachment_data = payload['attachment']
                ciphertext = base64.b64decode(attachment_data['ciphertext'])
                decrypted_bytes = None
                if payload['security_level'] == 2:
                    decrypted_bytes = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(attachment_data['nonce']), q_key_record.key_data)
                elif payload['security_level'] == 3:
                    decrypted_bytes = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(attachment_data['nonce']), base64.b64decode(attachment_data['session_key']), q_key_record.key_data)
                return send_file(io.BytesIO(decrypted_bytes), download_name=attachment_data['filename'], as_attachment=True)
            else:
                for part in parsed_email.iter_attachments():
                    return send_file(io.BytesIO(part.get_payload(decode=True)), download_name=part.get_filename(), as_attachment=True)

        elif provider == 'microsoft':
            msg_resp = oauth.microsoft.get(f"me/messages/{message_id}?$select=body", token=token).json()
            body_text = msg_resp.get('body', {}).get('content', '')
            try:
                payload = json.loads(body_text)
                is_encrypted = 'key_id' in payload
            except: is_encrypted = False

            if is_encrypted:
                q_key_record = key_manager.get_key_by_id(payload['key_id'])
                attachment_data = payload['attachment']
                ciphertext = base64.b64decode(attachment_data['ciphertext'])
                decrypted_bytes = None
                if payload['security_level'] == 2:
                    decrypted_bytes = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(attachment_data['nonce']), q_key_record.key_data)
                elif payload['security_level'] == 3:
                    decrypted_bytes = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(attachment_data['nonce']), base64.b64decode(attachment_data['session_key']), q_key_record.key_data)
                return send_file(io.BytesIO(decrypted_bytes), download_name=attachment_data['filename'], as_attachment=True)
            else:
                att_resp = oauth.microsoft.get(f"me/messages/{message_id}/attachments", token=token).json()
                if att_resp.get('value'):
                    att_id = att_resp['value'][0]['id']
                    attachment = oauth.microsoft.get(f"me/messages/{message_id}/attachments/{att_id}", token=token).json()
                    file_bytes = base64.b64decode(attachment['contentBytes'])
                    return send_file(io.BytesIO(file_bytes), download_name=attachment['name'], as_attachment=True)

    except Exception as e:
        print(f"Error downloading attachment: {e}")
        return "Failed to download attachment.", 500
    return "Attachment not found.", 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)