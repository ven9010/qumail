import os
import json
import base64
import io
from datetime import datetime, timezone
import pytz
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email import policy
from email.parser import BytesParser
from flask import Flask, url_for, session, redirect, render_template, request, flash, send_file, jsonify
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
    if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
        return payload['body']['data']
    if 'parts' in payload:
        for part in payload['parts']:
            found_data = find_gmail_body_data(part)
            if found_data:
                return found_data
    return ''

def get_email_body(msg_raw):
    parsed_email = BytesParser(policy=policy.default).parsebytes(msg_raw)
    html_part = parsed_email.get_body(preferencelist=('html',))
    if html_part:
        return html_part.get_content()
    plain_part = parsed_email.get_body(preferencelist=('plain',))
    if plain_part:
        return plain_part.get_content().replace('\n', '<br>')
    return "Email body could not be retrieved."

# --- Routes ---
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('inbox'))
    return render_template('login.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

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
        ms_user_info = client.get('me?$select=displayName,mail,userPrincipalName', token=token).json()
        user_info = { 'name': ms_user_info.get('displayName'), 'email': ms_user_info.get('mail') or ms_user_info.get('userPrincipalName'), **ms_user_info }
    session['user'] = {'provider': provider, 'info': user_info, 'token': token}
    return redirect(url_for('inbox'))

@app.route('/mail/<folder>')
@app.route('/inbox')
def inbox(folder='inbox'):
    if 'user' not in session: return redirect(url_for('index'))
    
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data.get('token')
    sender_email = user_data['info'].get('email') or user_data['info'].get('userPrincipalName')
    if not token: return redirect(url_for('logout'))

    messages = []
    try:
        if provider == 'google':
            query_map = {'inbox': "in:inbox -in:draft", 'sent': "in:sent", 'spam': "in:spam"}
            query = query_map.get(folder, "in:inbox")
            resp = oauth.google.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&q={query}', token=token)
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
                internal_date = msg_resp.get('internalDate')
                date_str = None
                if internal_date:
                    dt = datetime.fromtimestamp(int(internal_date) / 1000, tz=timezone.utc).astimezone(pytz.timezone('Asia/Kolkata'))
                    date_str = dt.strftime('%Y-%m-%d %H:%M')
                message_details = {'id': msg_id, 'subject': subject, 'sender': sender, 'snippet': snippet, 'attachment': None, 'date': date_str}

                body_data = find_gmail_body_data(payload)
                try:
                    body_text = base64.urlsafe_b64decode(body_data).decode('utf-8')
                    json_payload = json.loads(body_text)
                    if 'key_id' in json_payload:
                        q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                        if q_key_record:
                            decrypted_body = ""
                            level = json_payload['security_level']
                            ciphertext = base64.b64decode(json_payload['ciphertext'])
                            if level == 2:
                                decrypted_body = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(json_payload['nonce']), q_key_record.key_data).decode('utf-8')
                            elif level == 3:
                                decrypted_body = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data).decode('utf-8')
                            message_details.update({'subject': subject.replace("[QuMail Encrypted] ", ""), 'snippet': f"🛡️ [DECRYPTED] {decrypted_body[:100]}", 'attachment': json_payload.get("attachment")})
                except Exception:
                    if 'parts' in payload:
                        for part in payload['parts']:
                            if part.get('filename'):
                                message_details['attachment'] = {'filename': part.get('filename')}
                                break
                messages.append(message_details)
        
        elif provider == 'microsoft':
            folder_map = {'inbox': 'inbox', 'sent': 'sentitems', 'spam': 'junkemail'}
            folder_id = folder_map.get(folder, 'inbox')
            filter_query = ""  # Removed the filter to show all emails, including self-sent
            
            # --- BUG FIX: Request BOTH bodyPreview (for snippet) AND body (for decryption) ---
            select_fields = "id,subject,from,bodyPreview,body,hasAttachments,receivedDateTime,sentDateTime"
            api_url = f'me/mailfolders/{folder_id}/messages?$top=20&$select={select_fields}{filter_query}'
            resp = oauth.microsoft.get(api_url, token=token)
            resp.raise_for_status()
            
            for msg in resp.json().get('value', []):
                snippet = msg.get('bodyPreview', '')
                full_body_content = msg.get('body', {}).get('content', '')
                date_key = 'sentDateTime' if folder == 'sent' else 'receivedDateTime'
                date_value = msg.get(date_key)
                date_str = None
                if date_value:
                    dt = datetime.fromisoformat(date_value.replace('Z', '+00:00')).astimezone(pytz.timezone('Asia/Kolkata'))
                    date_str = dt.strftime('%Y-%m-%d %H:%M')
                message_details = {'id': msg['id'], 'subject': msg.get('subject', 'No Subject'), 'sender': msg.get('from', {}).get('emailAddress', {}).get('name', 'Unknown Sender'), 'snippet': snippet, 'attachment': None, 'date': date_str}

                try:
                    # --- BUG FIX: Attempt decryption on the FULL BODY, not the preview snippet ---
                    json_payload = json.loads(full_body_content) 
                    if 'key_id' in json_payload:
                        q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                        if q_key_record:
                            decrypted_body = ""
                            level = json_payload['security_level']
                            ciphertext = base64.b64decode(json_payload['ciphertext'])
                            if level == 2:
                                decrypted_body = crypto_utils.decrypt_aes(ciphertext, base64.b64decode(json_payload['nonce']), q_key_record.key_data).decode('utf-8')
                            elif level == 3:
                                decrypted_body = crypto_utils.decrypt_hybrid_otp(ciphertext, base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data).decode('utf-8')
                            message_details.update({'subject': message_details['subject'].replace("[QuMail Encrypted] ", ""), 'snippet': f"🛡️ [DECRYPTED] {decrypted_body[:100]}", 'attachment': json_payload.get("attachment")})
                except Exception:
                    if msg.get('hasAttachments'): message_details['attachment'] = {'filename': 'attachment'}
                messages.append(message_details)

    except Exception as e:
        print(f"!!! Error fetching emails: {e} !!!")
    return render_template('inbox.html', user=user_data, messages=messages, current_folder=folder.capitalize())

@app.route('/api/message/<provider>/<message_id>')
def get_message_body_api(provider, message_id):
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    token = session['user']['token']
    try:
        if provider == 'google':
            resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()
            raw_email = base64.urlsafe_b64decode(resp['raw'])
            return jsonify({'body': get_email_body(raw_email)})
        elif provider == 'microsoft':
            resp = oauth.microsoft.get(f"me/messages/{message_id}", token=token).json()
            return jsonify({'body': resp.get('body', {}).get('content', 'Email body could not be retrieved.')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/compose')
def compose():
    if 'user' not in session: return redirect(url_for('index'))
    return render_template('compose.html')
    
# In app.py, replace the entire send_email function

@app.route('/send_email', methods=['POST'])
def send_email():
    if 'user' not in session: return redirect(url_for('index'))
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data['token']
    sender_email = user_data['info'].get('email') or user_data['info'].get('mail') or user_data['info'].get('userPrincipalName')
    to_address, subject, body, security_level, attachment = request.form.get('to'), request.form.get('subject'), request.form.get('body'), int(request.form.get('security_level')), request.files.get('attachment')
    
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
                if attachment and attachment.filename: payload['message']['attachments'].append({'@odata.type': '#microsoft.graph.fileAttachment', 'name': attachment.filename, 'contentBytes': base64.b64encode(attachment.read()).decode('utf-8')})
                oauth.microsoft.post('https://graph.microsoft.com/v1.0/me/sendMail', json=payload, token=token)
            flash("Email sent successfully!", "success")
        else: # Handles Level 2 and 3
            q_key_record = key_manager.get_unused_key()
            if not q_key_record:
                flash("Failed to send: No quantum keys available.", "error")
                return redirect(url_for('compose'))
            
            quantum_key = q_key_record.key_data
            encrypted_payload = {"key_id": q_key_record.id, "security_level": security_level}
            
            # --- THIS IS THE CORRECTED INDENTATION ---
            if security_level == 2:
                body_ciphertext, body_nonce = crypto_utils.encrypt_aes(body.encode('utf-8'), quantum_key)
                encrypted_payload.update({"ciphertext": base64.b64encode(body_ciphertext).decode('utf-8'), "nonce": base64.b64encode(body_nonce).decode('utf-8')})
                if attachment and attachment.filename:
                    att_ciphertext, att_nonce = crypto_utils.encrypt_aes(attachment.read(), quantum_key)
                    encrypted_payload["attachment"] = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8')}
            
            elif security_level == 3: # This is now correctly aligned
                body_ciphertext, body_nonce, enc_session_key = crypto_utils.encrypt_hybrid_otp(body.encode('utf-8'), quantum_key)
                encrypted_payload.update({"nonce": base64.b64encode(body_nonce).decode('utf-8'), "ciphertext": base64.b64encode(body_ciphertext).decode('utf-8'), "session_key": base64.b64encode(enc_session_key).decode('utf-8')})
                if attachment and attachment.filename:
                    att_ciphertext, att_nonce, att_enc_session_key = crypto_utils.encrypt_hybrid_otp(attachment.read(), quantum_key)
                    encrypted_payload["attachment"] = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8'), "session_key": base64.b64encode(att_enc_session_key).decode('utf-8')}
            # -------------------------------------------

            final_body, final_subject = json.dumps(encrypted_payload), f"[QuMail Encrypted] {subject}"
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
            
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "error")
        
    return redirect(url_for('inbox'))

# In app.py, replace the entire download_attachment function with this one.

@app.route('/download_attachment/<provider>/<message_id>')
def download_attachment(provider, message_id):
    if 'user' not in session:
        return redirect(url_for('index'))

    token = session['user']['token']
    
    try:
        body_text = None
        # Step 1: Get the email's body content based on the provider
        if provider == 'google':
            msg_resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()
            raw_email_data = base64.urlsafe_b64decode(msg_resp['raw'])
            parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email_data)
            body_part = parsed_email.get_body(preferencelist=('plain',))
            if body_part:
                body_text = body_part.get_content()
        
        elif provider == 'microsoft':
            resp = oauth.microsoft.get(f"me/messages/{message_id}?$select=body", token=token).json()
            body_text = resp.get('body', {}).get('content', '')

        # Step 2: Determine if the email is encrypted by trying to parse the body as JSON
        is_encrypted = False
        payload = None
        if body_text:
            try:
                payload = json.loads(body_text)
                if 'key_id' in payload:
                    is_encrypted = True
            except (json.JSONDecodeError, TypeError):
                is_encrypted = False

        # Step 3: Handle the download based on whether it's encrypted or not
        if is_encrypted:
            # --- THIS IS THE CORRECTED LOGIC FOR ENCRYPTED ATTACHMENTS ---
            attachment_data = payload.get('attachment')
            key_id = payload.get('key_id')

            # Defensive checks: Ensure attachment data and key_id exist before proceeding
            if not attachment_data or not key_id:
                raise ValueError("Encrypted email payload is missing attachment data or key_id.")

            q_key_record = key_manager.get_key_by_id(key_id)
            if not q_key_record:
                raise ValueError(f"Decryption key with id {key_id} not found.")

            ciphertext = base64.b64decode(attachment_data['ciphertext'])
            nonce = base64.b64decode(attachment_data['nonce'])
            decrypted_bytes = None
            
            security_level = payload.get('security_level')
            if security_level == 2:
                decrypted_bytes = crypto_utils.decrypt_aes(ciphertext, nonce, q_key_record.key_data)
            elif security_level == 3:
                session_key = base64.b64decode(attachment_data['session_key'])
                decrypted_bytes = crypto_utils.decrypt_hybrid_otp(ciphertext, nonce, session_key, q_key_record.key_data)
            
            if decrypted_bytes:
                return send_file(io.BytesIO(decrypted_bytes), download_name=attachment_data['filename'], as_attachment=True)
            else:
                raise Exception("Decryption failed or produced no data.")
        
        else:
            # Logic for regular, unencrypted attachments (remains the same)
            if provider == 'google':
                # Re-parse from earlier to find attachment parts
                raw_email_data = base64.urlsafe_b64decode(oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()['raw'])
                parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email_data)
                for part in parsed_email.iter_attachments():
                    return send_file(io.BytesIO(part.get_payload(decode=True)), download_name=part.get_filename(), as_attachment=True)
            
            elif provider == 'microsoft':
                att_resp = oauth.microsoft.get(f"me/messages/{message_id}/attachments", token=token).json()
                if att_resp.get('value'):
                    att_id = att_resp['value'][0]['id']
                    attachment = oauth.microsoft.get(f"me/messages/{message_id}/attachments/{att_id}", token=token).json()
                    file_bytes = base64.b64decode(attachment['contentBytes'])
                    return send_file(io.BytesIO(file_bytes), download_name=attachment['name'], as_attachment=True)

    except Exception as e:
        print(f"!!! Critical Error in download_attachment: {e} !!!")
        flash(f"Failed to download attachment. Error: {e}", "error")
        # Redirect back to inbox instead of showing a blank page
        return redirect(url_for('inbox'))

    # If all else fails, show a 404
    return "Attachment not found.", 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)