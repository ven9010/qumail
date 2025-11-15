import os
import json
import base64
import io
import traceback
import re 
import html
from datetime import datetime, timezone
import pytz
from email.message import EmailMessage
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
    with app.app_context():
        db.drop_all()
        db.create_all()
        key_manager.populate_key_bank_if_empty()
    print("Database has been successfully initialized.")

# --- OAuth Provider Configurations ---
oauth.register( name='google', client_id=os.getenv('GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), server_metadata_url='https://accounts.google.com/.well-known/openid-configuration', client_kwargs={'scope': 'openid email profile https://mail.google.com/'})
oauth.register( name='microsoft', client_id=os.getenv('MICROSOFT_CLIENT_ID'), client_secret=os.getenv('MICROSOFT_CLIENT_SECRET'), access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token', authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize', api_base_url='https://graph.microsoft.com/v1.0/', client_kwargs={'scope': 'User.Read Mail.ReadWrite Mail.Send'})

# --- Helper Functions ---
def get_email_body(msg_raw):
    parsed_email = BytesParser(policy=policy.default).parsebytes(msg_raw)
    html_part = parsed_email.get_body(preferencelist=('html',))
    if html_part:
        return html_part.get_content()
    plain_part = parsed_email.get_body(preferencelist=('plain',))
    if plain_part:
        return plain_part.get_content().replace('\n', '<br>')
    return "Email body could not be retrieved."

def extract_json_from_html(html_content):
    if not isinstance(html_content, str):
        return None
    content = html_content.strip()
    pre_match = re.search(r'<pre id="qumail-data"[^>]*>(.*?)</pre>', content, re.DOTALL | re.IGNORECASE)
    if pre_match:
        json_string = html.unescape(pre_match.group(1)).strip()
        if json_string.startswith('{') and json_string.endswith('}'):
            return json_string
    attr_match = re.search(r"data-qumail\s*=\s*(['\"])(.*?)\1", content, re.DOTALL | re.IGNORECASE)
    if attr_match:
        payload = attr_match.group(2).strip()
        try:
            padding_needed = len(payload) % 4
            if padding_needed:
                payload += '=' * (4 - padding_needed)
            json_string = base64.urlsafe_b64decode(payload).decode('utf-8')
            if json_string.startswith('{') and json_string.endswith('}'):
                return json_string
        except Exception:
            if payload.startswith('{') and payload.endswith('}'):
                return payload
    return None

# --- Routes ---
@app.route('/')
def index():
    if 'user' in session: return redirect(url_for('inbox'))
    return render_template('login.html')

@app.route('/privacy')
def privacy(): return render_template('privacy.html')

@app.route('/login/<provider>')
def login(provider):
    base_url = os.getenv('APP_BASE_URL')
    redirect_uri = f"{base_url}/auth/{provider}/callback"
    return oauth.create_client(provider).authorize_redirect(redirect_uri)

@app.route('/auth/<provider>/callback')
def authorize(provider):
    if 'user' in session: return redirect(url_for('inbox'))
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = None
    if provider == 'google': user_info = client.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token).json()
    elif provider == 'microsoft':
        ms_user_info = client.get('me?$select=displayName,mail,userPrincipalName', token=token).json()
        user_info = { 'name': ms_user_info.get('displayName'), 'email': ms_user_info.get('mail') or ms_user_info.get('userPrincipalName'), **ms_user_info }
    session['user'] = {'provider': provider, 'info': user_info, 'token': token}
    return redirect(url_for('inbox'))

# --- START: CORRECTED INBOX FUNCTION ---
@app.route('/mail/<folder>')
@app.route('/inbox')
def inbox(folder='inbox'):
    if 'user' not in session: return redirect(url_for('index'))
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data.get('token')
    if not token: return redirect(url_for('logout'))

    messages = []
    try:
        if provider == 'google':
            query_map = {'inbox': "in:inbox -in:draft", 'sent': "in:sent", 'spam': "in:spam", 'drafts': "in:draft", 'bin': "in:trash"}
            query = query_map.get(folder, "in:inbox")
            resp = oauth.google.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&q={query}', token=token)
            resp.raise_for_status()
            message_ids = resp.json().get('messages', []) or []
            
            for msg_summary in message_ids:
                msg_id = msg_summary['id']
                msg_resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=metadata&metadataHeaders=subject&metadataHeaders=from&metadataHeaders=to", token=token).json()
                headers = msg_resp.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                recipient_header = next((h['value'] for h in headers if h['name'].lower() == 'to'), None)
                snippet = msg_resp.get('snippet', '')
                internal_date = msg_resp.get('internalDate')
                date_str = datetime.fromtimestamp(int(internal_date) / 1000, tz=timezone.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M') if internal_date else None
                message_details = {'id': msg_id, 'subject': subject, 'sender': sender, 'snippet': snippet, 'attachment': None, 'date': date_str}

                if "[QuMail Encrypted]" in subject:
                    try:
                        raw_resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw", token=token).json()
                        raw_email_data = base64.urlsafe_b64decode(raw_resp['raw'])
                        body_html = get_email_body(raw_email_data)
                        json_string = extract_json_from_html(body_html)
                        if json_string:
                            json_payload = json.loads(json_string)
                            if "attachment_info" in json_payload:
                                message_details['attachment'] = json_payload["attachment_info"]
                            
                            # **KEY LOGIC RESTORED**: Attempt to decrypt for snippet preview
                            level = json_payload.get('security_level')
                            decrypted_body_bytes = None
                            if level == 2:
                                q_key_record = key_manager.get_shared_key_for_email(recipient_header)
                                if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_aes(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), q_key_record.key_data)
                            elif level == 3 and 'key_id' in json_payload:
                                q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                                if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data)
                            
                            if decrypted_body_bytes:
                                decrypted_body = decrypted_body_bytes.decode('utf-8')
                                message_details.update({
                                    'subject': subject.replace("[QuMail Encrypted] ", ""),
                                    'snippet': f"🛡️ [DECRYPTED] {decrypted_body[:100]}..."
                                })

                    except Exception as e:
                        print(f"!!! SNIPPET DECRYPTION FAILED (Google) !!! Email ID: {msg_id}, Error: {e}")
                else:
                    if 'parts' in msg_resp.get('payload', {}):
                        for part in msg_resp['payload']['parts']:
                            if part.get('filename'):
                                message_details['attachment'] = {'filename': part.get('filename')}
                                break
                messages.append(message_details)

        elif provider == 'microsoft':
            folder_map = {'inbox': 'inbox', 'sent': 'sentitems', 'spam': 'junkemail', 'drafts': 'drafts', 'bin': 'deleteditems'}
            folder_id = folder_map.get(folder, 'inbox')
            select_fields = "id,subject,from,bodyPreview,body,hasAttachments,receivedDateTime,sentDateTime,toRecipients"
            api_url = f'me/mailfolders/{folder_id}/messages?$top=20&$select={select_fields}'
            resp = oauth.microsoft.get(api_url, token=token)
            resp.raise_for_status()

            for msg in resp.json().get('value', []):
                snippet = msg.get('bodyPreview', '')
                full_body_content = msg.get('body', {}).get('content', '')
                date_key = 'sentDateTime' if folder == 'sent' else 'receivedDateTime'
                date_value = msg.get(date_key)
                date_str = datetime.fromisoformat(date_value.replace('Z', '+00:00')).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M') if date_value else None
                message_details = {'id': msg['id'], 'subject': msg.get('subject', 'No Subject'), 'sender': msg.get('from', {}).get('emailAddress', {}).get('name', 'Unknown Sender'), 'snippet': snippet, 'attachment': None, 'date': date_str}

                if "[QuMail Encrypted]" in message_details['subject']:
                    try:
                        json_string = extract_json_from_html(full_body_content)
                        if json_string:
                            json_payload = json.loads(json_string)
                            if "attachment_info" in json_payload:
                                message_details['attachment'] = json_payload["attachment_info"]
                            
                            # **KEY LOGIC RESTORED FOR MICROSOFT**: Attempt to decrypt for snippet preview
                            level = json_payload.get('security_level')
                            decrypted_body_bytes = None
                            recipient_email = msg.get('toRecipients', [{}])[0].get('emailAddress', {}).get('address')
                            if level == 2:
                                q_key_record = key_manager.get_shared_key_for_email(recipient_email)
                                if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_aes(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), q_key_record.key_data)
                            elif level == 3 and 'key_id' in json_payload:
                                q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                                if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data)

                            if decrypted_body_bytes:
                                decrypted_body = decrypted_body_bytes.decode('utf-8')
                                message_details.update({
                                    'subject': message_details['subject'].replace("[QuMail Encrypted] ", ""),
                                    'snippet': f"🛡️ [DECRYPTED] {decrypted_body[:100]}..."
                                })
                    except Exception as e:
                        print(f"!!! SNIPPET DECRYPTION FAILED (Microsoft) !!! Email ID: {msg['id']}, Error: {e}")
                elif msg.get('hasAttachments'):
                    message_details['attachment'] = {'filename': 'Attachment'}
                messages.append(message_details)

    except Exception as e:
        print(f"!!! Error fetching emails: {e} !!!"); traceback.print_exc()
    return render_template('inbox.html', user=user_data, messages=messages, current_folder=folder.capitalize())
# --- END: CORRECTED INBOX FUNCTION ---

@app.route('/delete_emails', methods=['POST'])
def delete_emails():
    # This function is correct and remains unchanged
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data or 'message_ids' not in data: return jsonify({'error': 'No message IDs provided.'}), 400
    message_ids = data['message_ids']
    provider = session['user']['provider']
    token = session['user']['token']
    deleted_count = 0
    for msg_id in message_ids:
        try:
            if provider == 'google':
                resp = oauth.google.post(f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/trash', token=token)
                resp.raise_for_status()
            elif provider == 'microsoft':
                move_payload = {'destinationId': 'deleteditems'}
                resp = oauth.microsoft.post(f'me/messages/{msg_id}/move', json=move_payload, token=token)
                resp.raise_for_status()
            deleted_count += 1
        except Exception as e:
            print(f"Failed to delete message {msg_id}: {e}")
    flash(f"{deleted_count} message(s) moved to Bin.", "success")
    return jsonify({'message': f'{deleted_count} message(s) deleted successfully.'}), 200

@app.route('/api/message/<provider>/<message_id>')
def get_message_body_api(provider, message_id):
    # This function is correct and remains unchanged
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    token = session['user']['token']
    try:
        if provider == 'google':
            resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()
            raw_email_data = base64.urlsafe_b64decode(resp['raw'])
            body_html = get_email_body(raw_email_data)
            json_string = extract_json_from_html(body_html)
            if json_string:
                json_payload = json.loads(json_string)
                parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email_data)
                recipient_email = parsed_email.get('To')
                level = json_payload.get('security_level')
                decrypted_body_bytes = None
                if level == 2:
                    q_key_record = key_manager.get_shared_key_for_email(recipient_email)
                    if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_aes(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), q_key_record.key_data)
                elif level == 3 and 'key_id' in json_payload:
                    q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                    if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data)
                if decrypted_body_bytes:
                    return jsonify({'body': f'<div style="white-space: pre-wrap; word-break: break-word;">{decrypted_body_bytes.decode("utf-8")}</div>'})
                else:
                    return jsonify({'body': '<p class="text-red-400">Decryption failed: Key error.</p>'})
            return jsonify({'body': body_html})
        
        elif provider == 'microsoft':
            resp = oauth.microsoft.get(f"me/messages/{message_id}", token=token).json()
            body_content = resp.get('body', {}).get('content', 'Email body could not be retrieved.')
            json_string = extract_json_from_html(body_content)
            if json_string:
                json_payload = json.loads(json_string)
                recipient = resp.get('toRecipients', [{}])[0].get('emailAddress', {}).get('address')
                level = json_payload.get('security_level')
                decrypted_body_bytes = None
                if level == 2:
                    q_key_record = key_manager.get_shared_key_for_email(recipient)
                    if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_aes(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), q_key_record.key_data)
                elif level == 3 and 'key_id' in json_payload:
                    q_key_record = key_manager.get_key_by_id(json_payload['key_id'])
                    if q_key_record: decrypted_body_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(json_payload['ciphertext']), base64.b64decode(json_payload['nonce']), base64.b64decode(json_payload['session_key']), q_key_record.key_data)
                if decrypted_body_bytes:
                    return jsonify({'body': f'<div style="white-space: pre-wrap; word-break: break-word;">{decrypted_body_bytes.decode("utf-8")}</div>'})
                else:
                    return jsonify({'body': '<p class="text-red-400">Decryption failed: Key error.</p>'})
            return jsonify({'body': body_content})

    except Exception as e:
        return jsonify({'error': 'An internal error occurred.'}), 500

@app.route('/compose')
def compose():
    if 'user' not in session: return redirect(url_for('inbox'))
    return render_template('compose.html')

@app.route('/send_email', methods=['POST'])
def send_email():
    # This function is correct and remains unchanged
    if 'user' not in session: return redirect(url_for('inbox'))
    user_data = session.get('user')
    provider = user_data['provider']
    token = user_data['token']
    sender_email = user_data['info'].get('email') or user_data['info'].get('mail') or user_data['info'].get('userPrincipalName')
    to_address, subject, body, security_level, attachment = request.form.get('to'), request.form.get('subject'), request.form.get('body'), int(request.form.get('security_level')), request.files.get('attachment')

    has_attachment = attachment and attachment.filename
    is_encrypted = security_level > 1

    try:
        if not is_encrypted:
            if provider == 'google':
                message = EmailMessage()
                message['To'], message['From'], message['Subject'] = to_address, sender_email, subject
                message.set_content(body)
                if has_attachment:
                    attachment.seek(0)
                    message.add_attachment(attachment.read(), maintype='application', subtype='octet-stream', filename=attachment.filename)
                payload = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
                oauth.google.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', json=payload, token=token)
            elif provider == 'microsoft':
                payload = {'message': {'subject': subject, 'body': {'contentType': 'Text', 'content': body}, 'toRecipients': [{'emailAddress': {'address': to_address}}], 'attachments': []}, 'saveToSentItems': 'true'}
                if has_attachment:
                    attachment.seek(0)
                    payload['message']['attachments'].append({'@odata.type': '#microsoft.graph.fileAttachment', 'name': attachment.filename, 'contentBytes': base64.b64encode(attachment.read()).decode('utf-8')})
                oauth.microsoft.post('me/sendMail', json=payload, token=token)
        else:
            body_payload = {"security_level": security_level}
            if security_level == 2:
                q_key_record = key_manager.get_shared_key_for_email(to_address)
                if not q_key_record: flash("No shared key for recipient.", "error"); return redirect(url_for('compose'))
                ciphertext, nonce = crypto_utils.encrypt_aes(body.encode('utf-8'), q_key_record.key_data)
                body_payload.update({"ciphertext": base64.b64encode(ciphertext).decode('utf-8'), "nonce": base64.b64encode(nonce).decode('utf-8')})
            elif security_level == 3:
                q_key_record = key_manager.get_unused_key()
                if not q_key_record: flash("No quantum keys available.", "error"); return redirect(url_for('compose'))
                body_payload["key_id"] = q_key_record.id
                ciphertext, nonce, session_key = crypto_utils.encrypt_hybrid_otp(body.encode('utf-8'), q_key_record.key_data)
                body_payload.update({"nonce": base64.b64encode(nonce).decode('utf-8'), "ciphertext": base64.b64encode(ciphertext).decode('utf-8'), "session_key": base64.b64encode(session_key).decode('utf-8')})
                key_manager.mark_key_as_used(q_key_record)

            encrypted_attachment_payload = None
            if has_attachment:
                attachment.seek(0); attachment_data = attachment.read()
                att_payload = {}
                if security_level == 2:
                    q_key_record_att = key_manager.get_shared_key_for_email(to_address)
                    att_ciphertext, att_nonce = crypto_utils.encrypt_aes(attachment_data, q_key_record_att.key_data)
                    att_payload = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8')}
                elif security_level == 3:
                    q_key_record_att = key_manager.get_unused_key()
                    if not q_key_record_att: flash("No quantum keys for attachment.", "error"); return redirect(url_for('compose'))
                    att_ciphertext, att_nonce, att_session_key = crypto_utils.encrypt_hybrid_otp(attachment_data, q_key_record_att.key_data)
                    att_payload = {"filename": attachment.filename, "nonce": base64.b64encode(att_nonce).decode('utf-8'), "ciphertext": base64.b64encode(att_ciphertext).decode('utf-8'), "session_key": base64.b64encode(att_session_key).decode('utf-8'), "key_id": q_key_record_att.id}
                    key_manager.mark_key_as_used(q_key_record_att)
                encrypted_attachment_payload = json.dumps(att_payload).encode('utf-8')
                body_payload['attachment_info'] = {'filename': attachment.filename}
            
            json_string = json.dumps(body_payload)
            b64_payload = base64.urlsafe_b64encode(json_string.encode('utf-8')).decode('utf-8')
            html_body = f"""<div id="qumail-container" style="font-family: sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px;" data-qumail='{b64_payload}'><h2 style="color: #333;">🔒 This email is encrypted by QuMail</h2><p style="color: #555;">To view this message, please open it using the <a href="https://qumail.onrender.com" target="_blank">QuMail application</a>.</p><p style="color: #999; font-size: 12px;">QuMail ensures your communications are quantum-secure.</p></div><pre id="qumail-data" style="display:none !important; visibility:hidden !important; mso-hide:all;">{html.escape(json_string)}</pre>"""
            plain_text = "To view this encrypted message, please open it using the QuMail application: https://qumail.onrender.com"
            final_subject = f"[QuMail Encrypted] {subject}"

            if provider == 'google':
                message = EmailMessage()
                message['To'], message['From'], message['Subject'] = to_address, sender_email, final_subject
                message.set_content(plain_text)
                message.add_alternative(html_body, subtype='html')
                if encrypted_attachment_payload:
                    message.add_attachment(encrypted_attachment_payload, maintype='application', subtype='octet-stream', filename='encrypted.qumail')
                payload = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
                oauth.google.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', json=payload, token=token)
            elif provider == 'microsoft':
                payload = {'message': {'subject': final_subject, 'body': {'contentType': 'HTML', 'content': html_body}, 'toRecipients': [{'emailAddress': {'address': to_address}}], 'attachments': []}, 'saveToSentItems': 'true'}
                if encrypted_attachment_payload:
                    payload['message']['attachments'].append({'@odata.type': '#microsoft.graph.fileAttachment', 'name': 'encrypted.qumail', 'contentBytes': base64.b64encode(encrypted_attachment_payload).decode('utf-8')})
                oauth.microsoft.post('me/sendMail', json=payload, token=token)

        flash("Email sent successfully!", "success")
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "error"); traceback.print_exc()
    return redirect(url_for('inbox'))

@app.route('/download_attachment/<provider>/<message_id>')
def download_attachment(provider, message_id):
    # This function is correct and remains unchanged
    if 'user' not in session: return redirect(url_for('index'))
    token = session['user']['token']
    try:
        if provider == 'google':
            resp = oauth.google.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=raw", token=token).json()
            raw_email_data = base64.urlsafe_b64decode(resp['raw'])
            parsed_email = BytesParser(policy=policy.default).parsebytes(raw_email_data)
            
            for part in parsed_email.iter_attachments():
                filename = part.get_filename()
                if not filename: continue
                if filename == "encrypted.qumail":
                    payload_bytes = part.get_payload(decode=True)
                    attachment_payload = json.loads(payload_bytes.decode('utf-8'))
                    body_html = get_email_body(raw_email_data)
                    body_json_string = extract_json_from_html(body_html)
                    if not body_json_string: raise Exception("Body payload not found.")
                    body_payload = json.loads(body_json_string)
                    level = body_payload.get('security_level')
                    decrypted_bytes = None
                    if level == 2:
                        recipient_email = parsed_email.get('To')
                        q_key_record = key_manager.get_shared_key_for_email(recipient_email)
                        if not q_key_record: raise ValueError("Shared key not found.")
                        decrypted_bytes = crypto_utils.decrypt_aes(base64.b64decode(attachment_payload['ciphertext']), base64.b64decode(attachment_payload['nonce']), q_key_record.key_data)
                    elif level == 3:
                        key_id = attachment_payload.get('key_id')
                        if not key_id: raise ValueError("Attachment key_id missing.")
                        q_key_record = key_manager.get_key_by_id(key_id)
                        if not q_key_record: raise ValueError("Attachment key not found.")
                        decrypted_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(attachment_payload['ciphertext']), base64.b64decode(attachment_payload['nonce']), base64.b64decode(attachment_payload['session_key']), q_key_record.key_data)
                    if decrypted_bytes:
                        return send_file(io.BytesIO(decrypted_bytes), download_name=attachment_payload['filename'], as_attachment=True)
                    else: raise Exception("Attachment decryption failed.")
                else:
                    return send_file(io.BytesIO(part.get_payload(decode=True)), download_name=filename, as_attachment=True)
        
        elif provider == 'microsoft':
            msg_resp = oauth.microsoft.get(f"me/messages/{message_id}", token=token).json()
            body_content = msg_resp.get('body', {}).get('content', '')
            body_json_string = extract_json_from_html(body_content)
            att_resp = oauth.microsoft.get(f"me/messages/{message_id}/attachments", token=token).json()
            if not att_resp.get('value'): raise Exception("No attachments found.")

            attachment_data = att_resp['value'][0]
            filename = attachment_data.get('name')
            att_id = attachment_data.get('id')
            
            if filename == "encrypted.qumail":
                full_attachment = oauth.microsoft.get(f"me/messages/{message_id}/attachments/{att_id}", token=token).json()
                payload_bytes = base64.b64decode(full_attachment['contentBytes'])
                attachment_payload = json.loads(payload_bytes.decode('utf-8'))
                if not body_json_string: raise Exception("Body payload not found.")
                body_payload = json.loads(body_json_string)
                level = body_payload.get('security_level')
                decrypted_bytes = None
                if level == 2:
                    recipient = msg_resp.get('toRecipients', [{}])[0].get('emailAddress', {}).get('address')
                    q_key_record = key_manager.get_shared_key_for_email(recipient)
                    if not q_key_record: raise ValueError("Shared key not found.")
                    decrypted_bytes = crypto_utils.decrypt_aes(base64.b64decode(attachment_payload['ciphertext']), base64.b64decode(attachment_payload['nonce']), q_key_record.key_data)
                elif level == 3:
                    key_id = attachment_payload.get('key_id')
                    if not key_id: raise ValueError("Attachment key_id missing.")
                    q_key_record = key_manager.get_key_by_id(key_id)
                    if not q_key_record: raise ValueError("Attachment key not found.")
                    decrypted_bytes = crypto_utils.decrypt_hybrid_otp(base64.b64decode(attachment_payload['ciphertext']), base64.b64decode(attachment_payload['nonce']), base64.b64decode(attachment_payload['session_key']), q_key_record.key_data)
                if decrypted_bytes:
                    return send_file(io.BytesIO(decrypted_bytes), download_name=attachment_payload['filename'], as_attachment=True)
                else: raise Exception("Attachment decryption failed.")
            else:
                full_attachment = oauth.microsoft.get(f"me/messages/{message_id}/attachments/{att_id}", token=token).json()
                file_bytes = base64.b64decode(full_attachment['contentBytes'])
                return send_file(io.BytesIO(file_bytes), download_name=filename, as_attachment=True)

    except Exception as e:
        print(f"!!! Critical Error in download_attachment: {e} !!!"); traceback.print_exc()
        flash(f"Failed to download attachment. Error: {e}", "error")
        return redirect(url_for('inbox'))
        
    flash("Attachment not found.", "error")
    return redirect(url_for('inbox'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    # This is a test commit to trigger Render