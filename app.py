from flask import Flask, render_template, request, redirect, url_for
from encryption import quantum_aes_encrypt, otp_encrypt
from key_manager import fetch_quantum_key
from database import store_key, get_key

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    return redirect(url_for("compose"))

@app.route("/auth/gmail")
def auth_gmail():
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

    if security_level in [2, 3]:
        quantum_key, key_id = fetch_quantum_key()
        store_key(key_id, quantum_key)  # Store key in database
        if security_level == 2:
            body = quantum_aes_encrypt(body, quantum_key).hex()
        else:
            key_bytes = bytes.fromhex(quantum_key)[:len(body)]
            body = otp_encrypt(body, key_bytes).hex()
    else:
        key_id = None

    return f"Email prepared: {body} (Security Level {security_level}, Key ID: {key_id})"

@app.route("/inbox")
def inbox():
    return render_template("inbox.html")

if __name__ == "__main__":
    app.run(debug=True)