from flask import Flask, request, render_template, session, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import logging
import hashlib
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# Setup logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Validate RSA key pair
def validate_key_pair(public_key, private_key):
    try:
        pub_key = RSA.import_key(public_key)
        priv_key = RSA.import_key(private_key)
        test_message = get_random_bytes(32)
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        encrypted = cipher_rsa.encrypt(test_message)
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        decrypted = cipher_rsa.decrypt(encrypted)
        return decrypted == test_message
    except Exception as e:
        logger.error(f"Key pair validation failed: {str(e)}")
        return False

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (email TEXT PRIMARY KEY, password TEXT, public_key TEXT, private_key TEXT, key_verification_url TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                 (Id INTEGER PRIMARY KEY AUTOINCREMENT, sender_email TEXT, 
                  recipient_email TEXT, encrypted_message TEXT, encrypted_key TEXT, nonce TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        key_verification_url = request.form.get('key_verification_url', '')  # Optional
        
        session.clear()
        
        key = RSA.generate(2048)
        public_key = key.publickey().exportKey('PEM').decode()
        private_key = key.exportKey('PEM').decode()
        
        if not validate_key_pair(public_key, private_key):
            return render_template('signup.html', error="Generated key pair is invalid.")
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('DELETE FROM users WHERE email = ?', (email,))
            c.execute(' INSERT INTO users (email, password, public_key, private_key, key_verification_url) VALUES (?, ?, ?, ?, ?)', 
                     (email, hashed_password, public_key, private_key, key_verification_url))
            conn.commit()
            session['private_key'] = private_key
            session['email'] = email
            logger.debug(f"User {email} signed up. Public key hash: {hashlib.sha256(public_key.encode()).hexdigest()}")
            return render_template('signup.html', 
                                 message="Signup successful! Copy your public key and post it to a public GitHub repository or Gist. Enter the URL below.",
                                 public_key=public_key, key_verification_url=key_verification_url)
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error="Email already exists")
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        session.clear()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT password, private_key, public_key FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            if not validate_key_pair(user[2], user[1]):
                logger.error(f"Invalid key pair for {email}")
                return render_template('login.html', error="Invalid key pair in database. Please re-sign up.")
            session['email'] = email
            session['private_key'] = user[1] if user[1] else None
            if not session['private_key']:
                logger.error(f"No private key found for user {email}")
                return render_template('login.html', error="No private key for this user. Please re-sign up.")
            logger.debug(f"User {email} logged in")
            return redirect(url_for('home'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    if not session.get('private_key'):
        logger.error(f"No private key in session for {session['email']}")
        return render_template('home.html', messages=[(0, "System", "No private key available. Please re-sign up.")])
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, sender_email, encrypted_message, encrypted_key, nonce FROM messages WHERE recipient_email = ?', 
             (session['email'],))
    messages = c.fetchall()
    conn.close()
    
    decrypted_messages = []
    for msg in messages:
        try:
            private_key = RSA.import_key(session['private_key'])
            cipher_rsa = PKCS1_OAEP.new(private_key)
            encrypted_key = base64.b64decode(msg[3])
            aes_key = cipher_rsa.decrypt(encrypted_key)
            encrypted_message = base64.b64decode(msg[2])
            nonce = base64.b64decode(msg[4])
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, nonce)
            decrypted_bytes = cipher_aes.decrypt(encrypted_message)
            padding_length = decrypted_bytes[-1]
            decrypted_bytes = decrypted_bytes[:-padding_length]
            try:
                decrypted_message = decrypted_bytes.decode('utf-8')
                decrypted_messages.append((msg[0], msg[1], decrypted_message))
            except UnicodeDecodeError as e:
                logger.error(f"UTF-8 decode failed for message {msg[0]}")
                decrypted_messages.append((msg[0], msg[1], f"Error decrypting message: UTF-8 decode failed"))
        except Exception as e:
            logger.error(f"Failed to decrypt message {msg[0]}: {str(e)}")
            decrypted_messages.append((msg[0], msg[1], f"Error decrypting message: {str(e)}"))
    return render_template('home.html', messages=decrypted_messages)

@app.route('/get_public_key', methods=['POST'])
def get_public_key():
    email = request.form.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT public_key, key_verification_url FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({'public_key': user[0], 'key_verification_url': user[1] or ''})
    return jsonify({'error': 'User not found'}), 404

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        recipient_email = request.form['recipient_email']
        verification_url = request.form.get('verification_url', '')
        try:
            message = request.form['message'].encode('utf-8')
        except UnicodeEncodeError:
            return render_template('send_message.html', error="Message contains invalid characters. Use standard text.")
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT public_key, key_verification_url FROM users WHERE email = ?', (recipient_email,))
        user = c.fetchone()
        if not user:
            conn.close()
            return render_template('send_message.html', error="Recipient not found")

         recipient_public_key = '\n'.join(line.strip() for line in user[0].splitlines() if line.strip())
        db_verification_url = user[1] or ''
        
        # Verify public key if a URL is provided or stored
        warning = None
        if verification_url or db_verification_url:
            url_to_check = verification_url or db_verification_url
            try:
                response = requests.get(url_to_check, timeout=5)
                if response.status_code != 200 or recipient_public_key not in response.text:
                    conn.close()
                    return render_template('send_message.html', error="Public key verification failed: Key not found at URL or mismatch.")
            except requests.RequestException:
                warning = f"Could not verify public key at {url_to_check}. Proceeding without verification."
        else:
            warning = "No GitHub URL provided. The message will be encrypted with the stored public key, which may be less secure."
        
        try:
            aes_key = get_random_bytes(16)
            nonce = get_random_bytes(16)
            padding_length = 16 - (len(message) % 16)
            message += bytes([padding_length] * padding_length)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, nonce)
            encrypted_message = base64.b64encode(cipher_aes.encrypt(message)).decode()
            
            recipient_key = RSA.import_key(recipient_public_key)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            encrypted_key = base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()
            
            c.execute('INSERT INTO messages (sender_email, recipient_email, encrypted_message, encrypted_key, nonce) VALUES (?, ?, ?, ?, ?)', 
                     (session['email'], recipient_email, encrypted_message, encrypted_key, base64.b64encode(nonce).decode()))
            conn.commit()
            conn.close()
            logger.debug(f"Message sent from {session['email']} to {recipient_email}")
            return render_template('send_message.html', message="Message sent successfully", warning=warning)
        except ValueError as e:
            conn.close()
            logger.error(f"Error encrypting message: {str(e)}")
            return render_template('send_message.html', error=f"Invalid public key format: {str(e)}")
    return render_template('send_message.html')

@app.route('/delete_message', methods=['POST'])
def delete_message():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    message_id = request.form.get('message_id')
    if not message_id:
        return jsonify({'error': 'Message ID is required'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM messages WHERE id = ? AND recipient_email = ?', (message_id, session['email']))
    if c.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Message not found or unauthorized'}), 404
    conn.commit()
    conn.close()
    logger.debug(f"Message {message_id} deleted by {session['email']}")
    return jsonify({'success': 'Message deleted'})

