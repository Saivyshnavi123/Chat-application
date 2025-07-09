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

