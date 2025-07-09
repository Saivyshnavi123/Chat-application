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
