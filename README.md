# Secure-Messaging-Web-App

## Project Overview

This project is a Flask-based web application designed for secure messaging, implementing end-to-end encryption using RSA and AES. It fulfills the requirements of the project by incorporating a public key verification mechanism using GitHub Gists, ensuring protection against a malicious server tampering with public keys. The application allows users to sign up, log in, send encrypted messages, and delete received messages, with a focus on security and user-friendly identity verification.

## Features

 **User Authentication**: Users can sign up and log in with email and password, with passwords securely hashed using Werkzeug.
 **Key Generation**: Generates RSA key pairs (2048-bit) during signup, storing the public key and (currently) the private key in a SQLite database.
**Identity Verification**: Users can provide a GitHub Gist URL containing their public key during signup. Before sending a message, the recipient’s public key is verified against the Gist URL to ensure authenticity, meeting the project’s “PK/DNS based identity” requirement.
**End-to-End Encryption**: Messages are encrypted using AES-CBC with a random key, which is encrypted with the recipient’s RSA public key (PKCS1_OAEP).
**Message Management**: Users can view decrypted messages in their inbox and delete messages securely.
**User-Friendly Interface**: Templates (`signup.html`, `send_message.html`, etc.) provide clear instructions for posting public keys to GitHub Gists and verifying recipient keys.
