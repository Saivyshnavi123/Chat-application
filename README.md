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

##Requirements Fulfillment

The proejct requires a secure messaging application with a mechanism to verify user identities, protecting against a malicious server swapping public keys. This is achieved through:

- **PK/DNS Based Identity**: Users post their public key to a public GitHub Gist (e.g., `https://gist.githubusercontent.com/Caxzen/0e795385c414ac7bddffd8883554fcf5/raw/9868773a0b2f9c95fd3861371dac3e0a9d331835/public_key.pem`) and provide the URL during signup. The application verifies the recipient’s public key against this URL before sending a message, ensuring the key hasn’t been tampered with. GitHub’s HTTPS URLs align with the “DNS based” aspect, and Gists serve as a “social media based identity” due to their public, user-associated nature.
- **Security**: Messages are encrypted with AES and RSA, ensuring confidentiality. HTTPS (enabled via hosting) secures data in transit.
- **Accessibility**: The application can be hosted on PythonAnywhere, providing a public URL for testing (e.g., `https://yourusername.pythonanywhere.com`).

  ### Prerequisites
- Python 3.8 or higher
- Git (for cloning the repository)
- A GitHub account (for creating Gists)

- ### Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/your-repo.git
   cd your-repo
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
