# Secure-Messaging-Web-App

## Project Overview

This project is a Flask-based web application designed for secure messaging, implementing end-to-end encryption using RSA and AES. It fulfills the requirements of the project by incorporating a public key verification mechanism using GitHub Gists, ensuring protection against a malicious server tampering with public keys. The application allows users to sign up, log in, send encrypted messages, and delete received messages, with a focus on security and user-friendly identity verification.

## Features

 **User Authentication**: Users can sign up and log in with email and password, with passwords securely hashed using Werkzeug.
 **Key Generation**: Generates RSA key pairs (2048-bit) during signup, storing the public key and (currently) the private key in a SQLite database.
**Identity Verification**: Before sending a message, the recipient’s public key is verified against the Gist URL to ensure authenticity, meeting the project’s “PK/DNS based identity” requirement.
**End-to-End Encryption**: Messages are encrypted using AES-CBC with a random key, which is encrypted with the recipient’s RSA public key (PKCS1_OAEP).
**Message Management**: Users can view decrypted messages in their inbox and delete messages securely.
**User-Friendly Interface**: Templates (`signup.html`, `send_message.html`, etc.) provide clear instructions for posting public keys to GitHub Gists and verifying recipient keys.

##Requirements Fulfillment

The proejct requires a secure messaging application with a mechanism to verify user identities, protecting against a malicious server swapping public keys. This is achieved through:

- **PK/DNS Based Identity**: Users post their public key to a public GitHub Gist (e.g., 'https://gist.githubusercontent.com/Koushik168/19bc23f182537ab82b085bc965c74842/raw/213c8903efb5150e58a68195587f1dac6f3d8d9b/gistfile1.txt)`) and provide the URL during signup. The application verifies the recipient’s public key against this URL before sending a message, ensuring the key hasn’t been tampered with. GitHub’s HTTPS URLs align with the “DNS based” aspect, and Gists serve as a “social media based identity” due to their public, user-associated nature.
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

   3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   The `requirements.txt` includes:
   ```
   Flask==2.0.1
   Werkzeug==2.0.2
   PyCryptodome==3.15.0
   requests==2.28.1
   ```

4. **Initialize the Database**:
   ```bash
   python -c "from app import init_db; init_db()"
   ```
   This creates `database.db` with `users` and `messages` tables.

5. **Run the Application Locally**:
   ```bash
   python app.py
   ```
   Access the app at `http://localhost:5000`.

   ### Hosting on PythonAnywhere
To deploy the application online, use PythonAnywhere’s free tier:

1. **Sign Up**: Create a free account at [PythonAnywhere](https://www.pythonanywhere.com).
2. **Clone Repository**:
   - In a Bash console:
     ```bash
     git clone https://github.com/Saivyshnavi123/Chat-application.git 
     cd Chat-application
     ```
     3. **Set Up Virtual Environment**:
   ```bash
   mkvirtualenv --python=/usr/bin/python3.9 myenv
   workon myenv
   pip install -r requirements.txt
   ```
4. **Initialize Database**:
   ```bash
   python -c "from app import init_db; init_db()"
   ```

   5. **Configure Web App**:
   - In the “Web” tab, create a manual configuration web app (Python 3.9).
   - Set source code path: `/home/caxy/mysite`.
   - Set virtualenv: `myenv`.
   - Edit WSGI file (`/var/www/caxy_pythonanywhere_com_wsgi.py`):
     ```python
     import sys
     project_home = '/home/caxy/mysite'
     if project_home not in sys.path:
         sys.path.append(project_home)
     from app import app as application
     ```
   - Set working directory: `/home/caxy/mysite`.
   - Add static file mapping: URL `/static/` to `/home/caxy/mysite/static`.
6. **Enable HTTPS**: In the “Web” tab, enable “Force HTTPS”.
7. **Reload**: Click “Reload” and access at `https://caxy.pythonanywhere.com`.

## Usage

1. **Sign Up**:
   - Navigate to `/signup`.
   - Enter an email, password, and optionally a GitHub Gist URL containing your public key (e.g., (https://gist.githubusercontent.com/Koushik168/e1d916af114bf1f8b9064c026206cefd/raw/4f0b876d16754308e9866d0b011077118b757f60/Public_Key.pem).
   - Copy the displayed public key and create a public Gist:
     - Go to [GitHub Gists](https://gist.github.com).
     - Paste the key into a file (e.g., `public_key.pem`), set as public, and copy the raw URL.
     - Paste the URL into the signup form if not already done.
2. **Log In**: Use your email and password at `/login`.
3. **Send a Message**:
   - Go to `/send_message`.
   - Enter the recipient’s email and optionally their Gist URL (auto-filled if stored).
   - Write and send a message, which is encrypted with the recipient’s verified public key.
4. **View Messages**: Access `/home` to view decrypted messages.
5. **Delete Messages**: Delete messages from your inbox via the provided interface.

## Security Considerations

- **Identity Verification**: The GitHub Gist-based public key verification prevents a malicious server from swapping keys, aligning with the project’s requirement.
- **Encryption**: Messages are encrypted with AES-CBC (random 16-byte key and nonce) and RSA (PKCS1_OAEP), ensuring confidentiality.
- **Vulnerability**: Private keys are stored in the database, which is insecure if the server is compromised. Future improvements could include client-side private key storage (e.g., download during signup).
- **HTTPS**: Hosting on PythonAnywhere with “Force HTTPS” secures data in transit.
- **Input Validation**: The app sanitizes inputs but could improve by validating GitHub URLs (e.g., checking for `raw.githubusercontent.com` or `gist.githubusercontent.com`).

## Known Limitations

- Limited error handling for invalid Gist URLs; warnings are shown instead of blocking messages.
- SQLite is used, which is sufficient for small-scale use but may not scale for large user bases.


## Resources

- Flask: https://flask.palletsprojects.com/
- PyCryptodome: https://pycryptodome.readthedocs.io/
- Requests: https://requests.readthedocs.io/

## AI Usage
We have used artificial intelligence for knowing the information regarding RSA and AES usages, keys, features, and benefits.

