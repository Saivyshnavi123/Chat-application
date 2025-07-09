# Secure-Messaging-Web-App

## Project Overview

This project is a Flask-based web application designed for secure messaging, implementing end-to-end encryption using RSA and AES. It fulfills the requirements of the project by incorporating a public key verification mechanism using GitHub Gists, ensuring protection against a malicious server tampering with public keys. The application allows users to sign up, log in, send encrypted messages, and delete received messages, with a focus on security and user-friendly identity verification.

## Features

- **User Authentication**: Users can sign up and log in with email and password, with passwords securely hashed using Werkzeug.
- **Key Generation**: Generates RSA key pairs (2048-bit) during signup, storing the public key and (currently) the private key in a SQLite database.
