# SecureVault – Secure File Encryption and Decryption System

SecureVault is a Python Flask and MySQL-based project designed to protect files using encryption, integrity verification, authentication, and access control.

## Features

- User registration and login
- File encryption and decryption using AES-256-GCM
- SHA-256 file integrity verification
- Role-based access for Users and Admins
- Login attempt monitoring and security alerts
- Audit activity logs
- Cyber incident reporting and management
- Mobile and Wireless Security information
- Cyber Law and Compliance information

## Technologies Used

- Python
- Flask
- MySQL
- HTML, CSS, JavaScript
- AES-256-GCM
- SHA-256
- Werkzeug password hashing

## Setup

1. Clone or download this repository.
2. Create and activate a Python virtual environment.
3. Install dependencies using `pip install -r requirements.txt`.
4. Create the `securevault` MySQL database and configure the required tables.
5. Configure local environment variables for database credentials, Flask session security, and encryption key management.
6. Run the application using `python app.py`.

## Security Notice

Do not commit passwords, secret keys, `.env` files, private user data, or actual encrypted files. Use a local development environment and test data.

## Project Status

Academic diploma project developed for learning file security, cryptography, database management, and security monitoring.
