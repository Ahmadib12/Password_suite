🔐 Password Security Suite
📌 Overview
Password Security Suite is a Python-based cyber security tool designed to help users improve their password security. It includes a password strength checker, a secure password generator, and a local encrypted password manager.
This project demonstrates fundamental concepts in cyber security such as password strength analysis, encryption, and secure credential storage.
⚙️ Features
Password Strength Checker
Evaluates password strength and provides improvement suggestions.
AI Guessing Time Estimator
Estimates how long a brute-force attack could take to crack a password.
Strong Password Generator
Generates secure and random passwords.
Encrypted Password Manager
Stores credentials locally with encryption protected by a master password.
📦 Installation
1. Install Python
Download from: https://www.python.org
2. Install required library
Copy code
Bash
pip install cryptography
3. Clone or download the project
Save as:
Copy code

password_suite.py
▶️ Usage
Run the program:
Copy code
Bash
python password_suite.py
If needed:
Copy code
Bash
python3 password_suite.py
🔐 Security Notes
The master password is never stored
If lost, encrypted data cannot be recovered
All passwords are stored locally in passwords.json
Use a strong master password (16+ characters recommended)
⚠️ OpenSSL Issue Fix (If Needed)
Linux/macOS:
Copy code
Bash
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
Windows CMD:
Copy code
Bash
set CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
PowerShell:
Copy code
Bash
$env:CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
🎯 Learning Outcome
This project demonstrates:
Password security principles
Encryption using Python libraries
Secure local data storage
Basic cryptography awareness
