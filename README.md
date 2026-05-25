# 🔐 Password Security Suite

## 📌 Overview
Password Security Suite is a Python-based cyber security tool designed to help users improve their password security. It includes a password strength checker, a strong password generator, and a secure local password manager with encryption.

This project demonstrates basic cyber security concepts such as password strength analysis, brute-force resistance awareness, and encrypted data storage.

---

## ⚙️ Features

- **Password Strength Checker**  
  Analyzes password strength and provides improvement suggestions.

- **AI Guessing Time Estimator**  
  Estimates how long it would take for a brute-force attack to crack a password.

- **Strong Password Generator**  
  Creates highly random and secure passwords.

- **Encrypted Password Manager**  
  Stores credentials locally using encryption and protects them with a master password.

---

## 📦 Installation

### 1. Install Python
Download Python from: https://www.python.org

### 2. Install required library
```bash
pip install cryptography
```

### 3. Download the script
Save the file as:
```bash
password_suite.py
```

---

## ▶️ Usage

Run the program:

```bash
python password_suite.py
```

Or:

```bash
python3 password_suite.py
```

---

## 🔐 Security Notes

- The master password is **never stored**
- If forgotten, encrypted data cannot be recovered
- All passwords are stored locally in `passwords.json`
- Always use a strong master password (16+ characters recommended)

---

## ⚠️ OpenSSL Issue Fix (If Needed)

### Linux/macOS:
```bash
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
```

### Windows CMD:
```bash
set CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
```

### Windows PowerShell:
```bash
$env:CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
```

---

## 🎯 Learning Outcomes

This project demonstrates:
- Password security principles
- Encryption using Python
- Secure local data storage
- Awareness of brute-force attacks

---

## 👨‍💻 Author
**Ahmad Ibrahim**  
Cyber Security Enthusiast  
Borno, Nigeria
```
