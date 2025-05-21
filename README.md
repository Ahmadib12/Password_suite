Password Security Suite
This Python script provides essential tools for enhancing your digital security: a password strength checker with an AI guessing time estimator, a strong password generator, and a secure, local password manager.
Features
 * Password Strength Analysis: Evaluates password strength and offers improvement tips.
 * AI Guessing Time Estimation: Calculates how long a powerful AI might take to brute-force a password.
 * Strong Password Generation: Creates highly random and secure passwords.
 * Secure Local Password Manager: Stores your credentials encrypted on your local machine, protected by a master password.
Installation
To run this script, you need Python installed on your system. You also need the cryptography library.
 * Install Python: If you don't have Python, download and install it from python.org.
 * Install cryptography: Open your terminal or command prompt and run:
   pip install cryptography

   (You might use pip3 install cryptography or python -m pip install cryptography depending on your setup).
 * Save the Script: Save the provided Python code into a file named password_suite.py.
Usage
1. Set Environment Variable (If OpenSSL Error Occurs)
If you encounter an error like RuntimeError: OpenSSL 3.0's legacy provider failed to load, set this environment variable in the same terminal session before running the script:
 * Linux/macOS (Bash, Zsh):
   export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

 * Windows (Command Prompt):
   set CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

 * Windows (PowerShell):
   $env:CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

2. Run the Script
Navigate to the directory where you saved password_suite.py in your terminal and execute:
python password_suite.py

(Or python3 password_suite.py).
3. Interactive Menu
The script will display a main menu. To use the Password Manager, you must first select Option 4 to "Set/Change Master Password" for the current session. This is where you define your master password.
Important Security Notes
 * Master Password is Critical: This is the single key to your encrypted password vault.
   * Choose a very strong, unique, and memorable master password. It should be long (16+ characters minimum) and include a mix of uppercase, lowercase, numbers, and symbols.
   * The master password is NEVER stored by the script. If you forget it, your stored passwords are irrecoverable.
 * Local Storage: Your encrypted passwords are saved in passwords.json in the same directory as the script. Keep this file secure.
 * AI Guessing Time: This is a theoretical estimate for brute-force attacks. Always use strong, unique passwords for real-world security.
