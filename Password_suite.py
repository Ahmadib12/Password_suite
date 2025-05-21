import math
import random
import string
import json
import os
import base64
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configuration for AI Guessing Time ---
AI_GUESSES_PER_SECOND = 1_000_000_000_000 # 1 trillion guesses per second

# --- Password Manager Configuration ---
PASSWORD_FILE = "passwords.json"
PBKDF2_ITERATIONS = 480000 # Recommended iterations for PBKDF2 (NIST recommendation)

def calculate_entropy(password):
    """
    Calculates the Shannon entropy of a password in bits.
    Entropy = L * log2(R)
    L = length of the password
    R = size of the character set (charset_size)
    """
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26  # lowercase letters
    if any(c.isupper() for c in password):
        charset_size += 26  # uppercase letters
    if any(c.isdigit() for c in password):
        charset_size += 10  # digits
    if any(c in string.punctuation for c in password):
        charset_size += 32  # common punctuation (approx)

    if charset_size == 0:
        return 0  # No known character types, entropy is 0

    password_length = len(password)
    if password_length == 0:
        return 0

    entropy = password_length * math.log2(charset_size)
    return entropy

def format_time(seconds):
    """
    Formats a duration in seconds into a human-readable string.
    """
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.2f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.2f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.2f} days"
    years = days / 365.25 # Account for leap years
    if years < 100:
        return f"{years:.2f} years"
    centuries = years / 100
    return f"{centuries:.2f} centuries"

def estimate_ai_guess_time(entropy_bits, guesses_per_second=AI_GUESSES_PER_SECOND):
    """
    Estimates the time it would take for an AI to guess a password
    based on its entropy and the AI's guessing rate.
    """
    if entropy_bits == 0:
        return "Instantly (0 entropy)"

    keyspace_size = 2**entropy_bits
    time_in_seconds = keyspace_size / guesses_per_second

    return format_time(time_in_seconds)

def check_password_strength(password):
    """
    Checks the strength of a password and provides feedback.
    """
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = 0
    feedback = []

    if length >= 12:
        score += 2
        feedback.append("Good length.")
    elif length >= 8:
        score += 1
        feedback.append("Moderate length. Consider making it longer.")
    else:
        feedback.append("Too short. Aim for at least 8-12 characters.")

    if has_lower:
        score += 1
    else:
        feedback.append("Add lowercase letters.")
    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters.")
    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers.")
    if has_symbol:
        score += 1
    else:
        feedback.append("Add special characters (e.g., !@#$%^&*).")

    unique_chars = len(set(password))
    if unique_chars < length / 2 and length > 0: # Avoid division by zero for empty password
        feedback.append("Contains too many repeated characters.")
        score -= 1

    if score >= 5:
        strength = "Very Strong"
    elif score >= 3:
        strength = "Strong"
    elif score >= 1:
        strength = "Moderate"
    else:
        strength = "Weak"

    return strength, feedback, score

def generate_strong_password(length=16):
    """
    Generates a strong, random password.
    Ensures at least one of each character type if length allows.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 to include all character types.")

    characters = string.ascii_letters + string.digits + string.punctuation
    password = []

    # Ensure at least one of each type
    password.append(random.choice(string.ascii_lowercase))
    password.append(random.choice(string.ascii_uppercase))
    password.append(random.choice(string.digits))
    password.append(random.choice(string.punctuation))

    # Fill the rest of the length with random characters from the full set
    for _ in range(length - 4):
        password.append(random.choice(characters))

    random.shuffle(password) # Shuffle to randomize order
    return "".join(password)

# --- Password Manager Functions ---

def derive_key(master_password, salt):
    """
    Derives a cryptographic key from the master password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key length
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def load_passwords(master_password):
    """
    Loads encrypted passwords from the file, decrypts them, and returns them.
    Returns an empty dictionary if the file doesn't exist or decryption fails.
    """
    if not os.path.exists(PASSWORD_FILE):
        return {}

    try:
        with open(PASSWORD_FILE, 'r') as f:
            encrypted_data = json.load(f)

        salt = base64.b64decode(encrypted_data['salt'])
        key = derive_key(master_password, salt)
        f = Fernet(key)

        decrypted_passwords = {}
        for service, encrypted_entry in encrypted_data['passwords'].items():
            # Decrypt each field separately
            decrypted_username = f.decrypt(encrypted_entry['username'].encode()).decode()
            decrypted_password = f.decrypt(encrypted_entry['password'].encode()).decode()
            decrypted_passwords[service] = {
                'username': decrypted_username,
                'password': decrypted_password
            }
        return decrypted_passwords
    except Exception as e:
        print(f"Error loading or decrypting passwords: {e}")
        print("Please ensure your master password is correct or the file is not corrupted.")
        return {}

def save_passwords(master_password, passwords_data):
    """
    Encrypts the passwords and saves them to the file.
    """
    # If file doesn't exist, generate a new salt. Otherwise, try to load existing salt.
    salt = None
    if os.path.exists(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, 'r') as f:
                existing_data = json.load(f)
                salt = base64.b64decode(existing_data.get('salt'))
        except json.JSONDecodeError:
            print("Warning: Existing password file is corrupted. Generating new salt.")
            salt = None # Force new salt if corrupted

    if salt is None:
        salt = os.urandom(16) # Generate a new salt if not found or corrupted

    key = derive_key(master_password, salt)
    f = Fernet(key)

    encrypted_passwords = {}
    for service, entry in passwords_data.items():
        encrypted_username = f.encrypt(entry['username'].encode()).decode()
        encrypted_password = f.encrypt(entry['password'].encode()).decode()
        encrypted_passwords[service] = {
            'username': encrypted_username,
            'password': encrypted_password
        }

    data_to_save = {
        'salt': base64.b64encode(salt).decode(),
        'passwords': encrypted_passwords
    }

    try:
        with open(PASSWORD_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        print("Passwords saved successfully (encrypted).")
    except Exception as e:
        print(f"Error saving passwords: {e}")

def get_master_password():
    """
    Prompts the user for the master password securely.
    """
    while True:
        master_password = input("Enter your master password: ")
        if not master_password:
            print("Master password cannot be empty.")
        else:
            return master_password

def add_password_entry(master_password):
    """
    Adds a new password entry to the manager.
    """
    passwords = load_passwords(master_password)
    service = input("Enter service name (e.g., Google, Facebook): ").strip()
    username = input("Enter username/email: ").strip()
    password = input("Enter password: ").strip()

    if not service or not username or not password:
        print("Service, username, and password cannot be empty.")
        return

    passwords[service] = {'username': username, 'password': password}
    save_passwords(master_password, passwords)
    print(f"Password for '{service}' added.")

def retrieve_password_entry(master_password):
    """
    Retrieves and displays a password entry.
    """
    passwords = load_passwords(master_password)
    if not passwords:
        print("No passwords stored or failed to load.")
        return

    service = input("Enter service name to retrieve: ").strip()
    if service in passwords:
        entry = passwords[service]
        print(f"\n--- Details for '{service}' ---")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
        print("----------------------------")
    else:
        print(f"No entry found for service '{service}'.")

def list_password_entries(master_password):
    """
    Lists all stored service names.
    """
    passwords = load_passwords(master_password)
    if not passwords:
        print("No passwords stored or failed to load.")
        return

    print("\n--- Stored Services ---")
    if passwords:
        for service in passwords.keys():
            print(f"- {service}")
    else:
        print("No passwords currently stored.")
    print("-----------------------")

def delete_password_entry(master_password):
    """
    Deletes a password entry.
    """
    passwords = load_passwords(master_password)
    if not passwords:
        print("No passwords stored or failed to load.")
        return

    service = input("Enter service name to delete: ").strip()
    if service in passwords:
        del passwords[service]
        save_passwords(master_password, passwords)
        print(f"Password for '{service}' deleted.")
    else:
        print(f"No entry found for service '{service}'.")

def main():
    """
    Main function to run the password strength checker, generator, and manager.
    """
    print("--- Password Security Suite ---")

    # Master password handling for the session
    current_master_password = None

    while True:
        print("\n--- Main Menu ---")
        print("1. Check Password Strength & AI Guessing Time")
        print("2. Generate Strong Password")
        print("3. Password Manager (Requires Master Password)")
        print("4. Set/Change Master Password (for current session)")
        print("5. Quit")

        choice = input("Enter your choice (1-5): ").strip()

        if choice == '1':
            password_to_check = input("Enter the password to check: ")
            strength, feedback, score = check_password_strength(password_to_check)
            entropy = calculate_entropy(password_to_check)
            ai_guess_time = estimate_ai_guess_time(entropy)

            print(f"\n--- Password Analysis for '{password_to_check}' ---")
            print(f"Strength: {strength} (Score: {score}/5)")
            print(f"Entropy: {entropy:.2f} bits")
            print(f"Estimated AI Guessing Time (at {AI_GUESSES_PER_SECOND / 10**12:.0f} trillion guesses/sec): {ai_guess_time}")
            print("\nFeedback:")
            if feedback:
                for item in feedback:
                    print(f"- {item}")
            else:
                print("- Looks good!")

            print("\n--- Important Note on AI Guessing Time ---")
            print("This estimation assumes a highly powerful AI performing a brute-force attack.")
            print("Actual guessing time can vary greatly based on the AI's sophistication,")
            print("available computational resources, and the type of attack (e.g., dictionary,")
            print("credential stuffing, or pre-computed rainbow tables can be much faster for weak passwords).")
            print("High entropy is crucial for resisting brute-force attacks.")

        elif choice == '2':
            try:
                gen_length = int(input("Enter desired password length (e.g., 16): "))
                generated_password = generate_strong_password(gen_length)
                entropy = calculate_entropy(generated_password)
                ai_guess_time = estimate_ai_guess_time(entropy)

                print(f"\n--- Generated Strong Password ---")
                print(f"Password: {generated_password}")
                print(f"Length: {len(generated_password)}")
                print(f"Entropy: {entropy:.2f} bits")
                print(f"Estimated AI Guessing Time: {ai_guess_time}")
                print("\nRemember to store your password securely and never reuse it!")
            except ValueError as e:
                print(f"Error: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        elif choice == '3':
            if current_master_password is None:
                print("\nYou need to set/enter your master password first (Option 4).")
                continue

            while True:
                print("\n--- Password Manager Menu ---")
                print("a. Add New Password")
                print("b. Retrieve Password")
                print("c. List All Services")
                print("d. Delete Password")
                print("e. Back to Main Menu")

                pm_choice = input("Enter your choice (a-e): ").strip().lower()

                if pm_choice == 'a':
                    add_password_entry(current_master_password)
                elif pm_choice == 'b':
                    retrieve_password_entry(current_master_password)
                elif pm_choice == 'c':
                    list_password_entries(current_master_password)
                elif pm_choice == 'd':
                    delete_password_entry(current_master_password)
                elif pm_choice == 'e':
                    break
                else:
                    print("Invalid choice. Please enter a-e.")

        elif choice == '4':
            print("\n--- Set/Change Master Password ---")
            print("WARNING: If you change your master password, you will NOT be able to access")
            print("passwords encrypted with the old master password. This only sets the master")
            print("password for the current session and for new saves.")
            new_master_password = get_master_password()
            confirm_master_password = input("Confirm your master password: ")
            if new_master_password == confirm_master_password:
                current_master_password = new_master_password
                print("Master password set for the current session.")
            else:
                print("Master passwords do not match. Please try again.")

        elif choice == '5':
            print("Exiting. Stay secure!")
            break
        else:
            print("Invalid choice. Please enter 1-5.")

if __name__ == "__main__":
    main()

