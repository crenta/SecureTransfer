#!/usr/bin/env python3
import socket, secrets, shutil, os, string, base64, time
from pathlib import Path
import tkinter as tk
from tkinter import simpledialog, messagebox, Label, Entry, Button, StringVar
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
import ipaddress
import datetime
import sys
import ssl

# --- Function to create and manage the combined input window ---
def get_ip_and_auth_code(root):
    result = {"ip": None, "auth_code": None, "cancelled": False}

    dialog = tk.Toplevel(root)
    dialog.title("Send Folder (mTLS) - Connection")

    # --- Variables to hold input ---
    ip_var = StringVar()
    auth_var = StringVar()

    # --- Submit Logic ---
    def on_submit(event=None):
        ip_input = ip_var.get().strip()
        auth_input = auth_var.get().strip()
        validated_ip = None
        validated_auth = None

        # Validate IP
        if not ip_input:
            messagebox.showerror("Input Error", "Target IP cannot be empty.", parent=dialog)
            return

        ip_input_lower = ip_input.lower()
        if ip_input_lower == "test":
              validated_ip = "test"
              # No auth code needed for test mode
        else:
            try:
                # Validate format, but don't require it to be *this* machine's IP
                ipaddress.ip_address(ip_input)
                validated_ip = ip_input # Store the original casing if it's a valid IP
            except ValueError:
                messagebox.showerror("Input Error", f"'{ip_input}' is not a valid IP address format (like 192.168.1.1) or 'test'.", parent=dialog)
                ip_entry.focus() # Keep focus on IP entry after error
                return # Stay in dialog if IP is invalid

        # Validate Auth Code (only if IP is not "test")
        if validated_ip != "test":
            if not auth_input:
                 messagebox.showerror("Input Error", "Auth code cannot be empty when IP is specified.", parent=dialog)
                 auth_entry.focus() # Keep focus on Auth entry
                 return
            if len(auth_input) == 4 and auth_input.isdigit():
                validated_auth = auth_input
            else:
                messagebox.showerror("Input Error", "Auth code must be exactly 4 digits (0-9).", parent=dialog)
                auth_entry.focus() # Keep focus on Auth entry
                return # Stay in dialog if auth code is invalid

        # If all validations passed
        result["ip"] = validated_ip
        result["auth_code"] = validated_auth
        dialog.destroy()

    # --- Cancel Logic ---
    def on_cancel():
        result["cancelled"] = True
        dialog.destroy()

    dialog.protocol("WM_DELETE_WINDOW", on_cancel) # Handle closing window

    # --- Create Widgets ---
    Label(dialog, text="Target IP (or 'test'):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ip_entry = Entry(dialog, textvariable=ip_var, width=30)
    ip_entry.grid(row=0, column=1, padx=5, pady=5)

    Label(dialog, text="4-digit Auth Code:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    auth_entry = Entry(dialog, textvariable=auth_var, width=10)
    auth_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

    # Frame for buttons
    button_frame = tk.Frame(dialog)
    button_frame.grid(row=2, column=0, columnspan=2, pady=10)

    submit_button = Button(button_frame, text="Submit", command=on_submit, width=10)
    submit_button.pack(side=tk.LEFT, padx=10)

    cancel_button = Button(button_frame, text="Cancel", command=on_cancel, width=10)
    cancel_button.pack(side=tk.RIGHT, padx=10)

    # Bind the Enter key (<Return>) to the entry fields ---
    ip_entry.bind('<Return>', on_submit)
    auth_entry.bind('<Return>', on_submit)

    # Make modal and wait
    ip_entry.focus()
    dialog.grab_set()
    dialog.wait_window()

    return result

# ======================================
# --- Certificate Generation Function (for Sender) ---
# ======================================
def generate_self_signed_cert(cert_path, key_path, common_name="SecureSenderClient"):
    """Generates a self-signed certificate and private key if they don't exist."""
    if cert_path.exists() and key_path.exists():
        print(f"Using existing sender certificate ({cert_path.name}) and key ({key_path.name})")
        return True

    print(f"Generating new self-signed sender certificate (CN={common_name})...")
    try:
        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"Sender private key saved to: {key_path}")

        # Create certificate subject/issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureSender"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Build certificate
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension( # Basic constraints typical for end-entity certs
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256()) # Sign

        # Save certificate
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"Sender certificate saved to: {cert_path}")
        print("\nIMPORTANT: Share the 'sender_cert.pem' file with the RECEIVER securely!\n")
        time.sleep(2)
        return True

    except ImportError:
         messagebox.showerror("Missing Dependency", "The 'cryptography' library is needed for certificate generation.")
         return False
    except Exception as e:
        messagebox.showerror("Certificate Generation Failed", f"Could not generate sender TLS certificate/key:\n{e}")
        return False

# ======================================
# --- Main Script Logic Starts Here ---
# ======================================

# GUI root hidden
root = tk.Tk()
root.withdraw()

# Determine base path
if getattr(sys, 'frozen', False):
    base = Path(sys.executable).parent
else:
    base = Path(__file__).parent

# --- Define File Paths ---
SEND_FOLDER = base / "SEND_FOLDER"
KEY_FILE_DECRYPT = base / "KEY.txt"
ZIP_FILENAME_BASE = "SECURE_SENDER"
ZIP_PATH = base / f"{ZIP_FILENAME_BASE}.zip"
ENC_PATH = base / f"{ZIP_FILENAME_BASE}.enc"
TEST_SEND = base / "TEST_SEND" # For test mode

# --- TLS Configuration & Paths ---
TLS_PORT = 12346 # Must match receiver
RECEIVER_CERT_FILE = base / "receiver_cert.pem" # Receiver's public cert (sender needs this)
SENDER_CERT_FILE = base / "sender_cert.pem"     # Sender's public cert
SENDER_KEY_FILE = base / "sender_key.pem"      # Sender's private key

# --- Generate/Check Sender Certificates ---
if not generate_self_signed_cert(SENDER_CERT_FILE, SENDER_KEY_FILE):
    messagebox.showerror("TLS Setup Error", "Failed to generate or find sender TLS certificate/key. Cannot start sender.")
    sys.exit(1)

# --- Get IP and Auth Code ---
connection_details = get_ip_and_auth_code(root)

if connection_details["cancelled"]:
    messagebox.showerror("Cancelled", "Operation cancelled.")
    sys.exit(1)
target_ip = connection_details["ip"]
auth_code = connection_details["auth_code"]
if not target_ip:
     messagebox.showerror("Error", "Failed to get connection details.")
     sys.exit(1)

# --- Ensure SEND_FOLDER exists ---
if not SEND_FOLDER.exists():
    SEND_FOLDER.mkdir(); messagebox.showinfo("Info", f"'{SEND_FOLDER.name}/' created. Add files and run again."); sys.exit(0)
if not any(SEND_FOLDER.iterdir()):
     messagebox.showwarning("Empty Folder", f"'{SEND_FOLDER.name}' is empty. No files to send."); sys.exit(0)

# --- Application Key Generation & Encryption ---
if KEY_FILE_DECRYPT.exists(): KEY_FILE_DECRYPT.unlink()
raw_key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
decryption_code = '-'.join(raw_key[i:i+4] for i in range(0, 16, 4))
#KEY_FILE_DECRYPT.write_text(decryption_code)
salt = secrets.token_bytes(16)
def derive_key(code: str, salt: bytes) -> bytes:
    clean = code.replace('-', ''); kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return base64.urlsafe_b64encode(kdf.derive(clean.encode()))
key = derive_key(decryption_code, salt); cipher = Fernet(key)
messagebox.showinfo("Send Folder - Decryption Key",
                    f"Share this DECRYPTION key with receiver:\n\n{decryption_code}\n\n(Saved to {KEY_FILE_DECRYPT.name})")
try:
    print("Zipping folder..."); shutil.make_archive(str(base / ZIP_FILENAME_BASE), 'zip', SEND_FOLDER); print("Zipping complete.")
except Exception as e:
    if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True); messagebox.showerror("Error", f"Failed to zip folder:\n{e}"); sys.exit(1)
try:
    print("Encrypting file..."); ciphertext = cipher.encrypt(ZIP_PATH.read_bytes()); ENC_PATH.write_bytes(salt + ciphertext); print("Encryption complete.")
finally:
    if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True)


# --- TEST MODE ---
if target_ip == "test":
    # (Test mode doesn't test mTLS)
    TEST_SEND.mkdir(exist_ok=True)
    try:
        shutil.copy(ENC_PATH, TEST_SEND / ENC_PATH.name)
        messagebox.showinfo("Test Mode", f"Encrypted file copied to '{TEST_SEND.resolve()}'")
    except Exception as e:
         messagebox.showerror("Test Mode Error", f"Failed to copy file: {e}")
    finally:
        if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)
    sys.exit(0)

# --- Check for REQUIRED Receiver Certificate ---
if not RECEIVER_CERT_FILE.is_file():
    messagebox.showerror("TLS Error", f"Receiver certificate not found at:\n{RECEIVER_CERT_FILE}\n\nPlease obtain the receiver's certificate ('receiver_cert.pem') and place it here.")
    if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)
    sys.exit(1)

# --- Send encrypted file (Actual Send with mTLS) ---
context = None
secure_sock = None

try:
    # --- Create SSL Context for mTLS Client ---
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True # Verify receiver's hostname/IP in cert
    context.verify_mode = ssl.CERT_REQUIRED # Require receiver cert validation

    # 1. Load CA cert to verify the RECEIVER
    print(f"Loading receiver certificate for verification from: {RECEIVER_CERT_FILE}")
    context.load_verify_locations(cafile=RECEIVER_CERT_FILE)

    # 2. Load sender's own cert/key to present for client authentication
    print(f"Loading sender certificate ({SENDER_CERT_FILE.name}) and key ({SENDER_KEY_FILE.name}) for client authentication")
    context.load_cert_chain(certfile=SENDER_CERT_FILE, keyfile=SENDER_KEY_FILE)

    print(f"Attempting mTLS connection to {target_ip}:{TLS_PORT}...")
    with socket.create_connection((target_ip, TLS_PORT), timeout=25) as sock:
        print(f"Wrapping socket for mTLS, expecting server hostname/IP: {target_ip}")
        # server_hostname MUST match CN or SAN in receiver's certificate
        with context.wrap_socket(sock, server_hostname=target_ip) as secure_sock:
            print("mTLS connection established successfully.")
            receiver_cert = secure_sock.getpeercert() # Get receiver's cert info
            print(f"Receiver certificate subject: {dict(x[0] for x in receiver_cert.get('subject', []))}")
            print(f"Cipher used: {secure_sock.cipher()}")
            print(f"TLS protocol version: {secure_sock.version()}")

            # --- Authentication (4-digit code) AFTER mTLS Handshake ---
            print(f"Sending authentication code: {auth_code}")
            secure_sock.sendall(auth_code.encode('utf-8'))

            # --- Receive Authentication Confirmation ---
            print("Waiting for authentication confirmation from receiver...")
            confirmation = secure_sock.recv(4).decode('utf-8').strip()
            if confirmation != "OK":
                 messagebox.showerror("Authentication Failed", f"Receiver rejected the authentication code.\nReceived: {confirmation}")
                 raise ConnectionRefusedError("Authentication failed by receiver")

            print("Authentication successful.")
            # --- Send Encrypted File Data ---
            print("Sending encrypted file data...")
            with open(ENC_PATH, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: break
                    secure_sock.sendall(chunk)
            print("File data sent successfully.")

    messagebox.showinfo("Done", f"Encrypted file successfully sent to {target_ip} via mTLS!\nDecryption key saved to {KEY_FILE_DECRYPT.name}.")

# --- Specific Exception Handling ---
except FileNotFoundError as e:
     # Catch missing ENC_PATH or potentially missing cert/key if checks failed somehow
     messagebox.showerror("File Error", f"Required file not found: {e}")
     sys.exit(1)
except ssl.SSLCertVerificationError as e:
    # Error verifying the RECEIVER's certificate
    messagebox.showerror("TLS Verification Error", f"Could not verify the RECEIVER's certificate:\n{e}\n\n- Ensure '{RECEIVER_CERT_FILE.name}' is the correct certificate for {target_ip}.\n- Ensure the certificate hasn't expired and its CN/SAN matches '{target_ip}'.")
    sys.exit(1)
except ssl.SSLError as e:
    # General SSL errors during handshake (could be cert loading, protocol mismatch, receiver rejecting sender cert, etc.)
    error_details = str(e)
    msg = f"A TLS/SSL error occurred during connection:\n{error_details}\n\n"
    if "certificate verify failed" in error_details or "CERTIFICATE_VERIFY_FAILED" in error_details:
         msg += "- The RECEIVER likely rejected YOUR sender certificate.\n  Ensure the receiver trusts '{SENDER_CERT_FILE.name}'.\n"
    elif "dh key too small" in error_details or "bad dh p length" in error_details:
         msg += "- Diffie-Hellman key agreement error. May indicate issue on receiver side or network interference.\n"
    elif "No certificate returned" in error_details:
         msg += "- The receiver did not return a certificate, but one was expected.\n"
    else: # General advice
         msg += "- Ensure receiver is running, expecting mTLS on port {TLS_PORT}.\n- Check firewalls on both ends for port {TLS_PORT}.\n- Ensure compatible TLS versions/settings.\n- Verify both sender and receiver certificates are correctly loaded and trusted by the other party."
    messagebox.showerror("mTLS Handshake Error", msg)
    sys.exit(1)
except socket.timeout:
    messagebox.showerror("Transfer Failed", f"Connection to {target_ip}:{TLS_PORT} timed out.\n- Check IP/port.\n- Ensure receiver is running and waiting for an mTLS connection.\n- Check firewalls/network.")
    sys.exit(1)
except socket.gaierror as e:
     messagebox.showerror("Transfer Failed", f"Could not resolve host: {target_ip}\nError: {e}\nCheck the IP address.")
     sys.exit(1)
except ConnectionRefusedError as e:
    msg = f"Connection refused by {target_ip}:{TLS_PORT}."
    if "Authentication failed" in str(e): # Catch our custom auth failure
        msg = f"Authentication Failed: Receiver at {target_ip}:{TLS_PORT} rejected the 4-digit code."
    else: # Standard connection refused
        msg += f"\n- Ensure receiver script is running and expecting mTLS on port {TLS_PORT}.\n- Check firewall allows port {TLS_PORT}."
    messagebox.showerror("Transfer Failed", msg)
    sys.exit(1)
except ConnectionResetError:
     messagebox.showerror("Transfer Failed", f"Connection reset by {target_ip}:{TLS_PORT}.\nReceiver might have cancelled, crashed, or had a TLS error after connecting.")
     sys.exit(1)
except Exception as e:
    messagebox.showerror("Transfer Failed", f"An unexpected error occurred:\n{type(e).__name__}: {e}")
    sys.exit(1)
finally:
    # Clean up the encrypted file
    if ENC_PATH.exists():
        try:
            ENC_PATH.unlink()
            print(f"Cleaned up temporary file: {ENC_PATH}")
        except OSError as e:
            print(f"Warning: Could not delete temporary file {ENC_PATH}: {e}")