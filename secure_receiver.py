#!/usr/bin/env python3
import socket, base64, os, zipfile, sys, threading, secrets, time
from pathlib import Path
import tkinter as tk
from tkinter import simpledialog, messagebox, Label, Entry, Button, StringVar
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet, InvalidToken
import ipaddress
import datetime
import sys, os, subprocess
import ssl
import queue
import traceback

# --- Virtual Environment Handling ---
if not getattr(sys, 'frozen', False):
    def in_venv(): return (hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))
    if not in_venv():
        venv_dir = os.path.join(os.path.dirname(__file__), "venv")
        if not os.path.exists(venv_dir): print("Creating virtual environment..."); subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
        if os.name == "nt": python_bin = os.path.join(venv_dir, "Scripts", "python.exe")
        else: python_bin = os.path.join(venv_dir, "bin", "python")
        subprocess.check_call([python_bin, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([python_bin, "-m", "pip", "install", "cryptography"])
        print("Restarting script in virtual environment...")
        os.execv(python_bin, [python_bin] + sys.argv)
print("Running inside virtual environment!")

# --- Function to attempt finding the local IP ---
def get_local_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        print(f"Detected local IP: {ip}")
        return ip
    except Exception as e:
        print(f"Warning: Could not automatically detect local IP: {e}")
        return "0.0.0.0"
    finally:
        if s: s.close()

# --- Configuration ---
if getattr(sys, 'frozen', False):
    base_dir = Path(sys.executable).parent
else:
    base_dir = Path(__file__).parent

desktop = Path(os.path.expanduser("~/Desktop"))
received_folder = desktop / "received_folder"
received_folder.mkdir(exist_ok=True)

# --- TLS Configuration ---
TLS_PORT = 12346
CERT_FILE = base_dir / "receiver_cert.pem"      # Receiver's own public cert
KEY_FILE = base_dir / "receiver_key.pem"       # Receiver's own private key
SENDER_CERT_FILE_TRUSTED = base_dir / "sender_cert.pem" # Sender's public cert (receiver needs this to verify sender)
# ============================

# --- Certificate Generation Function ---
def generate_self_signed_cert(cert_path, key_path, ip_address_str):
    if cert_path.exists() and key_path.exists():
        print(f"Using existing receiver certificate ({cert_path.name}) and key ({key_path.name})")
        return True

    print(f"Generating new self-signed receiver certificate for IP: {ip_address_str}...")
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048 # 2048 is generally sufficient, 4096 is more secure but slower
        )

        # Save private key
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption() # No password on key file
            ))
        print(f"Receiver private key saved to: {key_path}")

        # Create certificate subject and issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"), # Optional
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"), # Optional
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureReceiver"), # Optional
            # Use IP address in Common Name (CN) OR preferably Subject Alternative Name (SAN)
            # x509.NameAttribute(NameOID.COMMON_NAME, ip_address_str)
        ])

        # Build certificate
        cert_builder = x509.CertificateBuilder().subject_name(
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
            # Set validity period (e.g., 1 year)
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )

        # --- Add Subject Alternative Name (SAN) for IP Address ---
        try:
            ip_addr_obj = ipaddress.ip_address(ip_address_str)
            san_extension = x509.SubjectAlternativeName([x509.IPAddress(ip_addr_obj)])
            cert_builder = cert_builder.add_extension(san_extension, critical=False)
            print(f"Added IP Address {ip_address_str} to Subject Alternative Name (SAN)")
        except ValueError:
            # If IP is '0.0.0.0' or invalid, use Common Name as fallback (less ideal)
            print(f"Warning: Could not create SAN for IP '{ip_address_str}'. Falling back to CN (less recommended for IP verification).")
            # Common Name if SAN failed
            subject = x509.Name(list(subject) + [x509.NameAttribute(NameOID.COMMON_NAME, ip_address_str)])
            cert_builder = cert_builder.subject_name(subject)
        # Add basic constraints
        cert_builder = cert_builder.add_extension(
                     x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )


        # Sign the certificate with the private key
        certificate = cert_builder.sign(private_key, hashes.SHA256())

        # Save certificate
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"Receiver certificate saved to: {cert_path}")
        print("\nIMPORTANT: Share the 'receiver_cert.pem' file with the SENDER securely!\n")
        time.sleep(2) # Give user time to read the message
        return True

    except ImportError:
        messagebox.showerror("Missing Dependency", "The 'cryptography' library is needed for certificate generation.\nPlease ensure it's installed (should happen automatically in venv).")
        return False
    except Exception as e:
        messagebox.showerror("Certificate Generation Failed", f"Could not generate receiver TLS certificate/key:\n{e}")
        return False
# --- END Certificate Generation Function ---


# Get Local IP, Generate Certs, Check Sender Cert, Get Decryption Key/Auth Code
root = tk.Tk()
root.withdraw() # Hide the main root window

# Determine IP to bind to
bind_ip = get_local_ip()
is_specific_ip = bind_ip != "0.0.0.0"

# --- Generate/Check Receiver Certificates ---
if not generate_self_signed_cert(CERT_FILE, KEY_FILE, bind_ip):
     messagebox.showerror("TLS Setup Error", "Failed to generate or find receiver TLS certificate/key. Cannot start receiver.")
     sys.exit(1)

# --- Check for REQUIRED Trusted Sender Certificate ---
if not SENDER_CERT_FILE_TRUSTED.is_file():
    messagebox.showerror("mTLS Setup Error", f"Trusted sender certificate not found at:\n{SENDER_CERT_FILE_TRUSTED}\n\nPlease obtain the sender's public certificate ('{SENDER_CERT_FILE_TRUSTED.name}') and place it here.")
    sys.exit(1)
else:
    print(f"Found trusted sender certificate to verify clients: {SENDER_CERT_FILE_TRUSTED.name}")


# Generate AUTH code
generated_auth_code = "{:04d}".format(secrets.randbelow(10000))
print(f"Generated Auth Code (for sender): {generated_auth_code}")

decryption_code = None

# --- Functions for key input window (validate_key_input, on_submit) ---
def validate_key_input(event=None):
    cursor_pos = entry.index(tk.INSERT); raw = code_var.get().upper()
    cleaned = ''.join(c for c in raw if c.isalnum())[:16]
    formatted = '-'.join(cleaned[i:i+4] for i in range(0, len(cleaned), 4))
    code_var.set(formatted); diff = len(formatted) - len(raw)
    entry.icursor(cursor_pos + diff if diff != 0 else cursor_pos)
def on_submit(event=None):
    raw = entry.get().strip().upper(); cleaned = ''.join(c for c in raw if c.isalnum()).upper()
    if len(cleaned) != 16: messagebox.showerror("Invalid Key", "Decryption key must be exactly 16 alphanumeric characters."); return
    global decryption_code; decryption_code = '-'.join(cleaned[i:i+4] for i in range(0, 16, 4))
    key_window.destroy()


# --- Create the COMBINED window ---
key_window = tk.Toplevel(root) # Make it a Toplevel owned by the hidden root
key_window.title("Receive Folder (mTLS Enabled) - Auth / Key")
key_window.geometry("480x340") # Wider/taller for more info

# Display info
auth_label_text = (
    f"Receiver Ready (Mutual TLS Enabled):\n\n"
    f"1. Share your certificate '{CERT_FILE.name}' with the sender.\n"
    f"2. Ensure sender's certificate '{SENDER_CERT_FILE_TRUSTED.name}' is placed here.\n\n"
    f"3. Tell the Sender this Connection Info:\n"
    f"   Your IP Address:     {bind_ip}\n"
    f"   CONNECTION PORT:   {TLS_PORT}\n"
    f"   4-digit AUTH Code:   {generated_auth_code}\n\n"
    f"(Verify IP is correct for your network if needed)"
)
tk.Label(key_window, text=auth_label_text, font=("Arial", 10, "bold"), justify="left").pack(pady=(10, 5), padx=10)

tk.Label(key_window, text="-"*65).pack() # Separator

# Ask for Decryption key below
tk.Label(key_window, text="4. Enter the 16-character DECRYPTION key\n(once received from sender):", font=("Arial", 10)).pack(pady=(5, 0))
code_var = tk.StringVar()
entry = tk.Entry(key_window, textvariable=code_var, font=("Courier", 16), width=23, justify="center")
entry.pack(pady=5)
entry.bind('<KeyRelease>', validate_key_input)
entry.bind('<Return>', on_submit)

submit_button = tk.Button(key_window, text="Submit Decryption Key & Start Listening", command=on_submit)
submit_button.pack(pady=(5, 10))

entry.focus()
key_window.grab_set()
root.wait_window(key_window) # Wait for this window to close

# Check if Decryption Key was provided
if not decryption_code:
    messagebox.showerror("Cancelled", "No decryption code provided or window closed.")
    sys.exit(1)
print(f"Decryption key received: {decryption_code}. Proceeding to listen...")


# ------------ Define file paths ---------------
ENC_FILENAME_BASE = "SECURE_SENDER"
ENC_PATH = received_folder / f"{ENC_FILENAME_BASE}.enc"
ZIP_PATH = received_folder / f"{ENC_FILENAME_BASE}.zip"

# ----------- Socket Listener & Authentication (mTLS Enabled) ------------
cancelled = False
authenticated_connection = None # Will hold the SECURE socket
listener_socket = None
status_window = None

# --- Listener Function ---
def listen_for_connection(gui_q):
    global authenticated_connection, cancelled, listener_socket # Access globals
    secure_conn = None
    plain_conn = None
    addr = None

    # --- Create SSL Context for mTLS Server ---
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        # Load receiver's own cert/key
        print(f"Loading receiver TLS certificate ({CERT_FILE.name}) and key ({KEY_FILE.name})")
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        # Configure client certificate verification
        print(f"Configuring TLS to REQUIRE client certificate verification.")
        context.verify_mode = ssl.CERT_REQUIRED
        print(f"Loading trusted sender certificate ({SENDER_CERT_FILE_TRUSTED.name}) for client verification")
        context.load_verify_locations(cafile=SENDER_CERT_FILE_TRUSTED) # Trust sender's cert

    except ssl.SSLError as e:
        error_msg = f"TLS Error: Failed to load certificates/key or configure context:\n{e}\n\n{traceback.format_exc()}"
        print(error_msg)
        gui_q.put(("ERROR", error_msg))
        return # Fatal error, exit thread
    except FileNotFoundError as e:
        error_msg = f"TLS Error: Certificate or key file not found:\n{e}\n\n{traceback.format_exc()}"
        print(error_msg)
        gui_q.put(("ERROR", error_msg))
        return # Fatal error, exit thread
    except Exception as e: # Catch any other setup error
        error_msg = f"TLS Setup Error: An unexpected error occurred during context setup:\n{e}\n\n{traceback.format_exc()}"
        print(error_msg)
        gui_q.put(("ERROR", error_msg))
        return # Fatal error, exit thread


    # --- Setup Listener Socket ---
    # Use a local variable first, assign to global listener_socket only if successful
    local_listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        local_listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_listener_socket.bind((bind_ip, TLS_PORT))
        local_listener_socket.listen(1)
        local_listener_socket.settimeout(1.0) # Timeout for accept()
        listener_socket = local_listener_socket # Assign to global now bind/listen succeeded
        print(f"mTLS Listener started on {bind_ip}:{TLS_PORT}. Waiting for connection...")
        print(f"(Expecting Auth Code: {generated_auth_code} AFTER successful mTLS handshake)")

    except OSError as e:
        # Error during bind/listen is fatal for the listener
        error_msg = f"Listener Error: Could not start listener on {bind_ip}:{TLS_PORT}.\nError: {e}\n\n{traceback.format_exc()}"
        print(error_msg)
        gui_q.put(("ERROR", error_msg))
        local_listener_socket.close()
        return # Fatal error, exit thread
    except Exception as e:
        # Catch any other listener setup error
        error_msg = f"Listener Setup Error: An unexpected error occurred during listener setup:\n{e}\n\n{traceback.format_exc()}"
        print(error_msg)
        gui_q.put(("ERROR", error_msg))
        local_listener_socket.close()
        return # Fatal error, exit thread

    # --- Main Listening Loop ---
    try:
        while not cancelled:
            plain_conn = None
            secure_conn = None
            try:
                # Accept Plain Connection (Blocks with timeout)
                try:
                    plain_conn, addr = listener_socket.accept()
                except socket.timeout:
                    continue # No connection attempt, just loop again
                except OSError as e:
                    # Handle cases where the socket is closed by the cancel button
                    if cancelled:
                        print("Listener socket closed by cancellation.")
                        break # Exit loop cleanly
                    else:
                        raise # Re-raise other OS errors

                plain_conn.settimeout(20) # Timeout for mTLS handshake and auth
                print(f"\nConnection attempt from {addr}")

                # Wrap Socket for mTLS (Handshake + Client Cert Verification happens here)
                print("Attempting mTLS handshake (verifying sender certificate)...")
                secure_conn = context.wrap_socket(plain_conn, server_side=True)
                # Handshake successful if no exception
                print(f"mTLS handshake successful with {addr}.")

                # Log sender cert info
                sender_cert = secure_conn.getpeercert()
                sender_subject = dict(x[0] for x in sender_cert.get('subject', [])) if sender_cert else "N/A"
                print(f"Verified Sender certificate subject: {sender_subject}")
                print(f"Cipher used: {secure_conn.cipher()}")
                print(f"TLS protocol version: {secure_conn.version()}")

                # Authenticate (4-digit code) OVER mTLS
                print("Waiting for 4-digit authentication code...")
                received_auth_code = secure_conn.recv(4) # Might raise timeout or other errors

                if not received_auth_code: # Connection closed gracefully by sender
                    print("Authentication failed: Sender disconnected before sending code.")
                    secure_conn.close()
                    continue # Wait for next connection

                received_auth_code_str = received_auth_code.decode('utf-8')
                print(f"Received auth code: '{received_auth_code_str}'")

                if received_auth_code_str == generated_auth_code:
                    print("4-Digit Code Authentication successful!")
                    secure_conn.sendall(b"OK\n") # Send confirmation
                    # SUCCESS! Put the connection object on the queue for the main thread
                    gui_q.put(("SUCCESS", secure_conn))
                    # Don't close secure_conn here, main thread needs it
                    authenticated_connection = secure_conn # Also set global for immediate check after wait_window
                    break # Exit while loop on success
                else:
                    print("4-Digit Code Authentication failed: Incorrect code.")
                    secure_conn.sendall(b"FAIL\n") # Send rejection
                    secure_conn.close()
                    continue # Wait for next connection

            # --- Handle Errors Specific to One Connection Attempt ---
            except socket.timeout:
                # Timeout during handshake or waiting for auth code
                if secure_conn: print(f"Timeout waiting for 4-digit code from {addr}.")
                elif plain_conn: print(f"Timeout during mTLS handshake with {addr}.")
                # Close sockets related to this failed attempt
                if secure_conn: secure_conn.close()
                elif plain_conn: plain_conn.close()
                continue # Wait for next connection attempt
            except ssl.SSLCertVerificationError as e:
                # Specific error for client cert failure
                 print(f"mTLS Handshake Error from {addr}: Client certificate verification failed: {e}")
                 if plain_conn: plain_conn.close() # Close plain socket, wrap failed
                 continue # Wait for next connection attempt
            except ssl.SSLError as e:
                 # This catches other TLS errors during handshake/recv
                 print(f"mTLS Handshake/Communication Error from {addr}: {e}")
                 if secure_conn: secure_conn.close()
                 elif plain_conn: plain_conn.close()
                 continue # Wait for next connection attempt
            except ConnectionResetError:
                 print(f"Connection reset by {addr} during handshake or authentication.")
                 if secure_conn: secure_conn.close()
                 elif plain_conn: plain_conn.close()
                 continue # Wait for next connection attempt
            except Exception as e:
                 # Generic error during a specific connection attempt
                 print(f"Error during connection/authentication with {addr}: {type(e).__name__}: {e}")
                 print(traceback.format_exc()) # Print traceback for debugging
                 if secure_conn: secure_conn.close()
                 elif plain_conn: plain_conn.close()
                 continue # Wait for next connection attempt

    # --- End of Main Loop (due to success, cancellation, or fatal listener error) ---
    finally:
        # Close the main listener socket IF it was successfully created
        if listener_socket:
            listener_socket.close()
            print("Listener socket closed.")
        # Put a message if the loop exited without success and wasn't cancelled
        if not authenticated_connection and not cancelled:
             # Check if an error message was already put on the queue by setup exceptions
             # If the loop breaks unexpectedly, this is a fallback.
             if gui_q.empty(): # Avoid putting extra messages if already errored out
                 gui_q.put(("CLOSED", "Listener loop exited unexpectedly without success."))

# --- Create Queue ---
gui_queue = queue.Queue()

# --- Start Listener Thread ---
listener_thread = threading.Thread(target=listen_for_connection, args=(gui_queue,), daemon=True)
listener_thread.start()

# --- Create status window ---
status_window = tk.Toplevel(root)
status_window.title("Listening (mTLS Enabled)...")
status_label_text = (
    f"Listening securely (Mutual TLS) on {bind_ip}:{TLS_PORT}\n"
    f"Using Auth Code: {generated_auth_code} (after mTLS)\n\n"
    f"(Waiting for sender...)\n"
    f"(Requires sender cert '{SENDER_CERT_FILE_TRUSTED.name}')"
)
tk.Label(status_window, text=status_label_text, justify="center").pack(padx=20, pady=10)

# --- Cancel button logic ---
def cancel_listener_from_status():
    global cancelled, listener_socket, status_window
    print("Cancel button pressed.")
    cancelled = True # Signal the thread to stop looping

    # Attempt to close the listener socket to interrupt accept()
    if listener_socket:
        try:
            listener_socket.close()
        except Exception as e:
            print(f"Minor error closing listener socket on cancel: {e}")

    # Close the status window
    try:
        if status_window and status_window.winfo_exists():
            status_window.destroy()
    except tk.TclError as e:
        print(f"Error destroying status window on cancel: {e}")

tk.Button(status_window, text="Cancel Listening", command=cancel_listener_from_status).pack(pady=10)
status_window.protocol("WM_DELETE_WINDOW", cancel_listener_from_status) # Handle window close button


# --- Function to Check the Queue (Runs in Main Thread) ---
def check_queue():
    global authenticated_connection, cancelled, status_window

    try:
        # Check queue without blocking
        message = gui_queue.get_nowait()
        msg_type, data = message

        print(f"GUI Queue received: Type={msg_type}") # Debug print

        if msg_type == "ERROR":
            messagebox.showerror("Listener Error", data)
            cancelled = True # Treat listener errors as cancellation/failure
            if status_window and status_window.winfo_exists():
                status_window.destroy()
                # status_window = None

        elif msg_type == "SUCCESS":
            authenticated_connection = data # Store the connection object
            if status_window and status_window.winfo_exists():
                status_window.destroy() # Close status window on success
                # status_window = None

        elif msg_type == "CLOSED":
             # Listener closed unexpectedly without success
             if not cancelled: # Only show error if not manually cancelled
                 messagebox.showwarning("Listener Stopped", data)
                 cancelled = True # Mark as failed/cancelled
             if status_window and status_window.winfo_exists():
                status_window.destroy()
                # status_window = None

    except queue.Empty:
        # No message, queue is empty
        pass
    except tk.TclError as e:
        # Handle cases where the status window might already be destroyed
        print(f"Tkinter error in check_queue (window likely closed): {e}")
        # Make sure cancelled is set if the window is gone but we didn't get success/error
        if not authenticated_connection and not cancelled:
            cancelled = True # Assume cancellation if window closed externally
    except Exception as e:
        # Catch unexpected errors in queue processing
        print(f"Unexpected error in check_queue: {e}")
        traceback.print_exc()
        cancelled = True
        if status_window and status_window.winfo_exists():
             status_window.destroy()
             # status_window = None


    # --- Reschedule Check ---
    # Keep checking only if the thread is running AND the window still exists
    # AND we haven't successfully connected or explicitly cancelled/errored out
    if listener_thread.is_alive() and status_window and status_window.winfo_exists() \
       and authenticated_connection is None and not cancelled:
         root.after(100, check_queue) # Check again in 100ms

# --- Center window logic ---
status_window.update_idletasks()
screen_width = status_window.winfo_screenwidth()
screen_height = status_window.winfo_screenheight()
window_width = status_window.winfo_width()
window_height = status_window.winfo_height()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
status_window.geometry(f'+{x}+{y}')
status_window.grab_set()

# --- Start the first queue check ---
root.after(100, check_queue)

# --- Wait for Status Window ---
# This blocks the main thread here. It unblocks when status_window is destroyed
# either by the cancel button or by check_queue() processing a SUCCESS/ERROR msg.
root.wait_window(status_window)


# --- Check if connection succeeded (AFTER wait_window returns) ---
if cancelled:
    print("Operation cancelled or failed while listening.")
    sys.exit(1)
if authenticated_connection is None:
    # This case might happen if the thread ends but didn't put SUCCESS/ERROR
    # Or if check_queue logic has a flaw.
    print("Error: No authenticated mTLS connection received but not cancelled.")
    messagebox.showerror("Error", "No authenticated mTLS connection received.\nCheck sender/receiver certs, IP/Port/Auth Code.\nSee console for details.")
    sys.exit(1)

print("Authenticated mTLS connection established. Proceeding with file reception...")

# Receive the Encrypted File (Over mTLS)
# (uses the secure 'authenticated_connection')
if authenticated_connection is None:
     messagebox.showerror("Internal Error", "Authenticated connection lost before file reception.")
     sys.exit(1)

try:
    with authenticated_connection: # Use the connection stored by check_queue
        authenticated_connection.settimeout(60) # Increase timeout for larger files
        print("Receiving encrypted file over mTLS...")
        bytes_received = 0
        with open(ENC_PATH, 'wb') as f:
            while True:
                try:
                    # Check if cancelled during reception
                    if cancelled:
                        raise InterruptedError("Reception cancelled by user.")
                    data = authenticated_connection.recv(4096 * 4)
                    if not data: break # Sender closed connection cleanly
                    f.write(data)
                    bytes_received += len(data)
                except socket.timeout:
                    messagebox.showerror("Error", "Timeout during file reception. Connection may be lost.")
                    raise # Re-raise to be caught by outer block
                except ssl.SSLError as e:
                    messagebox.showerror("TLS Error", f"TLS error during file reception: {e}")
                    raise # Re-raise
                except InterruptedError as e:
                    messagebox.showwarning("Cancelled", f"{e}")
                    raise # Re-raise
                except Exception as e:
                    messagebox.showerror("Reception Error", f"Error receiving data: {e}")
                    raise # Re-raise
        print(f"\nFile reception complete. Total bytes: {bytes_received}")
        if bytes_received == 0 and not cancelled:
             messagebox.showwarning("Reception Warning", f"Received 0 bytes from sender. Encrypted file '{ENC_PATH.name}' is empty.")

except InterruptedError:
     # Handle cancellation during reception
     print("File reception cancelled.")
     if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)
     sys.exit(1)
except Exception as e:
    messagebox.showerror("Reception Failed", f"An error occurred during file reception: {type(e).__name__}: {e}")
    if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)
    sys.exit(1)

# Decrypt the Received File
print("Decrypting file...")
try:
    # Check if the encrypted file exists before trying to read
    if not ENC_PATH.exists():
         if not cancelled: # Don't show error if cancelled during reception
             messagebox.showerror("Decryption Error", f"Encrypted file '{ENC_PATH.name}' not found or was deleted after reception error.")
         # Make sure zip path is also cleaned if enc is missing
         if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True)
         sys.exit(1)

    data = ENC_PATH.read_bytes()
    if len(data) < 17:
        if len(data) == 0:
            messagebox.showwarning("Decryption Skipped", f"Received encrypted file '{ENC_PATH.name}' is empty. Nothing to decrypt.")
            # Clean up empty files
            if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)
            if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True)
            messagebox.showinfo("Done", "Received an empty file. Operation finished.")
            sys.exit(0) # Exit successfully for empty file case
        else:
            raise ValueError(f"Received encrypted file '{ENC_PATH.name}' is too short ({len(data)} bytes) to be valid.")

    salt, ciphertext = data[:16], data[16:]
    clean = decryption_code.replace('-', '')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    key = base64.urlsafe_b64encode(kdf.derive(clean.encode()))
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(ciphertext)
    ZIP_PATH.write_bytes(decrypted_data)
    print("Decryption successful.")

except InvalidToken:
    messagebox.showerror("Decryption Failed", "Invalid DECRYPTION key or the received file is corrupted/incomplete.")
    if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True) # Clean up potentially bad zip
    sys.exit(1)
except ValueError as e: # Catch "too short" or other value errors
    messagebox.showerror("Decryption Failed", f"Error processing received file: {e}")
    sys.exit(1)
except Exception as e:
    messagebox.showerror("Decryption Failed", f"An unexpected error occurred during decryption: {type(e).__name__}: {e}")
    if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True)
    sys.exit(1)
finally:
    # Clean up the encrypted file after attempting decryption
    if ENC_PATH.exists(): ENC_PATH.unlink(missing_ok=True)

# Unzip the Decrypted File
if not ZIP_PATH.exists():
      messagebox.showerror("Unzip Error", f"Decrypted file '{ZIP_PATH.name}' not found. Cannot unzip.")
      sys.exit(1)

print("Unzipping file...")
try:
    with zipfile.ZipFile(ZIP_PATH, 'r') as zf:
        if not zf.namelist():
            messagebox.showwarning("Unzip Warning", f"The decrypted file '{ZIP_PATH.name}' is an empty archive.")
        else:
            zf.extractall(received_folder)
            print("Unzipping successful.")
except zipfile.BadZipFile:
     messagebox.showerror("Unzip Failed", f"The decrypted file '{ZIP_PATH.name}' is not a valid Zip archive or is corrupted.")
     sys.exit(1)
except Exception as e:
    messagebox.showerror("Unzip Failed", f"An unexpected error occurred during unzipping: {type(e).__name__}: {e}")
    sys.exit(1)
finally:
     if ZIP_PATH.exists(): ZIP_PATH.unlink(missing_ok=True) # Clean up zip file


messagebox.showinfo("Done", f"File received securely via Mutual TLS, decrypted & extracted to:\n{received_folder}")
print("Operation complete.")

root.quit()
