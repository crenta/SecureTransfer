-------------------------------------------------------
## Securely transfer files over the air with Python




--------------------------------------------------------
# Secure Sender/Receiver with mTLS and Encryption

This project provides two Python scripts (`sender.py` and `receiver.py`) for securely transferring the contents of a folder (`SEND_FOLDER`) from one machine (Sender/Host) to another (Receiver/Target) over a network.

## Features

* **Mutual TLS (mTLS):** Ensures both the sender and receiver authenticate each other using cryptographic certificates before any data transfer. Prevents spoofing and man-in-the-middle attacks (assuming initial certificate exchange is secure).
* **End-to-End Encryption:** The folder contents are zipped and then encrypted using AES (via Fernet) with a unique key for each transfer. Only someone with the decryption key can access the original files.
* **Self-Signed Certificate Generation:** The scripts automatically generate the necessary TLS certificates if they don't exist.
* **Simple Authentication Code:** An additional 4-digit code is used after the mTLS handshake as a basic confirmation step.
* **User-Friendly Prompts:** GUI dialogs guide the user through entering necessary information (IP, auth code, decryption key).
* **Automatic Dependency Handling (Receiver):** The receiver script attempts to create a Python virtual environment and install the `cryptography` dependency if run outside a venv.

## Prerequisites

* Python 3.x installed on both Sender and Receiver machines.
* `pip` (Python package installer) available (usually included with Python).
* The `cryptography` Python library (Receiver script attempts to install this automatically if needed).

## Setup Instructions

Follow these steps carefully on **both** the Sender (Host) and Receiver (Target) machines.
*(Note: BOTH `sender.py` and `receiver.py` may COEXIST on the same machine in the same folder as long as **BOTH the `cert.pem` files are properly exchanged between machines.** see below).*
*(Note: The programs may be **simpler to run in an IDE** for the first few runs to **check for package dependencies** and **generate necessary files**).*


1.  **Create Main Folder:**
    * On the **Sender** machine, create a main project directory (e.g., `SecureTransfer`).
    * On the **Receiver** machine, create a main project directory (e.g., `SecureTransfer`).

2.  **Place Scripts:**
    * Place `sender.py` inside the main folder (`SecureTransfer`) on the **Sender** machine.
    * Place `receiver.py` inside the main folder (`SecureTransfer`) on the **Receiver** machine.

3.  **Initial Run & Certificate/Folder Generation:**
    * **On the Receiver Machine:**
        * Open a terminal/command prompt, navigate (`cd`) into the `SecureTransfer` directory.
        * Run the receiver script: `python receiver.py` (or `python3 receiver.py`).
        * The script will:
            * Attempt to create a virtual environment (`venv`) and install `cryptography` if needed (this might take a moment). It may restart itself within the venv.
            * Generate `receiver_cert.pem` (public certificate) and `receiver_key.pem` (private key) in the `SecureTransfer` folder if they don't exist.
            * Create the `received_folder` directory on your Desktop if it doesn't exist.
            * **IMPORTANT:** It will likely show an error message saying `sender_cert.pem` is missing. This is **expected** at this stage. You can close the error message and the script for now.
    * **On the Sender Machine:**
        * Open a terminal/command prompt, navigate (`cd`) into the `SecureTransfer` directory.
        * Run the sender script: `python sender.py` (or `python3 sender.py`).
        * The script will:
            * Generate `sender_cert.pem` (public certificate) and `sender_key.pem` (private key) in the `SecureTransfer` folder if they don't exist.
            * Create the `SEND_FOLDER` directory inside `SecureTransfer` if it doesn't exist.
            * **IMPORTANT:** It will prompt for the Target IP/Auth code. It might also show an error if `receiver_cert.pem` is missing (depending on how quickly you close the IP/Auth prompt). This is **expected**. You can cancel or close the prompts/script for now.

4.  **Exchange PUBLIC Certificates:**
    * This is the crucial step for setting up mTLS trust. You need to securely transfer the **public certificate** from each machine to the other.
    * Copy `receiver_cert.pem` from the Receiver's `SecureTransfer` folder **TO** the Sender's `SecureTransfer` folder.
    * Copy `sender_cert.pem` from the Sender's `SecureTransfer` folder **TO** the Receiver's `SecureTransfer` folder.
    * **SECURITY WARNING:** Use a secure method for this transfer (e.g., USB drive, `scp`, secure chat). **NEVER copy the `_key.pem` files between machines.** These private keys must remain secret on their respective machines.

5.  **Firewall Configuration (Receiver):**
    * The **Receiver** machine's firewall must allow **incoming TCP connections** on port **`12346`** (this port number is defined as `TLS_PORT` in both scripts).
    * How you configure this depends on your operating system and firewall software.
    * *Example for Linux using UFW:* `sudo ufw allow 12346/tcp`
    * *(Note: Refer to my separate Linux firewall script/readme if for easy-script instructions).*
    * *Example for Windows Firewall:* You would typically create a new Inbound Rule allowing TCP traffic on port 12346 for Python or the specific script.

## Usage Instructions

Once setup is complete:

1.  **Prepare Files (Sender):**
    * Place all the files and folders you want to send **inside** the `SEND_FOLDER` located within the Sender's `SecureTransfer` directory.

2.  **Run Receiver:**
    * On the **Receiver** machine, navigate to the `SecureTransfer` directory in your terminal.
    * Run `python receiver.py` or in an IDE load `python receiver.py`, and run it as Python file.
    * A window will appear showing:
        * The Receiver's IP Address (verify this is the correct one the Sender can reach).
        * The Connection Port (`12346`).
        * A randomly generated 4-digit **Auth Code**.
    * **Communicate** the Receiver's IP and the 4-digit Auth Code to the Sender user.
    * The Receiver window will wait for you to enter the 16-character **Decryption Key**. You will get this key from the Sender user in the next steps. **Keep this window open.**

3.  **Run Sender:**
    * On the **Sender** machine, navigate to the `SecureTransfer` directory in your terminal.
    * Run `python sender.py` or in an IDE load `python sender.py`, and run it as Python file.
    * A window will prompt you for:
        * The **Target IP** (enter the IP address shown by the Receiver).
        * The **4-digit Auth Code** (enter the code shown by the Receiver).
    * Click "Submit".

4.  **Perform Transfer:**
    * The Sender script will zip and encrypt the contents of `SEND_FOLDER`.
    * A **new window** will appear on the Sender machine displaying the **16-character Decryption Key**.
    * **IMPORTANT:** Securely communicate this **Decryption Key** to the Receiver user (e.g., verbally, secure chat).
    * The Sender will attempt to connect to the Receiver using mTLS and the Auth Code.
    * The **Receiver user** must now enter the **Decryption Key** (communicated by the Sender) into their waiting prompt and click "Submit Decryption Key & Start Listening".
    * If mTLS, Auth Code, and Decryption Key entry are successful, the encrypted file transfer will begin.
    * Progress will be logged in the terminals of both scripts.

5.  **Verify Transfer (Receiver):**
    * Once the transfer is complete, the Receiver script will automatically decrypt the data and unzip the contents into the `received_folder` located on the Receiver's Desktop.
    * Check the `received_folder` to ensure all files arrived correctly.

## Security Considerations

* **Private Keys (`_key.pem`):** These are extremely sensitive. Never share them. Protect them appropriately on each machine. If a private key is compromised, the security of that machine's identity is broken.
* **Initial Certificate Exchange:** The security of mTLS relies on the initial exchange of public certificates (`.pem` files) being secure. If an attacker intercepts and replaces certificates during this first exchange, they could potentially perform a man-in-the-middle attack later.
* **Decryption Key Exchange:** The 16-character decryption key generated by the sender for each transfer must be transmitted securely to the receiver. Avoid sending it via unencrypted email or insecure chat. Verbal communication (in person or trusted phone call) or end-to-end encrypted chat are better options.
* **Auth Code:** The 4-digit code provides a very basic check *after* mTLS authentication. It's not a strong security measure on its own but helps prevent accidental connections if multiple receivers are running.
* **Network Security:** This tool assumes the network allows direct connection on the specified port. Use in untrusted networks requires careful firewall management.
* **Self-Signed Certificates:** While providing encryption and authentication between *these specific* sender/receiver pairs (once certs are exchanged), self-signed certificates are not inherently trusted by other systems or browsers like certificates from a public Certificate Authority (CA).

## Troubleshooting

* **Connection Refused/Timeout:** Check firewalls on both machines (especially the Receiver's incoming rule for port 12346). Ensure the Receiver script is running. Verify the correct IP address was entered on the Sender. Check network connectivity.
* **TLS/SSL Errors (`certificate verify failed`, `sslv3 alert handshake failure`, etc.):**
    * Most likely cause: Public certificates were not exchanged correctly or are missing. Double-check that `sender_cert.pem` is on the Receiver and `receiver_cert.pem` is on the Sender, both in the script's directory.
    * Ensure the corresponding `_key.pem` file exists alongside the `.pem` file on its *own* machine.
    * Rare: Certificate might be corrupted. Try deleting the `.pem` and `_key.pem` files on *both* machines and re-running the initial setup steps to regenerate them.
* **Authentication Failed (`Receiver rejected the authentication code`):** The wrong 4-digit Auth Code was entered on the Sender.
* **Decryption Failed (`InvalidToken`):** The wrong Decryption Key was entered on the Receiver, or the received `.enc` file was corrupted during transfer.
* **File Not Found Errors:** Ensure the scripts are run from within their main `SecureTransfer` directory. Check that `SEND_FOLDER` exists on the sender and `received_folder` exists on the receiver's Desktop.
* **Permission Denied:** The script might lack permissions to read `SEND_FOLDER`, write to the script directory (for certs/keys), or write to the `received_folder` on the Desktop. Check folder/file permissions.
* **Package Not Found:** You may not have the Python package installed. *Example `Cryptography`*.





## License

This project is licensed under the MIT License.


#Copyright (c) [2025]
[Crenta] [All rights reserved].

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
THIS SOFTWARE IS PROVIDED BY [Name of Organization] “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL [Name of Organisation] BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

