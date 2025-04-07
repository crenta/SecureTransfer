# Linux Firewall Toggle Script for Secure Receiver (UFW Port 12346)

## Overview

This `toggle_receiver_firewall.sh` script provides a convenient way to enable and disable the specific firewall rule needed by the Secure Receiver application (`receiver.py`) on Linux systems using UFW (Uncomplicated Firewall).

It specifically toggles the rule to **allow incoming TCP traffic on port 12346**. This allows the Sender application (`sender.py`) to connect to the Receiver.

The script:
* Checks if UFW is active.
* Uses a state file (`~/.config/receiver_firewall_state`) to remember whether the rule is currently considered ON or OFF.
* Uses `sudo` (or `pkexec` when run via the optional desktop icon) to gain privileges for modifying firewall rules.
* Uses `notify-send` (if available) to show desktop notifications about the rule status.

## Prerequisites

You need the following packages installed on the Linux machine where you will run the **Receiver** application:

1.  **`ufw`**: The Uncomplicated Firewall itself.
    ```bash
    sudo apt update && sudo apt install ufw
    ```
2.  **`libnotify-bin`**: Provides the `notify-send` command for desktop pop-up notifications.
    ```bash
    sudo apt update && sudo apt install libnotify-bin
    ```
3.  **`policykit-1`** (provides `pkexec`): Needed *only if you set up the optional desktop icon*. It allows the script to request your password graphically. Most desktop environments have this pre-installed.

## General UFW Information

This script only manages the rule for TCP port 12346. For general UFW setup, here are some helpful commands:

* **Enable UFW:** (Run once)
    ```bash
    sudo ufw enable
    ```
* **Set Default Policies:** (Recommended: Deny incoming, Allow outgoing)
    ```bash
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    ```
* **Reload UFW Rules:** (After manual changes)
    ```bash
    sudo ufw reload
    ```
* **Check Status:**
    ```bash
    sudo ufw status verbose
    ```

**This script specifically automates these two commands:**
* `sudo ufw allow 12346/tcp` (Turns rule ON)
* `sudo ufw delete allow 12346/tcp` (Turns rule OFF)

## Script Setup

1.  **Get the Script:**
    * Ensure you have the `toggle_receiver_firewall.sh` file.

2.  **Choose a Location:**
    * Decide where to save the script. A common place for user scripts is a `bin` directory in your home folder.
    * Create it if it doesn't exist:
        ```bash
        mkdir -p ~/bin
        ```
    * Alternatively, you can just save it in your home directory or another preferred location.

3.  **Copy the Script:**
    * Move or copy the script to your chosen location. Example for `~/bin`:
        ```bash
        cp toggle_receiver_firewall.sh ~/bin/
        ```

4.  **Make the Script Executable:**
    * Navigate to the directory where you saved the script and run `chmod`:
        ```bash
        chmod +x ~/bin/toggle_receiver_firewall.sh
        ```
        (Replace `~/bin/` if you chose a different location).

## Optional: Desktop Launcher Setup

This creates an application icon you can click to toggle the firewall rule, providing a graphical password prompt.

1.  **Navigate to Applications Directory:**
    ```bash
    cd ~/.local/share/applications/
    ```
    * If the directory doesn't exist, create it:
        ```bash
        mkdir -p ~/.local/share/applications
        ```

2.  **Create the `.desktop` File:**
    * Open a text editor (like `nano`, `gedit`, `vim`) to create the launcher file:
        ```bash
        nano toggle-receiver-firewall.desktop
        ```

3.  **Paste Content:**
    * Paste the following text into the editor.
    * **VERY IMPORTANT:** Modify the `Exec=` line to contain the **absolute, full path** to where you saved `toggle_receiver_firewall.sh` in the previous step.

    ```ini
    [Desktop Entry]
    Version=1.0
    Name=Toggle Receiver Firewall (12346)
    Comment=Enable/Disable Firewall Rule for Secure Receiver Port 12346
    # IMPORTANT: Replace the path below with the ACTUAL full path to your script!
    Exec=pkexec /home/kali/bin/toggle_receiver_firewall.sh
    Icon=kali-security # You can change this icon (e.g., security-high, network-firewall, utilities-terminal)
    Terminal=false
    Type=Application
    Categories=Network;Security;Utility;
    ```

4.  **Save and Close:**
    * If using `nano`, press `Ctrl+O`, then `Enter` to save, and `Ctrl+X` to exit.

5.  **Make Executable (Optional):**
    * Some desktop environments might require the `.desktop` file itself to be executable:
        ```bash
        chmod +x toggle-receiver-firewall.desktop
        ```

## Usage

**Before Running the Secure Receiver:**

* You need to **ENABLE** the firewall rule.

**After Closing the Secure Receiver:**

* You should **DISABLE** the firewall rule for better security.

**How to Toggle:**

* **Using the Desktop Icon (if created):**
    1.  Find the "Toggle Receiver Firewall (12346)" icon in your application menu (often under Utilities, Network, or Security). You can usually drag it to your desktop or panel.
    2.  **First Click:** The script runs, requests your password via a graphical prompt (`pkexec`), enables the rule (`sudo ufw allow 12346/tcp`)
    3.  **Second Click:** Runs again, requests password, disables the rule (`sudo ufw delete allow 12346/tcp`)
    4.  Subsequent clicks continue toggling the rule ON and OFF.

* **From the Terminal:**
    1.  Open your terminal.
    2.  Run the script using its full path:
        ```bash
        ~/bin/toggle_receiver_firewall.sh
        ```
        (Adjust path if you saved it elsewhere).
    3.  You will likely be prompted for your password directly in the terminal (`sudo`).
    4.  The script will output whether it enabled or disabled the rule and potentially show a desktop notification. Run it again to toggle the state back.

## Troubleshooting

* **"ERROR: UFW firewall is not active"**: Enable UFW first using `sudo ufw enable`.
* **Script "command not found"**: Make sure you are using the correct path to the script and that it is executable (`chmod +x`).
* **Icon doesn't work / "Failed to execute command"**:
    * Double-check the **full path** in the `Exec=` line inside your `toggle-receiver-firewall.desktop` file is exactly correct.
    * Ensure the script file (`toggle_receiver_firewall.sh`) is executable.
    * Verify `pkexec` is working (it's part of the `policykit-1` package).
* **Password prompt doesn't appear / Permission errors**: The script needs root privileges (via `sudo` or `pkexec`) to modify UFW rules. Ensure you are running it correctly (directly with terminal sudo prompt, or via the icon using `pkexec`).
* **Notifications not showing**: Make sure `libnotify-bin` is installed (`sudo apt install libnotify-bin`). Your desktop environment might also need a notification daemon running.