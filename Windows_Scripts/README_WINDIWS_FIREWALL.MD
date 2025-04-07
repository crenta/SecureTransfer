# Windows Firewall Toggle Script for Secure Receiver (PowerShell - Port 12346)

## Overview

This PowerShell script (`Toggle-ReceiverFirewallRule.ps1`) helps you manage the Windows Defender Firewall rule required by the Secure Receiver application (`secure_receiver.py`).

It securely toggles (adds or removes) an inbound firewall rule to allow **TCP traffic on port 12346**. The rule created by this script is automatically restricted to apply only when your computer is connected to **'Private' or 'Domain' network profiles**, enhancing security by keeping the port closed on untrusted 'Public' networks.

Running this script requires **Administrator privileges** because modifying firewall rules is a protected action.

## Prerequisites

* Windows Operating System (e.g., Windows 10, Windows 11)
* Windows PowerShell (comes pre-installed on modern Windows versions)

## Why This Script?

The Secure Receiver application needs port 12346 open to accept incoming connections from the Secure Sender. Manually opening and closing firewall ports can be tedious and easy to forget, potentially leaving your system exposed. This script provides:

* **Automation:** Easily add or remove the required firewall rule with a single action (like clicking a shortcut).
* **Enhanced Security:** The rule is only created for trusted network profiles ('Private', 'Domain'), significantly reducing exposure compared to an "Allow All" rule. It automatically stays closed on 'Public' networks (like public Wi-Fi).
* **Convenience:** Can be run directly from an Administrator PowerShell or via an easy-to-use desktop shortcut.

## Script Setup

1.  **Get the Script:**
    * Ensure you have the `Toggle-ReceiverFirewallRule.ps1` PowerShell script file.

2.  **Choose a Location:**
    * Save the `.ps1` file to a stable location on your computer where it won't be accidentally deleted. Examples: `C:\Scripts\`, your `Documents\PowerShell\` folder, etc.
    * Remember the full path to this file (e.g., `C:\Scripts\Toggle-ReceiverFirewallRule.ps1`).

3.  **PowerShell Execution Policy (One-time Check):**
    * PowerShell has security features called Execution Policies that might prevent scripts from running by default. To allow this locally saved script to run, you might need to adjust the policy for your user account.
    * Open PowerShell **as Administrator** (Right-click Start -> Windows PowerShell (Admin) or Terminal (Admin)).
    * Run the following command:
        ```powershell
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
        ```
    * If prompted, type `Y` and press Enter. This setting allows locally created scripts (like this one) and remotely downloaded scripts that are digitally signed to run. You generally only need to do this once per user.

## How the Script Works

When executed with Administrator privileges:

1.  The `#Requires -RunAsAdministrator` line at the top ensures PowerShell attempts to elevate if not already running as Admin (triggering a UAC prompt). -N/A
2.  It checks if a firewall rule named "Allow Secure Receiver Port 12346" already exists.
3.  **If the rule exists:** It removes the rule using `Remove-NetFirewallRule` and confirms removal in the console.
4.  **If the rule doesn't exist:** It adds the rule using `New-NetFirewallRule`, specifically configured for:
    * Inbound direction
    * Allow action
    * TCP protocol
    * Local port 12346
    * **Profiles: Private, Domain** (won't be active on Public networks)
    * It confirms the rule addition in the console.
5.  The script pauses with `Read-Host` before exiting so you can see the confirmation message.

## Usage

You need to run this script **twice** for each session of using the Secure Receiver: once to open the port *before* starting the receiver, and once to close the port *after* stopping the receiver.

* **Run ONCE before starting `secure_receiver.py`** to ADD the firewall rule (or ensure it's added).
* **Run ONCE after stopping `secure_receiver.py`** to REMOVE the firewall rule.

**Choose one method to run the script:**

**Method 1: Running Directly in PowerShell (Admin)**

1.  Right-click the Windows Start Menu.
2.  Select "Windows PowerShell (Admin)" or "Terminal (Admin)". Approve the UAC prompt.
3.  In the Administrator PowerShell window, navigate to the directory where you saved the script using the `cd` command. For example:
    ```powershell
    cd C:\Scripts
    ```
4.  Execute the script by typing its name preceded by `.\`:
    ```powershell
    .\Toggle-ReceiverFirewallRule.ps1
    ```
5.  Read the output message (rule added or removed) and press Enter when prompted to exit.

**Method 2: Using the Desktop Shortcut (Recommended for Convenience)**

1.  Right-click on your Desktop -> New -> Shortcut.
2.  For "Type the location of the item:", enter the following, **making sure to replace `"C:\path\to\your\Toggle-ReceiverFirewallRule.ps1"` with the actual full path** where you saved the script:
    ```
    powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\your\Toggle-ReceiverFirewallRule.ps1"
    ```
3.  Click Next.
4.  Give the shortcut a descriptive name, like `Toggle Receiver Firewall (12346)`.
5.  Click Finish.
6.  Right-click the newly created shortcut on your Desktop -> Properties.
7.  Go to the "Shortcut" tab.
8.  Click the "Advanced..." button.
9.  Check the box labeled "Run as administrator".
10. Click OK on the Advanced window.
11. Click OK on the Properties window.

Now, double-clicking this shortcut will:
* Trigger a User Account Control (UAC) prompt asking for permission to run PowerShell as administrator. Click "Yes".
* Execute the script, which will either add or remove the firewall rule based on its current state.
* Show the confirmation message in a PowerShell window (press Enter to close it).

This shortcut provides a convenient way to manage the firewall port specifically for your receiver application.

## Verification (Optional)

You can manually check the status and configuration of the firewall rule:

1.  Open PowerShell as Administrator.
2.  Run this command:
    ```powershell
    Get-NetFirewallRule -DisplayName 'Allow Secure Receiver Port 12346' | Format-List DisplayName, Enabled, Profile, Direction, Action, Protocol, LocalPort
    ```
3.  If the rule exists, this will show its details, including `Enabled: True/False` and the `Profile:` it applies to. If it doesn't exist, the command will return nothing or an error (if you remove `-ErrorAction SilentlyContinue` from the main script's check).

## Troubleshooting

* **Execution Policy Errors:** If you get an error about scripts being disabled, ensure you have run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` in an Administrator PowerShell window (Step 3 in Setup).
* **Script Doesn't Run / No UAC Prompt:** If using the shortcut, ensure "Run as administrator" is checked in the shortcut's advanced properties. If running directly, ensure you opened PowerShell *as Administrator*.
* **Shortcut Path Error:** Double-check the `-File` path in the shortcut's "Target" field matches the exact location where you saved the `.ps1` script. Use quotes if the path contains spaces.
* **Rule Add/Remove Fails:** Check the error message in the PowerShell window. It usually indicates a permissions issue (not running as Admin) or a problem with the rule definition itself.

## Customization (Optional)

If needed, you can modify the variables at the top of the `Toggle-ReceiverFirewallRule.ps1` script:
* `$RuleName`: Change the display name of the rule in Windows Firewall.
* `$Port`: Change the port number (MUST match the port used in `secure_receiver.py` and `sender.py`).
* `$Protocol`: Change the protocol (MUST match the applications).
* `$Profiles`: Change the list of profiles (e.g., set to just `@("Private")`).