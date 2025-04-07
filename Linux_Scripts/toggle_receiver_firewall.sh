#!/bin/bash

# --- Configuration ---
PORT="12346"
PROTO="tcp"
# This script toggles the simple rule allowing any source to the specified port.
# Toggling rules specific to an IP (e.g., "allow from 192.168.1.100...") is harder
# because the delete command needs the same specific details.
RULE_TO_TOGGLE="${PORT}/${PROTO}"
RULE_TO_DELETE="allow ${PORT}/${PROTO}" # ufw delete uses 'allow <rule>' format

# State file to remember if the rule is ON or OFF
STATE_FILE="$HOME/.config/receiver_firewall_state"
APP_NAME="Receiver Port ${PORT} Firewall"

# --- Ensure ~/.config directory exists ---
mkdir -p "$(dirname "$STATE_FILE")"

# --- Function for User Notification ---
# Uses notify-send. Install if needed: sudo apt install libnotify-bin
notify() {
    if command -v notify-send &> /dev/null; then
        notify-send -t 3500 "$APP_NAME" "$1" # 3.5 second timeout
    else
        echo "Notification: $1" # Fallback to console
    fi
}

# --- Check if ufw is active ---
if ! sudo ufw status | grep -qw active; then
    notify "ERROR: UFW firewall is not active/enabled. Cannot manage rules."
    exit 1
fi

# --- Read current state (Default to OFF) ---
CURRENT_STATE="OFF"
if [[ -f "$STATE_FILE" ]] && [[ "$(cat "$STATE_FILE")" == "ON" ]]; then
    # Check if the rule *actually* exists in ufw before assuming ON
    if sudo ufw status | grep -qw "$RULE_TO_TOGGLE"; then
        CURRENT_STATE="ON"
    else
        echo "State file says ON, but rule not found in ufw. Correcting state to OFF."
        CURRENT_STATE="OFF" # Correct state if manually deleted
        echo "OFF" > "$STATE_FILE"
    fi
fi

echo "Rule ${RULE_TO_TOGGLE} current state: $CURRENT_STATE"

# --- Toggle State ---
if [[ "$CURRENT_STATE" == "OFF" ]]; then
    echo "Attempting to ENABLE firewall rule..."
    # Use pkexec for graphical password prompt if available, else sudo
    if command -v pkexec &> /dev/null; then
        COMMAND="pkexec ufw allow $RULE_TO_TOGGLE"
    else
        COMMAND="sudo ufw allow $RULE_TO_TOGGLE"
    fi

    eval $COMMAND # Execute the command
    COMMAND_SUCCESS=$?

    if [[ $COMMAND_SUCCESS -eq 0 ]]; then
        echo "ON" > "$STATE_FILE"
        notify "Firewall rule ENABLED for TCP port $PORT (Any Source)."
        echo "Rule enabled."
    else
        notify "ERROR: Failed to enable firewall rule for port $PORT."
        echo "Failed to enable rule (requires privileges or rule exists?)."
        exit 1 # Exit with error
    fi
else # Current state is ON
    echo "Attempting to DISABLE firewall rule..."
    # Use pkexec for graphical password prompt if available, else sudo
    if command -v pkexec &> /dev/null; then
        COMMAND="pkexec ufw delete $RULE_TO_DELETE"
    else
        COMMAND="sudo ufw delete $RULE_TO_DELETE"
    fi

    eval $COMMAND # Execute the command
    COMMAND_SUCCESS=$?

    if [[ $COMMAND_SUCCESS -eq 0 ]]; then
        echo "OFF" > "$STATE_FILE"
        notify "Firewall rule DISABLED for TCP port $PORT."
        echo "Rule disabled."
    else
        # Check if it failed because the rule wasn't actually there
         if ! sudo ufw status | grep -qw "$RULE_TO_TOGGLE"; then
             echo "Rule seems to be already deleted. Updating state."
             echo "OFF" > "$STATE_FILE"
             notify "Firewall rule already DISABLED for TCP port $PORT."
         else
             notify "ERROR: Failed to disable firewall rule for port $PORT."
             echo "Failed to disable rule (requires privileges?)."
             exit 1 # Exit with error
        fi
    fi
fi

exit 0