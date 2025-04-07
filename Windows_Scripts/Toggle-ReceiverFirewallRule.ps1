#Requires -RunAsAdministrator # Ensures script asks for elevation if not run as admin

param(
    [string]$RuleName = "Allow Secure Receiver Port 12346",
    [int]$Port = 12346,
    [string]$Protocol = "TCP",
    # --- Specify desired profiles ---
    # Defines the network profiles where the rule will be active.
    # Options: "Private", "Domain", "Public"
    # Using Private and Domain restricts the rule to trusted networks.
    [string[]]$Profiles = @("Private", "Domain")
)

# Check if the rule exists by its display name
$rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

if ($rule) {
    # Rule exists, so the action is to remove it
    try {
        Write-Host "Rule '$RuleName' found. Removing..." -ForegroundColor Yellow
        # Remove the rule using its display name
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
        Write-Host "Rule '$RuleName' successfully removed." -ForegroundColor Green
        # Simple console pause to see the message before exiting
        Read-Host "Press Enter to exit"
    } catch {
        # Error handling if removal fails
        Write-Error "Failed to remove rule '$RuleName'. Error: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        Exit 1
    }
} else {
    # Rule does not exist, so the action is to add it (with profile restrictions)
    try {
        Write-Host "Rule '$RuleName' not found. Adding for profiles: $($Profiles -join ', ')..." -ForegroundColor Yellow
        # Create the new rule, specifying the network profiles
        New-NetFirewallRule -DisplayName $RuleName `
                            -Direction Inbound `
                            -Action Allow `
                            -Protocol $Protocol `
                            -LocalPort $Port `
                            -Profile $Profiles `
                            -ErrorAction Stop
        Write-Host "Rule '$RuleName' successfully added (Inbound, Protocol=$Protocol, Port=$Port, Profiles=$($Profiles -join ', '))." -ForegroundColor Green
        # Simple console pause to see the message before exiting
        Read-Host "Press Enter to exit"
    } catch {
        # Error handling if adding fails
        Write-Error "Failed to add rule '$RuleName'. Error: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        Exit 1
    }
}

# Exit script successfully
Exit 0