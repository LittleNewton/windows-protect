function Log-Event {
    param(
        [string]$Message,
        [string]$LogFilePath = "C:\Users\Administrator\bin\PowerShell Scripts\Security\log\Block RDP IP.log"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $LogFilePath -Value $logEntry
}

# Log the start of the script
Log-Event "Script started."


#-- Block attackers.
$EventID    = 4625  # Event ID for failed logon attempts
$LogType    = "Security"
$UniqueIPs  = New-Object System.Collections.Generic.HashSet[string]
$FirewallRuleName = "A-恶意IP黑名单"

# Query the event logs for the specific Event ID
$FailedLogonEvents = Get-WinEvent -LogName $LogType | Where-Object { $_.Id -eq $EventID }

# Iterate through each event to extract IP addresses
foreach ($Event in $FailedLogonEvents) {
    if ($Event.Message -match "源网络地址:	\s*(\d{1,3}(\.\d{1,3}){3})") {
        $IPAddress = $matches[1]
        # Exclude the loopback address and add others to the HashSet
        if ($IPAddress -ne "127.0.0.1") {
            $UniqueIPs.Add($IPAddress) > $null
            # Log each unique IP
            Log-Event "Found unique IP: $IPAddress"
        }
    }
}

if ($UniqueIPs.Count -eq 0) {
    Log-Event "No unique failed logon IPs found."
    exit
} else {
    # log new added ip address
    foreach ($IPAddress in $UniqueIPs) {
        # in $IPAddress no in the existingAddresses
        if ($ExistingAddresses -notcontains $IPAddress) {
            Log-Event "Added new IP: $IPAddress"
        }
    }

    # Retrieve the existing firewall rule
    $FirewallRule = Get-NetFirewallRule -DisplayName $FirewallRuleName

    # Check if the firewall rule exists
    if ($FirewallRule) {
        # Get the existing remote addresses from the firewall rule
        $ExistingAddresses = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $FirewallRule).RemoteAddress

        # Combine existing addresses with the new unique IPs
        $AllIPs = $ExistingAddresses + $UniqueIPs | Select-Object -Unique

        # Update the firewall rule with the new set of IP addresses
        Set-NetFirewallRule -Name $FirewallRule.Name -RemoteAddress $AllIPs
        Write-Output "Firewall rule '$FirewallRuleName' updated with new IP addresses."
        Log-Event "Firewall rule '$FirewallRuleName' updated with new IP addresses: $AllIPs"
    } else {
        Write-Error "Firewall rule '$FirewallRuleName' not found."
        Log-Event "Error: Firewall rule '$FirewallRuleName' not found."
    }
}

# Display unique IP addresses and log
$uniqueIPsString = $UniqueIPs -join ', '
Write-Output "Unique failed logon IPs (excluding 127.0.0.1): $uniqueIPsString"
Log-Event "Unique failed logon IPs (excluding 127.0.0.1): $uniqueIPsString"

# Log the end of the script
Log-Event "Script execution completed."
