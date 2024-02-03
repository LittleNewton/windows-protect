function Log-Event {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$LogBegin,
        [string]$LogFilePath = ".\log\Block RDP IP.log"
    )

    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    # Get timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Prepare log entry
    $logEntry = "$timestamp - $Message"

    # Log a separator for new events if $LogBegin is specified
    if ($LogBegin) {
        Add-Content -Path $LogFilePath -Value "`n`n$logEntry"
    } else {
        Add-Content -Path $LogFilePath -Value $logEntry
    }
}


# Log the start of the script with LogBegin
Log-Event -Message "Script started." -LogBegin


$EventID                    = 4625  # Event ID for failed logon attempts
$LogType                    = "Security"
$EventIPs                   = New-Object System.Collections.Hashtable
$NewIPs                     = New-Object System.Collections.Generic.HashSet[string]
$FirewallRuleName           = "Block Malicious RDP Brute Force"
$TolerableFailedAttempts    = 6

# Query the event logs for the specific Event ID
$FailedLogonEvents = Get-WinEvent -LogName $LogType | Where-Object { $_.Id -eq $EventID }

# Iterate through each event to extract IP addresses
foreach ($Event in $FailedLogonEvents) {
    if ($Event.Message -match "源网络地址:	\s*(\d{1,3}(\.\d{1,3}){3})") {
        $IPAddress = $matches[1]

        # Exclude the loopback address and add others to the HashSet
        if ($IPAddress -ne "127.0.0.1") {
            if ($EventIPs[$IPAddress] -eq $null) {
                $EventIPs[$IPAddress] = 1
            } else {
                $EventIPs[$IPAddress]++
            }
        }
    }
}


# Retrieve the existing firewall rule
$FirewallRule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue

# Check if the firewall rule exists
if ($FirewallRule) {
    # Get the existing remote addresses from the firewall rule
    $BlockedIPs = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $FirewallRule).RemoteAddress


    foreach ($IPAddress in $EventIPs.Keys) {
        # in $EventIPs but not in $BlockedIPs
        if ($BlockedIPs -notcontains $IPAddress -and $EventIPs[$IPAddress] -gt $TolerableFailedAttempts) {
            $NewIPs.Add($IPAddress) > $null
            Log-Event "Found new malicious IP: $IPAddress.`tAttack count: '$($EventIPs[$IPAddress])'."
        }
    }


    # Combine existing addresses with the new unique IPs
    # $AllIPs = ($BlockedIPs + " " + $EventIPs.Keys | Select-Object -Unique) -split " "
    $AllIPs = $BlockedIPs + $EventIPs.Keys | Select-Object -Unique

    # Update the firewall rule with the new set of IP addresses
    if ($NewIPs.Count -gt 0) {
        Log-Event "Updating firewall rule '$FirewallRuleName' with new IP addresses: '$NewIPs'"
        Log-Event "Current malicious IP addresses: '$AllIPs'."
        Set-NetFirewallRule -Name $FirewallRule.Name -RemoteAddress $AllIPs
    } else {
        Log-Event "No new IP addresses to add to firewall rule '$FirewallRuleName'"
    }
} else {
    Log-Event "Error: Firewall rule '$FirewallRuleName' not found."
    New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Action Block -Protocol Any -RemoteAddress $maliciousIPs
}

# Log the end of the script
Log-Event "Script execution completed."
