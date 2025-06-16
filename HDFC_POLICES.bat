@echo off
echo Applying Policy: Hide C: Drive and More...

:: === HIDE ONLY C: DRIVE ===
:: C: = 4 (A: = 1, B: = 2, C: = 4, D: = 8, etc.)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDrives" /t REG_DWORD /d 4 /f

:: Disable access to Command Prompt
reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v "DisableCMD" /t REG_DWORD /d 1 /f

:: Remove Windows PowerShell (Rename the executable)
takeown /f "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" /a
icacls "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" /deny "Everyone:(X)"
rename "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" powershell_blocked.exe >nul 2>&1

:: Block Administrator account from logging into other accounts
net user Administrator /active:no

:: Remove Quick Access recent files & folders
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\*" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\Recent Items\*" >nul 2>&1

:: Delete temp files
del /F /S /Q "%TEMP%\*.*" >nul 2>&1
del /F /S /Q "%SystemRoot%\Temp\*.*" >nul 2>&1

:: Clear recent items in applications
del /F /S /Q "%APPDATA%\Microsoft\Windows\Recent\*" >nul 2>&1

@echo off
echo Disabling USB removable drives via Group Policy registry keys...

:: Create the necessary registry key path
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /f

:: Deny read access to USB removable drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /v Deny_Read /t REG_DWORD /d 1 /f

:: Deny write access to USB removable drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /v Deny_Write /t REG_DWORD /d 1 /f

echo USB removable drives have been disabled.
pause


:: Block social media websites
echo 127.0.0.1 facebook.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 www.facebook.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 instagram.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 www.instagram.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 twitter.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 www.twitter.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 tiktok.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 www.tiktok.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 youtube.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 127.0.0.1 www.youtube.com >> %SystemRoot%\System32\drivers\etc\hosts

:: Apply group policy changes
gpupdate /force

echo.
echo C: Drive hidden and other security tweaks applied.
echo Restart may be required for all changes to take effect.
pause
