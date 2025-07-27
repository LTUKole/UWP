# UWP
# ==============================================================================
# "Saugaus" slaptažodžio kurimas į faila. [StickyNotes slaptažodis- VLC-UWP-Test!]
# ==============================================================================

# Pirmiausia sukurkite saugų katalogą (jei jo nėra)
New-Item -Path "C:\ProgramData\UWP_Update_Secrets" -ItemType Directory -Force

# ZIP slaptažodžio šifravimas 
Read-Host -Prompt "Įveskite ZIP archyvo slaptažodį" -AsSecureString | ConvertFrom-SecureString | Out-File "C:\ProgramData\UWP_Update_Secrets\secure_zip_password.txt"

# SMTP prisijungimo duomenų šifravimas
$credential = Get-Credential
$credential | Export-CliXml -Path "C:\ProgramData\UWP_Update_Secrets\secure_smtp_credential.xml"

# ==============================================================================
# Skripto paleidimas
# ==============================================================================

# PowerShell nurodome atsiusto ir išarchivuoto failo vieta.
cd "C:\Users\UserName\Downloads\UWP_Script"

# Paleidžiamas skriptas.
.\Update-UWPApp.ps1

# ==============================================================================
# Skripto automatizacija
# ==============================================================================

# Skripto automatizacija vyksta per Task Scheduler...
taskschd.msc
