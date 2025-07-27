#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Automatizuoja UWP tipo programos atnaujinimą, naudojant dinaminį PowerShell atnaujinimą.
.DESCRIPTION
    Šis scenarijus tikrina nurodytos UWP programos versiją, palygindamas ją su norima versija iš konfigūracijos failo.
    Jis naudoja užšifruotus slaptažodžius ir prisijungimo duomenis, dinamiškai atnaujina PowerShell iki naujausios stabilios versijos
    ir patikimai aptinka aktyvų vartotoją diegimui per interaktyvią suplanuotą užduotį.
.NOTES
    Versija: 0.7
#>

param()

# --- BOOTSTRAPPER: Užtikrinama, kad skriptas veikia PowerShell 7+ aplinkoje ---
# Šis blokas turi būti pačioje pradžioje, prieš visą kitą logiką.
if ($PSVersionTable.PSEdition -eq 'Desktop') { # Tikrinama, ar veikiame senojoje Windows PowerShell (5.1)
    $pwshPath = Join-Path -Path $env:ProgramFiles -ChildPath "PowerShell\7\pwsh.exe"
    if (Test-Path -Path $pwshPath) {
        # Jei PowerShell 7 yra įdiegtas, nedelsiant persijungiama į jį ir išeinama iš dabartinės sesijos.
        Write-Host "Aptikta sena PowerShell aplinka. Persijungiama į PowerShell 7..." -ForegroundColor Yellow
        Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -File `"$($MyInvocation.MyCommand.Path)`""
        exit 0 # Sėkmingai išeinama, nes naujas procesas paleistas.
    }
    # Jei PowerShell 7 nėra įdiegtas, skriptas tęs darbą senojoje aplinkoje, o vėlesnė logika atliks diegimą.
}


Set-StrictMode -Version Latest

# --- MODULIO IR KONFIGŪRACIJOS ĮKĖLIMAS ---
try {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
    $modulePath = Join-Path -Path $scriptRoot -ChildPath "functions.psm1"
    $configPath = Join-Path -Path $scriptRoot -ChildPath "config.json"

    if (-not (Test-Path -Path $modulePath)) {
        throw "KRITINĖ KLAIDA: Funkcijų modulis '$modulePath' nerastas."
    }
    Import-Module -Name $modulePath -Force

    if (-not (Test-Path -Path $configPath)) {
        # Naudojama funkcija iš modulio, kad būtų galima rašyti į žurnalą net jei konfigūracija nepavyko.
        Write-Log -Message "KRITINĖ KLAIDA: Konfigūracijos failas '$configPath' nerastas." -LogPath "C:\ProgramData\Logs\UWP_Update_Bootstrap_Error.log" -Level "ERROR"
        exit 1
    }
    $Config = Get-Content -Path $configPath | ConvertFrom-Json
}
catch {
    Write-Error "Įvyko kritinė klaida įkeliant modulį arba konfigūraciją: $($_.Exception.Message)"
    exit 1
}

# --- PAGRINDINIO PROCESO KINTAMIEJI ---
$updateStatus = "Procesas nepradėtas"
$finalLogContent = ""
# Laikinasis katalogas kuriamas viešoje vietoje, kad būtų pasiekiamas tiek SYSTEM, tiek vartotojo kontekste.
$publicTempPath = Join-Path -Path $env:PUBLIC -ChildPath "Documents\UWP_Update_Temp"
$pwshPath = Join-Path -Path $env:ProgramFiles -ChildPath "PowerShell\7\pwsh.exe"

# --- PAGRINDINIS VYKDYMO BLOKAS ---
try {
    Write-Log -Message "--- Pradedamas '$($Config.AppName)' atnaujinimo procesas kompiuteryje $($env:COMPUTERNAME) ---" -LogPath $Config.LogFilePath
    Write-Log -Message "Veikiama su PowerShell versija: $($PSVersionTable.PSVersion)" -LogPath $Config.LogFilePath
    
    # 1. PowerShell versijos patikrinimas (vykdomas tik jei bootstrapper'is nepersijungė)
    # Ši logika dabar veiks kaip pirminis diegimas, jei PS7 išvis nėra.
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Write-Log -Message "PowerShell 7 nerastas. Pradedamas diegimas." -LogPath $Config.LogFilePath -Level "WARN"
        Install-LatestPowerShell -LogPath $Config.LogFilePath
        
        Write-Log -Message "PowerShell atnaujintas. Scenarijus bus paleistas iš naujo naujoje aplinkoje." -LogPath $Config.LogFilePath
        Start-Process -FilePath $pwshPath -ArgumentList "-NoProfile -File `"$($MyInvocation.MyCommand.Path)`""
        exit
    }
    Write-Log -Message "PowerShell versija yra tinkama." -LogPath $Config.LogFilePath

    # 2. Būtinų modulių tikrinimas
    Write-Log -Message "2/8: Tikrinamas 7Zip4PowerShell modulis..." -LogPath $Config.LogFilePath
    Test-7ZipModule -LogPath $Config.LogFilePath
    Write-Log -Message "7Zip4PowerShell modulis paruoštas." -LogPath $Config.LogFilePath

    # 3. Vartotojo paieška
    Write-Log -Message "3/8: Ieškomas aktyvus vartotojas..." -LogPath $Config.LogFilePath
    $targetUser = Get-TargetUser -LogPath $Config.LogFilePath
    Write-Log -Message "Rastas tikslinis vartotojas: '$($targetUser.Name)' (SID: $($targetUser.SID))." -LogPath $Config.LogFilePath
    $updateStatus = "Vartotojas rastas: $($targetUser.Name)."
    
    # 4. Programos versijos tikrinimas
    Write-Log -Message "4/8: Tikrinama esama '$($Config.AppName)' versija..." -LogPath $Config.LogFilePath
    $currentVersion = Get-AppVersion -AppName $Config.AppName -UserSid $targetUser.SID -LogPath $Config.LogFilePath
    $desiredVersion = [version]$Config.DesiredVersion

    if ($currentVersion -and $currentVersion -ge $desiredVersion) {
        $updateStatus = "Programa '$($Config.AppName)' jau turi naujausią versiją ($currentVersion). Atnaujinimas nereikalingas."
        Write-Log -Message $updateStatus -LogPath $Config.LogFilePath
        return # Išeinama iš skripto sėkmingai
    }

    $updateStatus = if ($currentVersion) {
        "Rasta sena versija ($currentVersion). Pradedamas atnaujinimas į $desiredVersion."
    } else {
        "Programa '$($Config.AppName)' nerasta. Bus bandoma įdiegti versiją $desiredVersion."
    }
    Write-Log -Message $updateStatus -LogPath $Config.LogFilePath

    # 5. Pasiruošimas diegimui (laikinųjų failų valymas)
    Write-Log -Message "5/8: Valomas laikinasis katalogas: $publicTempPath" -LogPath $Config.LogFilePath
    Clean-TempFiles -Path $publicTempPath -LogPath $Config.LogFilePath
    Write-Log -Message "Laikinasis katalogas išvalytas ir paruoštas." -LogPath $Config.LogFilePath

    # 6. Atsisiuntimas
    Write-Log -Message "6/8: Atsisiunčiamas atnaujinimo paketas..." -LogPath $Config.LogFilePath
    $zipFilePath = Join-Path -Path $publicTempPath -ChildPath "update.zip"
    Download-File -Url $Config.UpdatePackageUrl -DestinationPath $zipFilePath -LogPath $Config.LogFilePath
    Write-Log -Message "Paketas sėkmingai atsiųstas." -LogPath $Config.LogFilePath

    # 7. Išskleidimas (naudojant saugų slaptažodį)
    Write-Log -Message "7/8: Išskleidžiamas archyvas..." -LogPath $Config.LogFilePath
    $securePassword = Get-Content -Path $Config.SecureZipPasswordPath | ConvertTo-SecureString
    Expand-UpdatePackage -ArchivePath $zipFilePath -DestinationPath $publicTempPath -InstallerScriptRelativePath $Config.InstallerScriptPath -Password $securePassword -LogPath $Config.LogFilePath
    Write-Log -Message "Archyvas sėkmingai išskleistas ir patikrintas." -LogPath $Config.LogFilePath
    
    # 8. Diegimas per planuotą užduotį
    Write-Log -Message "8/8: Pradedamas diegimas vartotojo sesijoje per planuotą užduotį..." -LogPath $Config.LogFilePath
    $taskName = "UWP_Update_Task_$(Get-Random -Maximum 99999)"
    Write-Log -Message "Kuriama laikina planuota užduotis '$taskName'..." -LogPath $Config.LogFilePath
    
    $installScriptFullPath = Join-Path -Path $publicTempPath -ChildPath $Config.InstallerScriptPath
    $taskArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$installScriptFullPath`" -SourcePath `"$publicTempPath`""
    
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $targetUser.SID -LogonType Interactive
    $taskAction = New-ScheduledTaskAction -Execute $pwshPath -Argument $taskArguments
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15) # Daugiau laiko sistemai sureaguoti
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    
    Register-ScheduledTask -TaskName $taskName -Principal $taskPrincipal -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Force
    Start-ScheduledTask -TaskName $taskName
    
    Write-Log -Message "Laukiama, kol užduotis '$taskName' bus baigta..." -LogPath $Config.LogFilePath
    $taskResult = Wait-ForScheduledTaskToComplete -TaskName $taskName -LogPath $Config.LogFilePath
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    if ($taskResult -ne 0) {
        throw "Planuota diegimo užduotis baigėsi su klaida. Rezultato kodas: $taskResult. Patikrinkite diegimo žurnalą: $env:TEMP\UWP_Install_Log.txt"
    }

    $updateStatus = "Programa '$($Config.AppName)' sėkmingai atnaujinta/įdiegta."
    Write-Log -Message "PROCESAS SĖKMINGAS!" -LogPath $Config.LogFilePath
}
catch {
    $updateStatus = "Kritinė klaida atnaujinimo procese: $($_.Exception.Message)"
    Write-Log -Message $updateStatus -LogPath $Config.LogFilePath -Level "ERROR"
    Write-Log -Message "Išsamesnė informacija: $($_.ToString())" -LogPath $Config.LogFilePath -Level "ERROR"
}
finally {
    Write-Log -Message "--- Atnaujinimo procesas baigtas. Galutinė būsena: $updateStatus ---" -LogPath $Config.LogFilePath
    
    if (Test-Path -Path $publicTempPath) {
        Write-Log -Message "Valomas laikinasis viešasis katalogas: $publicTempPath" -LogPath $Config.LogFilePath
        Remove-Item -Path $publicTempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    if (Test-Path $Config.LogFilePath) {
        $finalLogContent = (Get-Content -Path $Config.LogFilePath | Select-Object -Last 30) -join "<br>"
    }

    # El. pašto pranešimo siuntimas
    if ($Config.EmailSettings.Enabled) {
        # Sukuriama tuščia Hashtable.
        $emailSettingsHashtable = @{}
        foreach ($property in $Config.EmailSettings.PSObject.Properties) {
            $emailSettingsHashtable[$property.Name] = $property.Value
        }
        
        if (Test-Path $Config.EmailSettings.SecureCredentialPath) {
            try {
                $credential = Import-CliXml -Path $Config.EmailSettings.SecureCredentialPath
                $emailSettingsHashtable['Credential'] = $credential
            } catch {
                Write-Log -Message "Nepavyko įkelti saugių SMTP prisijungimo duomenų. El. laiškas nebus išsiųstas." -LogPath $Config.LogFilePath -Level "WARN"
                $emailSettingsHashtable['Enabled'] = $false
            }
        } else {
            Write-Log -Message "Saugumo failas '$($Config.EmailSettings.SecureCredentialPath)' nerastas. El. laiškas nebus išsiųstas." -LogPath $Config.LogFilePath -Level "WARN"
            $emailSettingsHashtable['Enabled'] = $false
        }
        
        $emailSubject = "$($Config.AppName) atnaujinimo ataskaita: $($env:COMPUTERNAME)"
        $emailBody = @"
        <html><body>
            <h2>$($Config.AppName) atnaujinimo ataskaita</h2>
            <p><strong>Kompiuteris:</strong> $($env:COMPUTERNAME)</p>
            <p><strong>Programa:</strong> $($Config.AppName)</p>
            <p><strong>Galutinė būsena:</strong> $updateStatus</p>
            <hr>
            <h3>Paskutiniai žurnalo įrašai:</h3>
            <pre style='font-family: Consolas, monospace; background-color: #f5f5f5; padding: 10px; border-radius: 5px; white-space: pre-wrap;'>$finalLogContent</pre>
        </body></html>
"@
        # Patikriname dar kartą, ar siuntimas vis dar įjungtas po visų patikrų.
        if ($emailSettingsHashtable['Enabled']) {
            Send-UpdateNotification -Subject $emailSubject -Body $emailBody -EmailSettings $emailSettingsHashtable -LogPath $Config.LogFilePath
        }
    }
}
