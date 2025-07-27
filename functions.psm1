#Requires -Version 5.1

<#
.SYNOPSIS
    Pagalbinių funkcijų modulis, skirtas UWP programos atnaujinimo procesui valdyti.
.NOTES
    Versija: 3.1
#>

Set-StrictMode -Version Latest

# ==============================================================================
# Žurnalų rašymo funkcija
# ==============================================================================
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$LogPath,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $logEntry = "[{0}][{1}] - {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level.ToUpper(), $Message
    try {
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path -Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logEntry
    }
    catch {
        Write-Warning "Nepavyko įrašyti į žurnalo failą: $($_.Exception.Message)"
    }
}
Export-ModuleMember -Function 'Write-Log'

# ==============================================================================
# Laikinųjų failų valymo funkcija
# ==============================================================================
function Clean-TempFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if (Test-Path -Path $Path) {
        Write-Log -Message "Valomas laikinasis katalogas: $Path" -LogPath $LogPath
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        }
        catch {
            throw "Klaida valant laikinąjį katalogą '$Path': $($_.Exception.Message)"
        }
    }
    # Sukuriamas katalogas iš naujo, kad būtų švarus.
    New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
}
Export-ModuleMember -Function 'Clean-TempFiles'

# ==============================================================================
# Dinaminė PowerShell atnaujinimo funkcija
# ==============================================================================
function Install-LatestPowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Ieškoma naujausios stabilios PowerShell versijos per GitHub API..." -LogPath $LogPath
    $apiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
    $tempMsiPath = Join-Path -Path $env:TEMP -ChildPath "PowerShell_latest.msi"

    try {
        $releaseInfo = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $msiAsset = $releaseInfo.assets | Where-Object { $_.name -like 'PowerShell-*-win-x64.msi' } | Select-Object -First 1
        
        if (-not $msiAsset) {
            throw "Nepavyko rasti tinkamo MSI diegimo failo naujausioje PowerShell versijoje ($($releaseInfo.tag_name))."
        }

        $downloadUrl = $msiAsset.browser_download_url
        Write-Log -Message "Atsisiunčiamas PowerShell '$($releaseInfo.tag_name)' MSI paketas iš $downloadUrl" -LogPath $LogPath
        
        # Naudojamas BITS siuntimui.
        Start-BitsTransfer -Source $downloadUrl -Destination $tempMsiPath -ErrorAction Stop
        
        Write-Log -Message "Pradedamas tylusis PowerShell diegimas..." -LogPath $LogPath
        $process = Start-Process "msiexec.exe" -ArgumentList "/i `"$tempMsiPath`" /quiet /norestart" -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            throw "PowerShell diegimas baigėsi su klaidos kodu: $($process.ExitCode)"
        }
        Write-Log -Message "PowerShell sėkmingai įdiegtas/atnaujintas." -LogPath $LogPath
    }
    catch {
        throw "Kritinė klaida diegiant PowerShell: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path -Path $tempMsiPath) {
            Remove-Item -Path $tempMsiPath -Force
        }
    }
}
Export-ModuleMember -Function 'Install-LatestPowerShell'

# ==============================================================================
# 7Zip4PowerShell modulio tikrinimo ir diegimo funkcija
# ==============================================================================
function Test-7ZipModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Tikrinamas 7Zip4PowerShell modulis." -LogPath $LogPath
    if (-not (Get-Module -Name "7Zip4PowerShell" -ListAvailable)) {
        Write-Log -Message "7Zip4PowerShell modulis nerastas. Bandoma įdiegti iš PowerShell Gallery." -LogPath $LogPath -Level "WARN"
        try {
            # Užtikrinama, kad NuGet tiekėjas yra įdiegtas
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            Install-Module -Name "7Zip4PowerShell" -Repository "PSGallery" -Force -Scope AllUsers -ErrorAction Stop
            Write-Log -Message "7Zip4PowerShell modulis sėkmingai įdiegtas." -LogPath $LogPath
        }
        catch {
            throw "Nepavyko įdiegti 7Zip4PowerShell modulio. Patikrinkite interneto ryšį ir PowerShell Gallery pasiekiamumą. Klaida: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log -Message "7Zip4PowerShell modulis rastas." -LogPath $LogPath
    }
}
Export-ModuleMember -Function 'Test-7ZipModule'

# ==============================================================================
# Patobulinta tikslinio vartotojo nustatymo funkcija
# ==============================================================================
function Get-TargetUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    # 1 bandymas: Greitasis metodas per explorer.exe procesą.
    Write-Log -Message "Ieškoma aktyvaus vartotojo (1 bandymas: explorer.exe procesas)..." -LogPath $LogPath
    try {
        $explorerProcess = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe' AND SessionId != 0" | Sort-Object -Property CreationDate -Descending | Select-Object -First 1
        if ($explorerProcess) {
            $ownerInfo = Invoke-CimMethod -InputObject $explorerProcess -MethodName GetOwner
            $targetUser = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$($ownerInfo.User)' AND Domain='$($ownerInfo.Domain)'"
            if ($targetUser) {
                Write-Log -Message "Rastas aktyvus vartotojas per explorer.exe: $($ownerInfo.Domain)\$($ownerInfo.User)" -LogPath $LogPath
                return $targetUser
            }
        }
    } catch {
        Write-Log -Message "Klaida ieškant vartotojo per explorer.exe: $($_.Exception.Message)" -LogPath $LogPath -Level "WARN"
    }

    # 2 bandymas: Patikimesnis metodas per saugumo įvykių žurnalą.
    Write-Log -Message "Ieškoma aktyvaus vartotojo (2 bandymas: Saugumo įvykių žurnalas)..." -LogPath $LogPath
    try {
        $event = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 100 | Where-Object { $_.Properties[8].Value -in @(2, 10) } | Select-Object -First 1
        if ($event) {
            $sid = $event.Properties[4].Value
            $targetUser = Get-CimInstance -ClassName Win32_UserAccount -Filter "SID = '$sid'"
            if ($targetUser) {
                Write-Log -Message "Rastas paskutinis prisijungęs vartotojas per įvykių žurnalą: $($targetUser.Domain)\$($targetUser.Name)" -LogPath $LogPath
                return $targetUser
            }
        }
    } catch {
        Write-Log -Message "Klaida ieškant vartotojo per saugumo žurnalą: $($_.Exception.Message)" -LogPath $LogPath -Level "WARN"
    }
    
    throw "Nepavyko rasti tinkamo tikslinio vartotojo nei per aktyvius procesus, nei per įvykių žurnalą."
}
Export-ModuleMember -Function 'Get-TargetUser'

# ==============================================================================
# UWP programos versijos tikrinimo funkcija
# ==============================================================================
function Get-AppVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        [Parameter(Mandatory = $true)]
        [string]$UserSid,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Tikrinama programos '$AppName' versija vartotojui su SID '$UserSid'." -LogPath $LogPath
    try {
        # Pirmiausia gaunamas VISŲ programų sąrašas vartotojui.
        $allUserPackages = Get-AppxPackage -User $UserSid -ErrorAction SilentlyContinue
        
        if (-not $allUserPackages) {
            Write-Log -Message "Nepavyko gauti jokių programų sąrašo vartotojui su SID '$UserSid'. Galbūt profilis neprieinamas arba neturi įdiegtų programų." -LogPath $LogPath -Level 'WARN'
            return $null
        }

        # Iš gauto sąrašo filtruojama reikiama programa.
        $appPackage = $allUserPackages | Where-Object { $_.PackageFamilyName -eq $AppName }

        if ($appPackage) {
            Write-Log -Message "Rasta '$AppName' versija: $($appPackage.Version)" -LogPath $LogPath
            return [version]$appPackage.Version
        }
        else {
            Write-Log -Message "Programa '$AppName' nerasta įdiegta vartotojui su SID '$UserSid'." -LogPath $LogPath -Level 'INFO'
            return $null
        }
    }
    catch {
        Write-Log -Message "Įvyko kritinė klaida tikrinant programos versiją: $($_.Exception.Message)" -LogPath $LogPath -Level "ERROR"
        return $null
    }
}
Export-ModuleMember -Function 'Get-AppVersion'

# ==============================================================================
# Failo atsisiuntimo funkcija
# ==============================================================================
function Download-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Pradedamas failo atsisiuntimas iš $Url" -LogPath $LogPath
    try {
        Start-BitsTransfer -Source $Url -Destination $DestinationPath -ErrorAction Stop
        Write-Log -Message "Failas sėkmingai atsiųstas į $DestinationPath" -LogPath $LogPath
    }
    catch {
        throw "Klaida siunčiantis failą iš '$Url': $($_.Exception.Message)"
    }
}
Export-ModuleMember -Function 'Download-File'

# ==============================================================================
# ZIP archyvo išskleidimo funkcija su patikrinimu
# ==============================================================================
function Expand-UpdatePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$InstallerScriptRelativePath,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Pradedamas archyvo '$ArchivePath' išskleidimas." -LogPath $LogPath
    try {
        Expand-7Zip -ArchiveFileName $ArchivePath -TargetPath $DestinationPath -SecurePassword $Password -ErrorAction Stop
        
        $installScriptFullPath = Join-Path -Path $DestinationPath -ChildPath $InstallerScriptRelativePath
        if (-not (Test-Path -Path $installScriptFullPath) -or (Get-Item $installScriptFullPath).Length -lt 10) { # Tikrinama ar failas ne tuščias
            throw "Išskleidimas nepavyko. Diegimo scenarijus '$InstallerScriptRelativePath' nerastas arba yra tuščias. Patikrinkite archyvo vientisumą ir slaptažodį."
        }
        
        Write-Log -Message "Archyvas sėkmingai išskleistas ir patikrintas." -LogPath $LogPath
    }
    catch {
        throw "Klaida išskleidžiant archyvą '$ArchivePath': $($_.Exception.Message)."
    }
}
Export-ModuleMember -Function 'Expand-UpdatePackage'

# ==============================================================================
# Planuotos užduoties laukimo funkcija
# ==============================================================================
function Wait-ForScheduledTaskToComplete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 1800, # 30 minučių
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    Write-Log -Message "Laukiama, kol bus įvykdyta planuota užduotis '$TaskName'. Laukimo limitas: $TimeoutSeconds s." -LogPath $LogPath
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            throw "Planuota užduotis '$TaskName' neberasta. Galbūt buvo ištrinta anksčiau laiko arba nebuvo sukurta."
        }

        if ($task.State -ne 'Running') {
            $stopwatch.Stop()
            $lastResult = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
            Write-Log -Message "Užduotis '$TaskName' baigė darbą. Būsena: $($task.State). Rezultato kodas: $lastResult." -LogPath $LogPath
            return $lastResult
        }
        Start-Sleep -Seconds 5
    }

    $stopwatch.Stop()
    throw "Viršytas laukimo limitas ($TimeoutSeconds s) laukiant užduoties '$TaskName' pabaigos."
}
Export-ModuleMember -Function 'Wait-ForScheduledTaskToComplete'

# ==============================================================================
# El. pašto pranešimų siuntimo funkcija
# ==============================================================================
function Send-UpdateNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [Parameter(Mandatory = $true)]
        [string]$Body,
        [Parameter(Mandatory = $true)]
        [hashtable]$EmailSettings,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    if (-not $EmailSettings.Enabled) {
        Write-Log -Message "El. pašto pranešimai išjungti konfigūracijoje." -LogPath $LogPath
        return
    }

    Write-Log -Message "Siunčiamas pranešimas el. paštu..." -LogPath $LogPath
    try {
        $sendMailParams = @{
            SmtpServer = $EmailSettings.SmtpServer
            Port       = $EmailSettings.Port
            From       = $EmailSettings.From
            To         = $EmailSettings.To
            Subject    = $Subject
            Body       = $Body
            BodyAsHtml = $true
        }

        if ($EmailSettings.UseSsl) {
            $sendMailParams.UseSsl = $true
        }
        if ($EmailSettings.Credential) {
            $sendMailParams.Credential = $EmailSettings.Credential
        } else {
             Write-Log -Message "Nenurodyti prisijungimo duomenys SMTP serveriui. Bandoma siųsti anonimiškai." -LogPath $LogPath -Level WARN
        }

        Send-MailMessage @sendMailParams -ErrorAction Stop
        Write-Log -Message "Pranešimas sėkmingai išsiųstas." -LogPath $LogPath
    }
    catch {
        $warningMessage = "Klaida siunčiant el. laišką: $($_.Exception.Message)"
        Write-Log -Message $warningMessage -LogPath $LogPath -Level ERROR
        Write-Warning $warningMessage
    }
}
Export-ModuleMember -Function 'Send-UpdateNotification'
