# Requires -Version 5.1

<#
.SYNOPSIS
    Įdiegia UWP programą iš nurodyto šaltinio katalogo.
.DESCRIPTION
    Šis scenarijus automatiškai bando įdiegti UWP paketą su visomis rastomis priklausomybėmis.
    Jei diegimas nepavyksta dėl priklausomybių konflikto, jis automatiškai bando
    įdiegti paketą iš naujo be priklausomybių. Ši versija yra pritaikyta veikti
    visiškai automatizuotai, be jokios vartotojo sąveikos.
.NOTES
    Versija: 3.2
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath
)

# Griežtas režimas ir išsamus klaidų fiksavimas.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Žurnalo failas kuriamas vartotojo laikiname kataloge.
$logFile = Join-Path -Path $env:TEMP -ChildPath "UWP_Install_Log.txt"

function Write-InstallLog {
    param([string]$Message)
    $logEntry = "[{0}] - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $logFile -Value $logEntry
}

try {
    Write-InstallLog "--- Pradedamas universalus diegimo scenarijus (v8.0) ---"
    Write-InstallLog "Ieškoma diegimo failų kataloge: $SourcePath"

    # Ieškome pagrindinio diegimo paketo pagal dažniausiai pasitaikančius plėtinius.
    $mainPackageExtensions = @("*.msixbundle", "*.eappxbundle", "*.appxbundle", "*.msix", "*.appx")
    $mainPackage = Get-ChildItem -Path $SourcePath -Recurse -Include $mainPackageExtensions | Where-Object { $_.Name -notlike "*_x86_*" -and $_.Name -notlike "*_arm_*" } | Sort-Object -Property Length -Descending | Select-Object -First 1

    if (-not $mainPackage) {
        throw "Pagrindinis diegimo paketas nerastas nurodytame kataloge."
    }
    Write-InstallLog "Rastas pagrindinis paketas: $($mainPackage.FullName)"

    # Surandame visas galimas priklausomybes tame pačiame kataloge.
    $dependencyPackages = Get-ChildItem -Path $mainPackage.DirectoryName -Recurse -Filter "*.appx" | Where-Object { $_.FullName -ne $mainPackage.FullName } | ForEach-Object { $_.FullName }

    try {
        # Pirmas bandymas: diegiama su visomis rastomis priklausomybėmis.
        Write-InstallLog "Pirmas bandymas: diegiama su visomis rastomis priklausomybėmis..."
        if ($dependencyPackages) {
            Write-InstallLog "Rastos priklausomybės: $($dependencyPackages -join ', ')"
            Add-AppxPackage -Path $mainPackage.FullName -DependencyPath $dependencyPackages -ForceApplicationShutdown
        } else {
            Write-InstallLog "Priklausomybių nerasta, diegiama be jų."
            Add-AppxPackage -Path $mainPackage.FullName -ForceApplicationShutdown
        }
    }
    catch {
        # Jei pirmas bandymas nepavyko dėl priklausomybių problemos (dažna klaida), bandome be jų.
        if ($_.Exception.HResult -eq 0x80073CF3) {
            Write-InstallLog "Pirmas bandymas nepavyko dėl priklausomybių konflikto. Bandymas iš naujo be priklausomybių..."
            Add-AppxPackage -Path $mainPackage.FullName -ForceApplicationShutdown
        }
        else {
            # Jei klaida kitokia, permetame ją toliau.
            throw
        }
    }

    Write-InstallLog "Programa sėkmingai įdiegta."
    exit 0 # Sėkminga pabaiga
}
catch {
    Write-InstallLog "KRITINĖ KLAIDA diegiant: $($_.Exception.Message)"
    Write-InstallLog "Išsami informacija: $($_.ToString())"
    exit 1 # Pabaiga su klaida
}
