<#

.SYNOPSIS
Configure Start + Taskbar Layout for Windows 11.

.DESCRIPTION
- Apply Start pinned apps (JSON) directly via ConfigureStartPins policy (inline JSON per Microsoft docs)
- Apply Taskbar layout (XML) via StartLayoutFile policy
- Hide Recommended, Recent Jumplists, Recently Added Apps, and Most Used Apps
- Disable recent docs tracking
- Reset option to restore Windows defaults
- Detailed logging to Intune Management Extension logs
- Copies layout to Default user profile for new users
- Windows 11 24H2/25H2 Pro/Enterprise
- Intune/SYSTEM context, idempotent, no prompts

.PARAMETER TestMode
Shows what would happen if the script runs without making changes.

.PARAMETER Reset
Removes all custom configurations and restores Windows defaults.

.EXAMPLE
.\Configure-Win11-StartMenu_v1.5.ps1 -TestMode

.EXAMPLE
.\Configure-Win11-StartMenu_v1.5.ps1 -Reset

.EXAMPLE
.\Configure-Win11-StartMenu_v1.5.ps1

.NOTES
    Author: Yoennis Olmo (updated & hardened)
    Version: v1.5
    Release Date: 06-01-2026

    Intune Info:
    Script type: Platform Script
    Assign to: (Devices)
    Script Settings:
    Run this script using the logged on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell Host: Yes

    Microsoft Documentation References:
    - Start Layout: https://learn.microsoft.com/en-us/windows/configuration/start/layout
    - Taskbar Pinned Apps: https://learn.microsoft.com/en-us/windows/configuration/taskbar/pinned-apps
    - ConfigureStartPins CSP: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#configurestartpins

#>

param(
    [switch]$TestMode,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

# ====
# CONFIG
# ====

$ScriptVersion = "v1.5"

# Hide Recommended section and recents (and related toggles)
$HideRecommendedAndRecents = $true

# Layout file output location
$LayoutRoot = "C:\ProgramData\StartTaskbar"
$TaskbarXmlPath = Join-Path $LayoutRoot "TaskbarLayout.xml"

# Log file location (Intune Management Extension logs)
$LogFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFilePath = Join-Path $LogFolder "Configure-Win11-StartMenu.log"

# Default user shell folder for new user profiles
$DefaultUserShellPath = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"

# START PINS JSON (per Microsoft docs - ConfigureStartPins policy)
# This JSON is stored directly in the registry value (inline), not as a file path
# Types:
# - desktopAppLink: a shortcut path (.lnk)
# - packagedAppId: UWP AUMID/AppUserModelID
# - desktopAppId: Desktop app AUMID (if known)
$StartPinsJson = @'
{
    "pinnedList": [
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft Edge.lnk" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Outlook (classic).lnk" },
        { "packagedAppId": "MSTeams_8wekyb3d8bbwe!MSTeams" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Word.lnk" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Excel.lnk" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\PowerPoint.lnk" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\OneNote.lnk" },
        { "packagedAppId": "Microsoft.CompanyPortal_8wekyb3d8bbwe!App" },
        { "desktopAppLink": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\File Explorer.lnk" },
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk" }
    ]
}
'@

# TASKBAR XML (per Microsoft docs - LayoutModificationTemplate)
# Uses DesktopApplicationID for desktop apps with known AUMID
# Uses UWA element for UWP apps (like Teams) with PinGeneration attribute
# PinListPlacement="Replace" removes default pins and only shows specified pins
$TaskbarXml = @'
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer" />
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Office.OUTLOOK.EXE.15" />
        <taskbar:DesktopApp DesktopApplicationID="MSEdge" />
        <taskbar:UWA AppUserModelID="MSTeams_8wekyb3d8bbwe!MSTeams" PinGeneration="1" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@

# ====
# Logging
# ====

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO",
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    if (-not (Test-Path -LiteralPath $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    # Write to log file
    Add-Content -Path $LogFilePath -Value $logEntry -ErrorAction SilentlyContinue

    # Write to console with color
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "INFO"    { "White" }
            "WARN"    { "Yellow" }
            "ERROR"   { "Red" }
            "SUCCESS" { "Green" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

# ====
# Helpers
# ====

function Test-PathExists {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        Write-Log "Created directory: $Path"
    }
}

function Write-FileWithoutBOM {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content,
        [switch]$TestMode
    )
    
    if ($TestMode) {
        Write-Log "[TEST MODE] Would create file: $Path" -Level "INFO"
        return
    }
    
    try {
        # Write UTF-8 without BOM (required for XML parsing)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
        Write-Log "Created file (UTF-8 no BOM): $Path" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to create file: $Path - $($_.Exception.Message)" -Level "ERROR"
    }
}

function Write-Registry {
    param(
        [Parameter(Mandatory)][ValidateSet("HKLM","HKCU","HKU")][string]$Hive,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet("String","DWord","ExpandString")][string]$Type = "DWord",
        [switch]$TestMode
    )

    $root = switch ($Hive) {
        "HKLM" { "HKEY_LOCAL_MACHINE" }
        "HKCU" { "HKEY_CURRENT_USER" }
        "HKU"  { "HKEY_USERS" }
    }
    $full = "Registry::$root\$Key"

    # Truncate long values for display
    $displayValue = if ($Value.Length -gt 80) { "$($Value.Substring(0,80))..." } else { $Value }

    if ($TestMode) {
        Write-Log "[TEST MODE] Would set registry: $full\$Name = $displayValue (Type: $Type)" -Level "INFO"
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $full)) { New-Item -Path $full -Force | Out-Null }
        
        $propType = switch ($Type) {
            "DWord" { "DWord" }
            "String" { "String" }
            "ExpandString" { "ExpandString" }
        }
        
        if ($Type -eq "DWord") {
            New-ItemProperty -Path $full -Name $Name -Value ([int]$Value) -PropertyType $propType -Force | Out-Null
        } else {
            New-ItemProperty -Path $full -Name $Name -Value ([string]$Value) -PropertyType $propType -Force | Out-Null
        }
        Write-Log "Set registry: $full\$Name = $displayValue" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to set registry: $full\$Name - $($_.Exception.Message)" -Level "ERROR"
    }
}

function Remove-RegistryValue {
    param(
        [Parameter(Mandatory)][ValidateSet("HKLM","HKCU","HKU")][string]$Hive,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Name,
        [switch]$TestMode
    )

    $root = switch ($Hive) {
        "HKLM" { "HKEY_LOCAL_MACHINE" }
        "HKCU" { "HKEY_CURRENT_USER" }
        "HKU"  { "HKEY_USERS" }
    }
    $full = "Registry::$root\$Key"

    if ($TestMode) {
        Write-Log "[TEST MODE] Would remove registry value: $full\$Name" -Level "INFO"
        return
    }

    try {
        if (Test-Path -LiteralPath $full) {
            $prop = Get-ItemProperty -Path $full -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $prop -and $null -ne $prop.$Name) {
                Remove-ItemProperty -Path $full -Name $Name -Force -ErrorAction Stop
                Write-Log "Removed registry value: $full\$Name" -Level "SUCCESS"
            } else {
                Write-Log "Registry value not found (skipped): $full\$Name" -Level "INFO"
            }
        } else {
            Write-Log "Registry key not found (skipped): $full" -Level "INFO"
        }
    } catch {
        Write-Log "Failed to remove registry value: $full\$Name - $($_.Exception.Message)" -Level "ERROR"
    }
}

# ====
# User Hive Functions
# ====

function Get-LoggedOnSIDs {
    try {
        $sids = @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop |
            ForEach-Object { $_.Antecedent -replace '.*Domain="([^"]+)",Name="([^"]+)".*','$1\$2' } |
            Sort-Object -Unique |
            ForEach-Object {
                try {
                    $nt = New-Object System.Security.Principal.NTAccount($_)
                    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $sid
                } catch { $null }
            } | Where-Object { $_ })
        if ($null -eq $sids) { return @() }
        return ,$sids
    } catch { return @() }
}

function Get-UserHivesToLoad {
    $loggedOnSids = Get-LoggedOnSIDs
    $profiles = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
        Test-Path (Join-Path $_.FullName "NTUSER.DAT")
    })

    $targets = @()
    if ($null -eq $profiles -or $profiles.Count -eq 0) {
        return ,$targets
    }

    foreach ($userProfile in $profiles) {
        if ($userProfile.Name -in @("All Users","Default","Default User","Public","DefaultAppPool")) { continue }

        $sid = $null
        try {
            $user = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$($userProfile.Name)'" -ErrorAction SilentlyContinue
            if ($user -and $user.SID) { $sid = $user.SID }
        } catch {}

        $hivePath = Join-Path $userProfile.FullName "NTUSER.DAT"
        if (-not (Test-Path -LiteralPath $hivePath)) { continue }

        $isLoaded = $false
        if ($sid -and (Test-Path -LiteralPath ("Registry::HKEY_USERS\$sid"))) {
            $isLoaded = $true
        }

        $targets += [pscustomobject]@{
            Name       = $userProfile.Name
            Path       = $userProfile.FullName
            SID        = $sid
            HivePath   = $hivePath
            IsLoggedOn = ($sid -and $loggedOnSids -contains $sid)
            IsLoaded   = $isLoaded
        }
    }
    return ,$targets
}

function Import-UserRegistryHives {
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Targets)
    $loaded = @()
    foreach ($t in $Targets) {
        if ($t.IsLoggedOn) { continue }
        if ($t.IsLoaded) { continue }

        if ($t.SID) {
            $mountName = "HKU\$($t.SID)"
        } else {
            $mountName = "HKU\TEMP_$($t.Name)"
        }

        try {
            if (Test-Path -LiteralPath ("Registry::" + $mountName.Replace('\','\\'))) {
                continue
            }
            reg.exe load $mountName "$($t.HivePath)" 2>&1 | Out-Null
            $loaded += @{ Name = $t.Name; Mount = $mountName; SID = $t.SID; Path = $t.Path; IsLoggedOn = $false }
            Write-Log "Loaded registry hive for user: $($t.Name)" -Level "INFO"
        } catch {
            Write-Log "Skipping hive for $($t.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }
    return ,$loaded
}

function Export-UserRegistryHives {
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Loaded)
    foreach ($h in $Loaded) {
        try {
            # Force garbage collection and wait to release handles
            [gc]::Collect()
            Start-Sleep -Milliseconds 500
            reg.exe unload $h.Mount 2>&1 | Out-Null
            Write-Log "Unloaded registry hive for user: $($h.Name)" -Level "INFO"
        } catch {
            Write-Log "Failed to unload hive for $($h.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }
}

function Clear-StartMenuCache {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [switch]$TestMode
    )

    $userProfilePath = "C:\Users\$UserName"
    $cachePaths = @(
        "$userProfilePath\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState",
        "$userProfilePath\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState",
        "$userProfilePath\AppData\Local\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\LocalState",
        "$userProfilePath\AppData\Local\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState",
        "$userProfilePath\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState",
        "$userProfilePath\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState"
    )

    foreach ($path in $cachePaths) {
        if (Test-Path $path) {
            if ($TestMode) {
                Write-Log "[TEST MODE] Would clear cache: $path" -Level "INFO"
            } else {
                try {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleared cache: $path" -Level "SUCCESS"
                } catch {
                    Write-Log "Could not clear cache: $path (may be in use)" -Level "WARN"
                }
            }
        }
    }
}

function Copy-TaskbarLayoutToUserProfile {
    param(
        [Parameter(Mandatory)][string]$UserProfilePath,
        [Parameter(Mandatory)][string]$Content,
        [switch]$TestMode
    )
    
    $userShellPath = Join-Path $UserProfilePath "AppData\Local\Microsoft\Windows\Shell"
    $userLayoutPath = Join-Path $userShellPath "LayoutModification.xml"
    
    if ($TestMode) {
        Write-Log "[TEST MODE] Would copy layout to: $userLayoutPath" -Level "INFO"
        return
    }
    
    try {
        Test-PathExists -Path $userShellPath
        Write-FileWithoutBOM -Path $userLayoutPath -Content $Content
    } catch {
        Write-Log "Failed to copy layout to $userLayoutPath : $($_.Exception.Message)" -Level "WARN"
    }
}

# ====
# Reset Function
# ====

function Invoke-Reset {
    param([switch]$TestMode)

    Write-Log "========================================" -Level "INFO"
    Write-Log "RESET MODE - Restoring Windows Defaults" -Level "WARN"
    Write-Log "========================================" -Level "INFO"

    # Remove HKLM policy registry values
    $policyValues = @(
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "StartLayoutFile" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "ConfigureStartPins" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "LockedStartLayout" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "TaskbarLayoutXML" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "ShowRecommendedSection" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "HideRecommendedSection" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "HideRecentJumplists" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "HideRecentlyAddedApps" },
        @{ Key = "Software\Policies\Microsoft\Windows\Explorer"; Name = "ShowOrHideMostUsedApps" },
        @{ Key = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoRecentDocsHistory" }
    )

    Write-Log "Removing HKLM policy registry values..." -Level "INFO"
    foreach ($reg in $policyValues) {
        Remove-RegistryValue -Hive "HKLM" -Key $reg.Key -Name $reg.Name -TestMode:$TestMode
    }

    # Remove .DEFAULT user registry values
    $defaultUserValues = @(
        "Start_TrackDocs",
        "Start_TrackProgs",
        "Start_ShowMostUsedApps",
        "Start_ShowRecentlyAddedApps"
    )

    Write-Log "Removing .DEFAULT user registry values..." -Level "INFO"
    foreach ($name in $defaultUserValues) {
        Remove-RegistryValue -Hive "HKU" -Key ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name $name -TestMode:$TestMode
    }

    # Process all user profiles
    Write-Log "Processing user profiles..." -Level "INFO"
    $toLoad = Get-UserHivesToLoad
    if ($null -eq $toLoad) { $toLoad = @() }

    $loadedHives = @()
    try {
        if (-not $TestMode) {
            $loadedHives = Import-UserRegistryHives -Targets $toLoad
        }
        if ($null -eq $loadedHives) { $loadedHives = @() }

        # Process offline user hives
        foreach ($h in $loadedHives) {
            Write-Log "Processing offline user: $($h.Name)" -Level "INFO"
            $rel = ($h.Mount -replace '^HKU\\','')
            $perUserKey = "$rel\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            foreach ($name in $defaultUserValues) {
                Remove-RegistryValue -Hive "HKU" -Key $perUserKey -Name $name -TestMode:$TestMode
            }
            
            # Remove user's LayoutModification.xml
            $userLayoutPath = Join-Path $h.Path "AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
            if (Test-Path $userLayoutPath) {
                if ($TestMode) {
                    Write-Log "[TEST MODE] Would delete: $userLayoutPath" -Level "INFO"
                } else {
                    Remove-Item -Path $userLayoutPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted: $userLayoutPath" -Level "SUCCESS"
                }
            }
            
            # Clear Start Menu cache for offline users
            Clear-StartMenuCache -UserName $h.Name -TestMode:$TestMode
        }

        # Process logged-on users
        foreach ($t in $toLoad) {
            if ($t.IsLoggedOn -and $t.SID) {
                Write-Log "Processing logged-on user: $($t.Name)" -Level "INFO"

                # Remove per-user registry values
                $perUserKey = "$($t.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                foreach ($name in $defaultUserValues) {
                    Remove-RegistryValue -Hive "HKU" -Key $perUserKey -Name $name -TestMode:$TestMode
                }

                # Remove user's LayoutModification.xml
                $userLayoutPath = Join-Path $t.Path "AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
                if (Test-Path $userLayoutPath) {
                    if ($TestMode) {
                        Write-Log "[TEST MODE] Would delete: $userLayoutPath" -Level "INFO"
                    } else {
                        Remove-Item -Path $userLayoutPath -Force -ErrorAction SilentlyContinue
                        Write-Log "Deleted: $userLayoutPath" -Level "SUCCESS"
                    }
                }

                # Clear Start Menu cache
                Clear-StartMenuCache -UserName $t.Name -TestMode:$TestMode
            }
        }

    } finally {
        if ($null -eq $loadedHives) { $loadedHives = @() }
        if (-not $TestMode) {
            Export-UserRegistryHives -Loaded $loadedHives
        }
    }

    # Delete layout files
    Write-Log "Removing layout files..." -Level "INFO"
    if ($TestMode) {
        if (Test-Path $TaskbarXmlPath) { Write-Log "[TEST MODE] Would delete: $TaskbarXmlPath" -Level "INFO" }
    } else {
        if (Test-Path $TaskbarXmlPath) {
            Remove-Item -Path $TaskbarXmlPath -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted: $TaskbarXmlPath" -Level "SUCCESS"
        }
    }

    # Delete Default user profile layout
    $defaultLayoutPath = Join-Path $DefaultUserShellPath "LayoutModification.xml"
    if ($TestMode) {
        if (Test-Path $defaultLayoutPath) { Write-Log "[TEST MODE] Would delete: $defaultLayoutPath" -Level "INFO" }
    } else {
        if (Test-Path $defaultLayoutPath) {
            Remove-Item -Path $defaultLayoutPath -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted: $defaultLayoutPath" -Level "SUCCESS"
        }
    }

    Write-Log "========================================" -Level "INFO"
    Write-Log "RESET COMPLETE" -Level "SUCCESS"
    Write-Log "Restart device for changes to take full effect" -Level "INFO"
    Write-Log "========================================" -Level "INFO"
}

# ====
# Execute
# ====

# Initialize log
Write-Log "==========================================" -Level "INFO"
Write-Log "Script started - Version $ScriptVersion" -Level "INFO"
Write-Log "Computer: $env:COMPUTERNAME" -Level "INFO"
Write-Log "Execution Context: $env:USERNAME" -Level "INFO"
Write-Log "Parameters: TestMode=$TestMode, Reset=$Reset" -Level "INFO"
Write-Log "==========================================" -Level "INFO"

if ($Reset) {
    Invoke-Reset -TestMode:$TestMode
    exit 0
}

if ($TestMode) {
    Write-Log "RUNNING IN TEST MODE - NO CHANGES WILL BE APPLIED" -Level "WARN"
}

# Create layout directories
Test-PathExists -Path $LayoutRoot
Test-PathExists -Path $DefaultUserShellPath

# ====
# PART 1: Configure Start Layout (JSON) via ConfigureStartPins policy
# Per Microsoft docs: JSON content goes directly into the registry value (inline)
# This is how Intune's CSP applies the policy
# ====

Write-Log "Configuring Start Layout..." -Level "INFO"

# Compress JSON to single line (required for registry)
$startPinsCompressed = ($StartPinsJson | ConvertFrom-Json | ConvertTo-Json -Depth 10 -Compress)

if ($TestMode) {
    Write-Log "[TEST MODE] Start Pins JSON (compressed): $startPinsCompressed" -Level "INFO"
}

# Apply ConfigureStartPins policy with inline JSON (per Microsoft docs)
Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "ConfigureStartPins" -Value $startPinsCompressed -Type "String" -TestMode:$TestMode

# ====
# PART 2: Configure Taskbar Layout (XML) via StartLayoutFile policy
# Per Microsoft docs: Use StartLayout policy with XML file path
# ====

Write-Log "Configuring Taskbar Layout..." -Level "INFO"

# Save XML file (UTF-8 without BOM for proper XML parsing)
Write-FileWithoutBOM -Path $TaskbarXmlPath -Content $TaskbarXml -TestMode:$TestMode

# Also copy to Default user profile for new users (ensures new profiles get the layout)
$defaultLayoutPath = Join-Path $DefaultUserShellPath "LayoutModification.xml"
Write-FileWithoutBOM -Path $defaultLayoutPath -Content $TaskbarXml -TestMode:$TestMode

# Apply StartLayoutFile policy with XML file path (for Taskbar)
Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Value $TaskbarXmlPath -Type "ExpandString" -TestMode:$TestMode

# Set LockedStartLayout to 0 (allow user changes, required for Windows 11 24H2+)
Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 0 -TestMode:$TestMode

# ====
# PART 3: Hide Recommended + Recents + Most Used + Recently Added
# ====

if ($HideRecommendedAndRecents) {
    Write-Log "Applying Hide Recommended/Recents policies..." -Level "INFO"

    # Policy-level (applies to all users)
    # Hide Recommended section (use HideRecommendedSection=1 per newer docs)
    Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -TestMode:$TestMode
    # Also set ShowRecommendedSection=0 for compatibility with older builds
    Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "ShowRecommendedSection" -Value 0 -TestMode:$TestMode
    # Hide Recent Jumplists
    Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentJumplists" -Value 1 -TestMode:$TestMode
    # Disable recent documents/history
    Write-Registry -Hive "HKLM" -Key "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -TestMode:$TestMode
    # Hide Recently Added Apps
    Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -TestMode:$TestMode
    # Hide Most Used Apps (policy) -> 2 = Hide, 1 = Show
    Write-Registry -Hive "HKLM" -Key "Software\Policies\Microsoft\Windows\Explorer" -Name "ShowOrHideMostUsedApps" -Value 2 -TestMode:$TestMode

    # Per-user defaults for new users (.DEFAULT)
    Write-Log "Applying .DEFAULT user settings..." -Level "INFO"
    Write-Registry -Hive "HKU" -Key ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -TestMode:$TestMode
    Write-Registry -Hive "HKU" -Key ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -TestMode:$TestMode
    Write-Registry -Hive "HKU" -Key ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowMostUsedApps" -Value 0 -TestMode:$TestMode
    Write-Registry -Hive "HKU" -Key ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowRecentlyAddedApps" -Value 0 -TestMode:$TestMode
}

# ====
# PART 4: Process User Profiles
# ====

Write-Log "Processing user profiles..." -Level "INFO"

$loadedHives = @()
try {
    $toLoad = Get-UserHivesToLoad
    if ($null -eq $toLoad) { $toLoad = @() }

    Write-Log "Found $($toLoad.Count) user profile(s) to process" -Level "INFO"

    if ($TestMode) {
        foreach ($t in $toLoad) {
            $status = if ($t.IsLoggedOn) { "Logged On - Will apply settings & clear cache" } elseif ($t.IsLoaded) { "Already Loaded" } else { "Will Load Hive" }
            Write-Log "[TEST MODE] User: $($t.Name) (SID: $($t.SID)) [$status]" -Level "INFO"
        }
    } else {
        $loadedHives = Import-UserRegistryHives -Targets $toLoad
    }

    if ($null -eq $loadedHives) { $loadedHives = @() }

    # Process offline user hives (not logged on)
    foreach ($h in $loadedHives) {
        Write-Log "Applying settings to offline user: $($h.Name)" -Level "INFO"
        
        # Copy taskbar layout to user profile
        Copy-TaskbarLayoutToUserProfile -UserProfilePath $h.Path -Content $TaskbarXml -TestMode:$TestMode
        
        if ($HideRecommendedAndRecents) {
            $rel = ($h.Mount -replace '^HKU\\','')
            $perUserKey = "$rel\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_TrackDocs" -Value 0 -TestMode:$TestMode
            Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_TrackProgs" -Value 0 -TestMode:$TestMode
            Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_ShowMostUsedApps" -Value 0 -TestMode:$TestMode
            Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_ShowRecentlyAddedApps" -Value 0 -TestMode:$TestMode
        }
        
        # Clear Start Menu cache
        Clear-StartMenuCache -UserName $h.Name -TestMode:$TestMode
    }

    # Process logged-on users
    if (-not $TestMode) {
        foreach ($t in $toLoad) {
            if ($t.IsLoggedOn -and $t.SID) {
                Write-Log "Processing logged-on user: $($t.Name)" -Level "INFO"

                # Copy taskbar layout to user profile
                Copy-TaskbarLayoutToUserProfile -UserProfilePath $t.Path -Content $TaskbarXml -TestMode:$TestMode

                # Apply settings directly to logged-on user's registry
                if ($HideRecommendedAndRecents) {
                    $perUserKey = "$($t.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                    Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_TrackDocs" -Value 0 -TestMode:$TestMode
                    Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_TrackProgs" -Value 0 -TestMode:$TestMode
                    Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_ShowMostUsedApps" -Value 0 -TestMode:$TestMode
                    Write-Registry -Hive "HKU" -Key $perUserKey -Name "Start_ShowRecentlyAddedApps" -Value 0 -TestMode:$TestMode
                }

                # Clear Start Menu cache
                Clear-StartMenuCache -UserName $t.Name -TestMode:$TestMode
            }
        }
    }
} finally {
    if ($null -eq $loadedHives) { $loadedHives = @() }
    if (-not $TestMode) {
        Export-UserRegistryHives -Loaded $loadedHives
    }
}

# ====
# Summary
# ====

Write-Log "==========================================" -Level "INFO"
if ($TestMode) {
    Write-Log "TEST MODE COMPLETE - NO CHANGES APPLIED" -Level "WARN"
} else {
    Write-Log "CONFIGURATION COMPLETE" -Level "SUCCESS"
    Write-Log "Start Layout: Applied via ConfigureStartPins policy (inline JSON in registry)" -Level "INFO"
    Write-Log "Taskbar Layout: $TaskbarXmlPath" -Level "INFO"
    Write-Log "Default User Layout: $defaultLayoutPath" -Level "INFO"
    Write-Log "Log file: $LogFilePath" -Level "INFO"
    Write-Log "Registry policies applied:" -Level "INFO"
    Write-Log "  HKLM\Software\Policies\Microsoft\Windows\Explorer" -Level "INFO"
    Write-Log "    - ConfigureStartPins = <JSON content> (inline)" -Level "INFO"
    Write-Log "    - StartLayoutFile = $TaskbarXmlPath" -Level "INFO"
    Write-Log "    - LockedStartLayout = 0" -Level "INFO"
    if ($HideRecommendedAndRecents) {
        Write-Log "    - HideRecommendedSection = 1" -Level "INFO"
        Write-Log "    - ShowRecommendedSection = 0" -Level "INFO"
        Write-Log "    - HideRecentlyAddedApps = 1" -Level "INFO"
        Write-Log "    - ShowOrHideMostUsedApps = 2 (Hide)" -Level "INFO"
        Write-Log "    - HideRecentJumplists = 1" -Level "INFO"
        Write-Log "    - NoRecentDocsHistory = 1" -Level "INFO"
    }
    Write-Log "User profiles processed: $($toLoad.Count)" -Level "INFO"
    Write-Log "IMPORTANT:" -Level "WARN"
    Write-Log "  - New users: Layout applies automatically on first logon" -Level "INFO"
    Write-Log "  - Existing users: Cache cleared - changes apply after logoff/logon" -Level "INFO"
    Write-Log "  - Offline users: Changes apply on next logon" -Level "INFO"
    Write-Log "  - Restart device for policies to take full effect" -Level "INFO"
}
Write-Log "==========================================" -Level "INFO"

exit 0
