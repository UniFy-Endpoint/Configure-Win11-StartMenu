# Configure Windows 11 Start Menu & Taskbar Layout

A PowerShell script to configure Windows 11 Start Menu pinned apps and Taskbar layout for enterprise deployments. Designed for **Windows 11 Pro** devices managed via Microsoft Intune where native policies (Settings Catalog/CSP) are limited to Enterprise/Education editions.

## Overview

This script provides a comprehensive solution to:

- Configure Start Menu pinned apps using inline JSON (per Microsoft CSP documentation)
- Configure Taskbar pinned apps using XML layout files
- Hide the Recommended section and disable recent items tracking
- Apply settings to existing users, new users, and the Default profile
- Reset all configurations back to Windows defaults

## Features

| Feature | Description |
|---------|-------------|
| **Inline JSON for Start Pins** | Stores JSON directly in registry (matches Intune CSP behavior) |
| **Taskbar XML Layout** | Uses Microsoft's LayoutModificationTemplate format |
| **Multi-user Support** | Processes logged-on users, offline users, and Default profile |
| **Idempotent** | Safe to run multiple times without side effects |
| **Test Mode** | Preview changes without applying them |
| **Reset Mode** | Restore Windows defaults with one command |
| **Detailed Logging** | Logs all actions to Intune Management Extension logs |
| **Cache Clearing** | Clears Start Menu cache for immediate effect |

## Requirements

- Windows 11 (24H2/25H2)
- PowerShell 5.1 or later
- Administrator privileges (or SYSTEM context via Intune)

## Installation

1. Download `Configure-Win11-StartMenu_v1_5.ps1`
2. Place in a suitable location (e.g., `C:\Scripts\`)
3. Run as Administrator or deploy via Intune

## Usage

### Standard Execution

```powershell
# Apply all configurations
.\Configure-Win11-StartMenu_v1_5.ps1
```

### Test Mode (Dry Run)

```powershell
# Preview what would happen without making changes
.\Configure-Win11-StartMenu_v1_5.ps1 -TestMode
```

### Reset to Windows Defaults

```powershell
# Remove all custom configurations
.\Configure-Win11-StartMenu_v1_5.ps1 -Reset

# Preview reset without making changes
.\Configure-Win11-StartMenu_v1_5.ps1 -Reset -TestMode
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-TestMode` | Switch | Shows what would happen without making any changes |
| `-Reset` | Switch | Removes all custom configurations and restores Windows defaults |

## Intune Deployment

Deploy as a **Platform Script** with these settings:

| Setting | Value |
|---------|-------|
| Script type | Platform Script |
| Assign to | Devices |
| Run this script using the logged on credentials | **No** |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell Host | **Yes** |

## Configuration Details

### Start Menu Pinned Apps

The script configures Start Menu pins using the `ConfigureStartPins` policy with inline JSON. This is the same method used by Intune's Settings Catalog CSP.

**Default pinned apps:**

| App | Type |
|-----|------|
| Microsoft Edge | Desktop App Link |
| Outlook (classic) | Desktop App Link |
| Microsoft Teams | UWP Package |
| Word | Desktop App Link |
| Excel | Desktop App Link |
| PowerPoint | Desktop App Link |
| OneNote | Desktop App Link |
| Company Portal | UWP Package |
| File Explorer | Desktop App Link |
| OneDrive | Desktop App Link |

**JSON Structure:**

```json
{
    "pinnedList": [
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft Edge.lnk" },
        { "packagedAppId": "MSTeams_8wekyb3d8bbwe!MSTeams" }
    ]
}
```

**Supported pin types:**

| Type | Description | Example |
|------|-------------|---------|
| `desktopAppLink` | Path to .lnk shortcut file | `%ALLUSERSPROFILE%\...\App.lnk` |
| `packagedAppId` | UWP App User Model ID (AUMID) | `MSTeams_8wekyb3d8bbwe!MSTeams` |
| `desktopAppId` | Desktop app AUMID (if known) | `Microsoft.Office.OUTLOOK.EXE.15` |

### Taskbar Pinned Apps

The script configures Taskbar pins using an XML layout file based on Microsoft's `LayoutModificationTemplate` schema.

**Default pinned apps:**

| App | Element Type | Identifier |
|-----|--------------|------------|
| File Explorer | DesktopApp | `Microsoft.Windows.Explorer` |
| Outlook | DesktopApp | `Microsoft.Office.OUTLOOK.EXE.15` |
| Microsoft Edge | DesktopApp | `MSEdge` |
| Microsoft Teams | UWA | `MSTeams_8wekyb3d8bbwe!MSTeams` |

**XML Structure:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer" />
        <taskbar:UWA AppUserModelID="MSTeams_8wekyb3d8bbwe!MSTeams" PinGeneration="1" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
```

**Element types:**

| Element | Use Case | Attributes |
|---------|----------|------------|
| `<taskbar:DesktopApp>` | Desktop apps with known AUMID | `DesktopApplicationID` or `Path` |
| `<taskbar:UWA>` | UWP/Store apps | `AppUserModelID`, `PinGeneration` |

## Registry Modifications

### Machine-Level Policies (HKLM)

All values under `HKLM\Software\Policies\Microsoft\Windows\Explorer`:

| Value Name | Type | Data | Description |
|------------|------|------|-------------|
| `ConfigureStartPins` | REG_SZ | JSON string | Inline JSON defining Start Menu pinned apps |
| `StartLayoutFile` | REG_EXPAND_SZ | File path | Path to Taskbar XML layout file |
| `LockedStartLayout` | REG_DWORD | 0 | Allow users to modify layout (required for 24H2+) |
| `HideRecommendedSection` | REG_DWORD | 1 | Hide the Recommended section |
| `ShowRecommendedSection` | REG_DWORD | 0 | Hide Recommended (legacy compatibility) |
| `HideRecentJumplists` | REG_DWORD | 1 | Hide recent items in taskbar jumplists |
| `HideRecentlyAddedApps` | REG_DWORD | 1 | Hide "Recently added" in Start Menu |
| `ShowOrHideMostUsedApps` | REG_DWORD | 2 | Hide most used apps (2=Hide, 1=Show) |

Under `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`:

| Value Name | Type | Data | Description |
|------------|------|------|-------------|
| `NoRecentDocsHistory` | REG_DWORD | 1 | Disable recent documents tracking |

### Per-User Settings (HKU)

Applied to `.DEFAULT` (new users) and all existing user profiles under `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`:

| Value Name | Type | Data | Description |
|------------|------|------|-------------|
| `Start_TrackDocs` | REG_DWORD | 0 | Disable document tracking |
| `Start_TrackProgs` | REG_DWORD | 0 | Disable program tracking |
| `Start_ShowMostUsedApps` | REG_DWORD | 0 | Hide most used apps |
| `Start_ShowRecentlyAddedApps` | REG_DWORD | 0 | Hide recently added apps |

## File Locations

| File | Path | Purpose |
|------|------|---------|
| Taskbar XML | `C:\ProgramData\StartTaskbar\TaskbarLayout.xml` | Taskbar layout definition |
| Default User Layout | `C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml` | Layout for new user profiles |
| Log File | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Configure-Win11-StartMenu.log` | Script execution log |

## Cache Locations Cleared

The script clears these cache folders to force Start Menu refresh:

- `%LOCALAPPDATA%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState`
- `%LOCALAPPDATA%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState`
- `%LOCALAPPDATA%\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\LocalState`
- `%LOCALAPPDATA%\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState`
- `%LOCALAPPDATA%\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState`
- `%LOCALAPPDATA%\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TempState`

## Customization

### Modifying Start Menu Pins

Edit the `$StartPinsJson` variable in the script:

```powershell
$StartPinsJson = @'
{
    "pinnedList": [
        { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\YourApp.lnk" },
        { "packagedAppId": "YourPackage_publisher!App" }
    ]
}
'@
```

### Modifying Taskbar Pins

Edit the `$TaskbarXml` variable in the script:

```powershell
$TaskbarXml = @'
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate ...>
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationID="YourApp.AUMID" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@
```

### Finding App Identifiers

**For Desktop Apps (AUMID):**

```powershell
Get-StartApps | Where-Object { $_.Name -like "*AppName*" }
```

**For UWP Apps (Package Family Name):**

```powershell
Get-AppxPackage | Where-Object { $_.Name -like "*AppName*" } | Select-Object Name, PackageFamilyName
```

### Disabling Recommended Section Hiding

Set `$HideRecommendedAndRecents = $false` in the CONFIG section.

## Troubleshooting

### Changes Not Applying

1. **Restart the device** - Some policies require a restart
2. **Log off and log on** - Per-user settings apply on logon
3. **Check the log file** - Review `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Configure-Win11-StartMenu.log`

### Start Menu Shows Wrong Pins

1. Clear Start Menu cache manually:
   ```powershell
   Remove-Item "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\*" -Recurse -Force
   ```
2. Restart Explorer:
   ```powershell
   Stop-Process -Name explorer -Force
   ```

### Script Fails with Access Denied

- Ensure running as Administrator
- For Intune deployment, verify "Run this script using the logged on credentials" is set to **No**

### Taskbar Pins Not Appearing

- Verify the app is installed
- Check the AUMID is correct
- Ensure XML file is UTF-8 encoded without BOM

## Reset Mode Details

The `-Reset` parameter performs these actions:

1. **Removes all HKLM policy registry values**
2. **Removes .DEFAULT user registry values**
3. **Processes all user profiles:**
   - Removes per-user registry values
   - Deletes `LayoutModification.xml` from user profiles
   - Clears Start Menu cache
4. **Deletes layout files** from `C:\ProgramData\StartTaskbar\` and Default profile

## References

- [Customize the Start menu layout on Windows 11](https://learn.microsoft.com/en-us/windows/configuration/start/layout)
- [Customize Taskbar pinned apps](https://learn.microsoft.com/en-us/windows/configuration/taskbar/pinned-apps)
- [ConfigureStartPins CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#configurestartpins)
- [Start Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.5 | 2026-01-13 | Combined best features: inline JSON, full logging, reset mode, UTF-8 no BOM, UWA elements, Default profile support |
| v1.4 | 2026-01-06 | Added reset mode, improved logging |
| v1.3 | 2026-01-06 | Inline JSON approach per Microsoft docs, UTF-8 no BOM |
| v1.2 | 2026-01-06 | Initial release with file-based JSON |

