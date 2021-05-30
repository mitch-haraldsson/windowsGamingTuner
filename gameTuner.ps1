#Requires -RunAsAdministrator
Param(
    [Parameter(Mandatory = $false)] [Switch] $Disable,
    [Parameter(Mandatory = $false)] [Switch] $SkipReboot
)

function Set-GameMode {
    param(
        [switch] $Disable
    )
    if ($Disable) {
        Write-Output "Disabling game mode"
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value "0" -Type String -Force
    }
    else {
        Write-Output "Enabling game mode"
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value "1" -Type String -Force
    }
}

function Set-Nagle {
    param(
        [switch] $Disable
    )
    $entries = (Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces -recurse -erroraction silentlycontinue | get-itemproperty | where { $_.'DhcpIpAddress' -ne $null });
    Write-Output "Changing nagle algorithm behavior for all relevant network interfaces..."
    Foreach ($entry in $entries) {
        if ($Disable) {
            Write-Output "Enabling Nagle for $($entry.DhcpIpAddress)"
            Write-Output "HKLM:$($entry.PSPath.split("::HKEY_LOCAL_MACHINE")[1])"
            Remove-ItemProperty -Path "HKLM:$($entry.PSPath.split("::HKEY_LOCAL_MACHINE")[1])" -Name "TcpAckFrequency" -Force
            Remove-ItemProperty -Path "HKLM:$($entry.PSPath.split("::HKEY_LOCAL_MACHINE")[1])" -Name "TCPNoDelay" -Force
        }
        else {
            Write-Output "Disabling Nagle for $($entry.DhcpIpAddress)" 
            $e = New-ItemProperty -Path "HKLM:$($entry.PSPath.split("::HKEY_LOCAL_MACHINE")[1])" -Name "TcpAckFrequency" -Value "1" -PropertyType DWORD -Force
            $e = New-ItemProperty -Path "HKLM:$($entry.PSPath.split("::HKEY_LOCAL_MACHINE")[1])" -Name "TCPNoDelay" -Value "1" -PropertyType DWORD -Force
        }
    }
}

function Set-TurnOffEnhancedPointerPrecission {
    param(
        [switch] $Disable
    )
    if ($Disable) {
        Write-Output "Enabling mouse acceleration"
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "1" -PropertyType String -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "6" -PropertyType String -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "10" -PropertyType String -Force
    }
    else {
        Write-Output "Disabling mouse acceleration"
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -PropertyType String -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -PropertyType String -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -PropertyType String -Force
    }
}


function Set-TurnOffAccessibilityShortCuts {
    param(
        [switch] $Disable
    )
    if ($Disable) {
        Write-Output "Turning accessibility shortcuts back on"
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" -Force
    }
    else {
        Write-Output "Turning accessibility shortcuts off"
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" -Force
    }
}

function Set-TurnOffWindowsAutoUpdate {
    param(
        [switch] $Disable
    )

    if ($Disable) {
        Write-Output "Turning auto update back on"
        $e = Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Force
    }
    else {
        Write-Output "Turning auto update off"
        $e = New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWORD -Value "1" -Force
    }   
}

function Set-BestPerformanceStyle {
    param(
        [switch] $Disable
    )

    if ($Disable) {
        Write-Output "Enabling default styles"
        $e = Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnails" -Force 
        $e = New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ThemeManager" -Name "ThemeActive" -Value "1" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "Composition" -Value "1" -Type DWORD -Force
        $e = Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "ColorizationOpaqueBlend" -Force
        $e = Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "AlwaysHibernateThumbnails" -Force 
        $e = Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value "1" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWORD -Value "1" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWORD -Value "1" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ThemeManager" -Name "ThemeActive" -Value "1" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type DWORD -Value "2" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MinAnimate" -Value ([byte[]](0x9e, 0x1e, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00)) -Type BINARY -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1" -Type DWORD -Force
    }
    else {
        Write-Output "Disable default styles"
        $e = New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnails" -Type DWORD -Value "1" -Force
        $e = New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ThemeManager" -Name "ThemeActive" -Value "0" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "Composition" -Value "0" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "ColorizationOpaqueBlend" -Value "0" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM]" -Name "AlwaysHibernateThumbnails" -Value "0" -Type DWORD -Force 
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWORD -Value "2" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWORD -Value "0" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWORD -Value "0" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWORD -Value "0" -Force
        $e = New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ThemeManager" -Name "ThemeActive" -Value "0" -Type DWORD -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type DWORD -Value "0" -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MinAnimate" -Value ([byte[]](0x90, 0x12, 0x01, 0x80, 0x10, 0x00, 0x00, 0x00)) -Type BINARY -Force
        $e = New-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Type DWORD -Force            
    }
}

function Set-CreateNewGamingformancePowerPlan {
    $gamingPlan = (Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -Filter "ElementName = 'Gaming Performance'").InstanceID
    $gamingPlanId = Select-String -Input $gamingPlan -Pattern "\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b" -AllMatches | % { $_.Matches } | % { $_.Value }
    if ($gamingPlanId -ne $null) {
        Write-Output "Gaming power plan already exists, activating it"
        powercfg -setactive $gamingPlanId
    }
    else {
        $ppres = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
        $createPowerPlanId = Select-String -Input $ppres -Pattern "\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b" -AllMatches | % { $_.Matches } | % { $_.Value }
        powercfg -changename $createPowerPlanId "Gaming Performance"
        Write-Output "Created gaming power plan"
        powercfg -setactive $createPowerPlanId
        Write-Output "Activated gaming power plan"
    }
}


if ($Disable) {
    Set-GameMode -Disable
    Set-Nagle -Disable
    Set-TurnOffEnhancedPointerPrecission -Disable
    Set-TurnOffAccessibilityShortCuts -Disable
    Set-TurnOffWindowsAutoUpdate -Disable
    Set-BestPerformanceStyle -Disable
}
else {
    Set-GameMode
    Set-Nagle
    Set-TurnOffEnhancedPointerPrecission
    Set-TurnOffAccessibilityShortCuts
    Set-TurnOffWindowsAutoUpdate
    Set-CreateNewGamingformancePowerPlan
    Set-BestPerformanceStyle
}
if ($SkipReboot) {
    Write-Output "`n**** Reboot your system so all changes take affect ****`n"
}
else {
    Restart-Computer -Force
}