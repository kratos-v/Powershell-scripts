function services
{
$runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }
$automaticServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic' }
$automaticDelayedServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic (Delayed Start)' }
"`n`nRunning Services:`n================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$runningServices | Format-Table -Property Name, DisplayName, Status | Out-File -Append -FilePath $outputfile -Encoding UTF8
"Services with Automatic Startup Type:`n=====================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$automaticServices | Format-Table -Property Name, DisplayName, StartType | Out-File -Append -FilePath $outputfile -Encoding UTF8
"Services with Automatic (Delayed Start) Startup Type:`n=====================================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$automaticDelayedServices | Format-Table -Property Name, DisplayName, StartType | Out-File -Append -FilePath $outputfile -Encoding UTF8
}
function GetActiveScheduledTasks {
    $ScheduledTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            Author = $_.Principal.UserId
            NextRunTime = $_.NextRunTime
            LastRunTime = $_.LastRunTime
            Status = $_.State
        }
    }
    return $ScheduledTasks
}
function RunRegistrykeys {

    param (
        [string]$registryPath
    )
    $values = Get-ItemProperty -Path $registryPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") }
    }
    return $values
}
function defenderexclusions
{
"`n`nMicrosoft Defender Exclusions added on the host:`n=====================================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$defenderExclusionsPath = @("HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions", "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes")
foreach ($keys in $defenderExclusionsPath)
{
Get-ItemProperty -Path $keys | ForEach-Object {
        $_.PSObject.Properties} | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | Out-File -Append -FilePath $outputfile -Encoding UTF8

}
}
function installedapplications
{
$registryPath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")

foreach ($value in $registryPath)
{
$installedApps = Get-ChildItem -Path $value | ForEach-Object {
    $displayName = (Get-ItemProperty -Path $_.PSPath -Name "DisplayName").DisplayName
    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        $displayVersion = (Get-ItemProperty -Path $_.PSPath -Name "DisplayVersion").DisplayVersion
        $publisher = (Get-ItemProperty -Path $_.PSPath -Name "Publisher").Publisher
        $installDate = (Get-ItemProperty -Path $_.PSPath -Name "InstallDate").InstallDate

        [PSCustomObject]@{
            DisplayName = $displayName
            DisplayVersion = $displayVersion
            Publisher = $publisher
            InstallDate = $installDate
        }
    }
}
$installedApps | Out-File -Append -FilePath $outputfile -Encoding UTF8
}
}
function getprocess
{
$processes = Get-Process | Select-Object Id, ProcessName, Path, CPU, WorkingSet | ForEach-Object {
    $process = $_
    $signerInfo = $null

    try {
        $signerInfo = Get-AuthenticodeSignature -FilePath $process.Path
    } catch {
    }
        if ($signerInfo -ne $null) {
        $subject = $signerInfo.SignerCertificate.Subject
        $cn = ($subject -split ',' | Where-Object { $_ -like 'CN=*' }) -replace 'CN=', ''
    } else {
        $cn = "N/A"
    }
    [PSCustomObject]@{
        ProcessName = $process.ProcessName
        Path = $process.Path
        RAMUsageMB = [math]::Round($process.WorkingSet / 1MB, 2)
        CPUUsage = $process.CPU
        IsValid = $signerInfo.Status -eq 'Valid'
        SignerCN = $cn
        
    }
} 
$processes | Format-Table -AutoSize | Out-File -Append -FilePath $outputfile -Encoding UTF8
}

$ErrorActionPreference = 'SilentlyContinue'
New-Item -Path "C:\temp" -ItemType Directory -ErrorAction SilentlyContinue
$outputfile = "C:\temp\output.txt"
$localDateTime = Get-Date
$utcDateTime = $localDateTime.ToUniversalTime()
"Device Date and Time: $localDateTime" | Out-File -FilePath $outputfile -Encoding UTF8
"UTC Date and Time: $utcDateTime" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hostname = [System.Net.Dns]::GetHostName()
$fqdn = [System.Net.Dns]::GetHostByName($hostname).HostName
$ipAddresses = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
$macAddress = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).MacAddress
$currentActiveUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$osDetails = Get-CimInstance -ClassName Win32_OperatingSystem
"`n`nDevice Details:`n==============="  | Out-File -Append -FilePath $outputfile -Encoding UTF8
"Hostname: $hostname" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"FQDN: $fqdn" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"IP Addresses: $($ipAddresses -join ', ')" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"MAC Address: $macAddress" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"Current Active User: $currentActiveUser" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"OS Details:" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"   OS Name: $($osDetails.Caption)" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"   Version: $($osDetails.Version)" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"   Build Number: $($osDetails.BuildNumber)" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"   Architecture: $($osDetails.OSArchitecture)" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`n`nList of Local user accounts in the host`n=======================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
Get-Localuser | Format-Table -AutoSize | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`n`nList of user accounts added into local Administrators group in the host`n=======================================================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize | Out-File -Append -FilePath $outputfile -Encoding UTF8
defenderexclusions
"`n`nList of Environment Variables in the host`n=======================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
Get-Childitem -path env: | Format-Table -AutoSize | Out-File -Append -FilePath $outputfile -Encoding UTF8
$activeScheduledTasks = GetActiveScheduledTasks
$hklm_run_registrypath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$hklm_runonce_registrypath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$hkcu_run_registrypath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$hkcu_runonce_registrypath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$hkcu_Logon_Script = "HKCU:\Environment"
$hklm_run_data = RunRegistrykeys -registryPath $hklm_run_registrypath
$hklm_runonce_data = RunRegistrykeys -registryPath $hklm_runonce_registrypath
$hkcu_run_data = RunRegistrykeys -registryPath $hkcu_run_registrypath
$hkcu_runonce_data = RunRegistrykeys -registryPath $hkcu_runonce_registrypath
$hkcu_logon_script_data = RunRegistrykeys -registryPath $hkcu_Logon_Script
$scheduledtaskData = $activeScheduledTasks
"`nList of Active Scheduled Tasks in the host`n==========================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$scheduledtaskData | Format-Table -AutoSize | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`n`nList of Auto Run Keys present in the host`n==========================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`nHKEY_LOCAL_MACHINE Run Keys`n===========================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hklm_run_data | Out-File -Append -FilePath $outputfile -Encoding UTF8
"HKEY_LOCAL_MACHINE RunOnce Keys`n===============================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hklm_runonce_data | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`nHKEY_CURRENT_USER Run Keys`n==========================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hkcu_run_data | Out-File -Append -FilePath $outputfile -Encoding UTF8
"HKEY_CURRENT_USER RunOnce Keys`n==============================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hkcu_runonce_data | Out-File -Append -FilePath $outputfile -Encoding UTF8
"HKEY_CURRENT_USER Logon script keys`n===================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
$hkcu_logon_script_data | Out-File -Append -FilePath $outputfile -Encoding UTF8
"`n`nList of Installed applications`n===================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
installedapplications
services
"`n`nList of Running Processes on the host`n===========================================" | Out-File -Append -FilePath $outputfile -Encoding UTF8
getprocess
Write-Host "`n`nArtifacts collection process completed. Please run the below command to download the output file`ndownload C:\temp\output.txt &"