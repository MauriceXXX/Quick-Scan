

function Get-AssistantStore {
    $RegPath = "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"

    Write-Host "`n[+] Scanning Registry..." -ForegroundColor Green

    $SubKeys = Get-ChildItem -Path "Registry::$RegPath" -Recurse -ErrorAction SilentlyContinue
    $AllKeys = @($RegPath) + $SubKeys.PSPath

    foreach ($Key in $AllKeys) {
        $KeyPath = $Key -replace "^Registry::", ""
        $Values = Get-ItemProperty -Path "Registry::$KeyPath" -ErrorAction SilentlyContinue | 
        Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider

        foreach ($Name in ($Values.PSObject.Properties.Name | Sort-Object)) {
            if ($Name.ToLower().Contains("sign.media")) {
                Write-Host "[USB FILE] $Name" -ForegroundColor Magenta
            }
        }
    }
}

function Get-SusSystemFiles {
    Write-Host "`n[+] Scanning System Directories..." -ForegroundColor Green

    $directories = @("C:\Windows\System32", "C:\Windows\SysWOW64")
    $suspiciousFiles = @{}

    foreach ($directory in $directories) {
        if (Test-Path $directory) {
            $files = Get-ChildItem -Path $directory -Recurse -ErrorAction SilentlyContinue -Force | 
            Where-Object { $_.Extension -in ".exe", ".dll", ".efi" }

            foreach ($file in $files) {
                $flags = @()
                if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) { $flags += "HIDDEN" }
                if ($file.Attributes -band [System.IO.FileAttributes]::System) { $flags += "SYSTEM" }

                if ($flags.Count -gt 0) {
                    $suspiciousFiles[$file.FullName] = ($flags -join " | ")
                }
            }
        }
    }

    foreach ($file in $suspiciousFiles.Keys) {
        Write-Host "[SUSPICIOUS FILE] $file -> $($suspiciousFiles[$file])" -ForegroundColor Red
    }
}

function Get-PrefetchBypass {
    Write-Host "`n[+] Scanning Prefetch Directory..." -ForegroundColor Green

    $directory = "C:\Windows\Prefetch"
    $suspiciousFiles = @{}

    if (Test-Path $directory) {
        $files = Get-ChildItem -Path $directory -Recurse -Force

        foreach ($file in $files) {
            $flags = @()
            if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) { $flags += "HIDDEN" }
            if ($file.Attributes -band [System.IO.FileAttributes]::System) { $flags += "SYSTEM" }
            if ($file.Attributes -band [System.IO.FileAttributes]::ReadOnly) { $flags += "READ-ONLY" }

            if ($flags.Count -gt 0) {
                $suspiciousFiles[$file.FullName] = ($flags -join " | ")
            }
        }
    }

    foreach ($file in $suspiciousFiles.Keys) {
        Write-Host "[PREFETCH] $file -> $($suspiciousFiles[$file])" -ForegroundColor Red
    }
}

function Get-ProcessInfo {
    $processDllMapping = @{
      "SysMain"  = "sechost.dll*"
      "DPS"      = "dps.dll*"
      "PcaSvc"   = "pcasvc.dll*"
      "eventlog" = "wevtsvc.dll*"
    }
  
    foreach ($processName in $processDllMapping.Keys) {
      $processId = (Get-CimInstance -Query "SELECT ProcessId FROM Win32_Service WHERE Name='$processName'").ProcessId
  
      if ($processId) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
          $dllPattern = $processDllMapping[$processName]
          $dllsInProcess = $process.Modules | Select-Object -ExpandProperty FileName
  
          $dllLoaded = $dllsInProcess | Where-Object { [System.IO.Path]::GetFileName($_) -like $dllPattern }
          
          if (-not $dllLoaded) {
            Write-Host "[THREAD MANIPULATION] DLL Missing in: $processName" -ForegroundColor Red
          }
  
          $suspendedThreads = @()
          foreach ($thread in $process.Threads) {
            if ($thread.ThreadState -eq 'Wait' -and $thread.WaitReason -eq 'Suspended') {
              $suspendedThreads += $thread
            }
          }
  
          if ($suspendedThreads.Count -gt 0) {
            Write-Host "[SUSPENDED THREAD] Found in: ${processName}:" -ForegroundColor Red
            foreach ($thread in $suspendedThreads) {
              Write-Host " - Thread ID: $($thread.Id), State: $($thread.ThreadState), Wait Reason: $($thread.WaitReason)" -ForegroundColor Yellow
            }
          }
        }
      }
    }
  }

function Get-Tasks {
    Write-Host "`n[+] Scanning Scheduled Tasks..." -ForegroundColor Green

    $tasks = Get-ScheduledTask | Where-Object { $_.Actions }

    foreach ($task in $tasks) {
        $fullTaskPath = "$($task.TaskPath)$($task.TaskName)"

        foreach ($action in ($task.Actions | Where-Object { $_.Execute })) {
            $rawCommand = [System.Environment]::ExpandEnvironmentVariables($action.Execute)
            $arguments = [System.Environment]::ExpandEnvironmentVariables($action.Arguments)
            $commandLine = "$rawCommand $arguments".Trim()

            $filePath = if ($commandLine -match '^\s*"?([^"\s]+?\.[^\s"\\/:]+)"?') { $matches[1] } else { $rawCommand }
            $filePath = $filePath.Trim('"').Trim("'")

            if (Test-Path $filePath) {
                if (Test-Path $filePath -PathType Leaf) {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $filePath
                        if ($signature.Status -eq 'Valid') {
                            # alles ok, optional anzeigen
                        }
                        elseif ($signature.Status -ne 'NotSigned') {
                            Write-Host "[SUSPICIOUS TASK] $fullTaskPath" -ForegroundColor Blue
                            Write-Host "  - Command: $commandLine" -ForegroundColor Red
                            Write-Host "  - Signature: $($signature.Status)" -ForegroundColor Red
                        }
                        else {
                            Write-Host "[SUSPICIOUS TASK] $fullTaskPath" -ForegroundColor Blue
                            Write-Host "  - Command: $commandLine" -ForegroundColor Red
                            Write-Host "  - File is Unsigned" -ForegroundColor DarkRed
                        }
                    }
                    catch {
                        Write-Host "[SUSPICIOUS TASK] $fullTaskPath" -ForegroundColor Blue
                        Write-Host "  - Command: $commandLine" -ForegroundColor Yellow
                        Write-Host "  - Signature Check Failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "[SUSPICIOUS TASK] $fullTaskPath" -ForegroundColor Blue
                Write-Host "  - Command: $commandLine" -ForegroundColor DarkGray
                Write-Host "  - File not Found: $filePath" -ForegroundColor Yellow
            }

        }
    }
}

function Get-EfiScan {
    mountvol X: /S
    if (-not (Test-Path "X:\EFI")) {
        Write-Error "`nEFI partition not found at X:. Aborting."
        return
    }

    Write-Host "`n[+] Scanning EFI .efi files" -ForegroundColor Green
    Get-ChildItem -Path "X:\EFI" -Recurse -Force -Filter *.efi -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_.FullName
        $hash = (Get-FileHash -Algorithm SHA256 -Path $file).Hash
        $sig = Get-AuthenticodeSignature -FilePath $file
        if ($($sig.Status) -eq "Valid") {
            Write-Host "EFI: $file" -ForegroundColor Cyan
            Write-Host "  Hash     : $hash"
            Write-Host "  SigStatus: $($sig.Status)"
            if ($sig.SignerCertificate) {
                Write-Host "  Signer   : $($sig.SignerCertificate.Subject)"
            }
        }
        else {
            Write-Host "EFI: $file" -ForegroundColor Red
            Write-Host "  Hash     : $hash"
            Write-Host "  SigStatus: $($sig.Status)"
            if ($sig.SignerCertificate) {
                Write-Host "  Signer   : $($sig.SignerCertificate.Subject)"
            }
        }
        Write-Host ""
    }

    mountvol X: /D
}

# ===============================
# === Main Execution ============
# ===============================

Write-Host "`n===== SYSTEM SCAN STARTED =====" -ForegroundColor Green

Get-AssistantStore
Get-SusSystemFiles
Get-PrefetchBypass
Get-ProcessInfo
Get-Tasks
Get-EfiScan

Write-Host "`n===== SYSTEM SCAN FINISHED =====" -ForegroundColor Green
