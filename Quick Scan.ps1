

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

function Get-UnsignedSystemFiles {
    param (
        [string[]]$Extensions = @("*.exe", "*.dll", "*.efi"),
        [string[]]$Paths = @("$env:windir\System32", "$env:windir\SysWOW64"),
        [int]$MinSizeKB = 5,
        [int]$MaxSizeMB = 50
    )

    $MinSizeBytes = $MinSizeKB * 1KB
    $MaxSizeBytes = $MaxSizeMB * 1MB

    Write-Host "`n[+] Scanning for Unsigned System Files..." -ForegroundColor Green

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            foreach ($ext in $Extensions) {
                Get-ChildItem -Path $path -Filter $ext -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
                    $_.Length -ge $MinSizeBytes -and $_.Length -le $MaxSizeBytes
                } | ForEach-Object {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $_.FullName
                        if ($signature.Status -ne 'Valid') {
                            Write-Host "[UNSIGNED FILE] $($_.FullName)" -ForegroundColor Yellow
                            Write-Host "  Size    : {0:N2} MB" -f ($_.Length / 1MB)
                            Write-Host "  Status  : $($signature.Status)"
                            if ($signature.SignerCertificate) {
                                Write-Host "  Signer  : $($signature.SignerCertificate.Subject)"
                            }
                            Write-Host ""
                        }
                    } catch {
                    }
                }
            }
        } else {
            Write-Warning "Path not found: $path"
        }
    }
}

function Format-EventRow {
    param (
        [string]$Time,
        [string]$Type,
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host ("{0,-20} {1,-20} {2}" -f $Time, $Type, $Message) -ForegroundColor $Color
}

function Get-DefenderEvents {
    param (
        [int[]]$EventIds = @(5000, 5001, 5007, 1116),
        [string]$LogName = 'Microsoft-Windows-Windows Defender/Operational'
    )

    Write-Host "Loading Defender Events...`n" -ForegroundColor Cyan
    Write-Host ("{0,-20} {1,-20} {2}" -f "Timestamp", "Type", "Details") -ForegroundColor Gray
    Write-Host ("-" * 70) -ForegroundColor DarkGray

    $query = @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">*[System[EventID=$($EventIds -join ' or EventID=')]]</Select>
  </Query>
</QueryList>
"@

    try {
        $events = Get-WinEvent -FilterXml $query -ErrorAction Stop

        if (-not $events) {
            Write-Host "No Defender Events Found." -ForegroundColor DarkGray
            return
        }

        foreach ($event in $events) {
            $eventXml = [xml]$event.ToXml()
            $timestamp = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $eventID   = $event.Id

            switch ($eventID) {
                5000 {
                    Format-EventRow -Time $timestamp -Type "Activated" -Message "Defender aktiviert" -Color Green
                }
                5001 {
                    Format-EventRow -Time $timestamp -Type "Deactivated" -Message "Defender deaktiviert" -Color Red
                }
                5007 {
                    $newValue = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'New Value' }).'#text'
                    $oldValue = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Old Value' }).'#text'

                    $newPath = $null
                    if ($newValue -match 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([A-Z]:\\[^=]*)') {
                        $newPath = $matches[1].Trim()
                    }

                    $oldPath = $null
                    if ($oldValue -match 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([A-Z]:\\[^=]*)') {
                        $oldPath = $matches[1].Trim()
                    }

                    if ($newPath -and -not $oldPath) {
                        Format-EventRow -Time $timestamp -Type "Exclusion Added" -Message $newPath -Color Cyan
                    }
                    elseif ($oldPath -and -not $newPath) {
                        Format-EventRow -Time $timestamp -Type "Exclusion Removed" -Message $oldPath -Color DarkYellow
                    }
                    elseif ($oldPath -and $newPath) {
                        Format-EventRow -Time $timestamp -Type "Exclusion Changed" -Message "$oldPath → $newPath" -Color Yellow
                    }
                }
                1116 {
                    $filePath = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'Path' }).'#text'
                    if ($filePath -match 'file:_([^;]+)') {
                        $path = $matches[1].Trim()
                        Format-EventRow -Time $timestamp -Type "Threat Detected" -Message $path -Color DarkRed
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error loading Result: $_" -ForegroundColor Red
    }
}

function Get-UsbStickTimeline {
    $logsAndEvents = @{
        'Microsoft-Windows-Kernel-PnP/Configuration'     = @(400, 410, 420)
        'Microsoft-Windows-Kernel-ShimEngine/Operational' = @(4)
        'Microsoft-Windows-StorageSpaces-Driver/Operational' = @(207)
    }

    $queryXml = "<QueryList>"
    $i = 0
    foreach ($log in $logsAndEvents.Keys) {
        $ids = $logsAndEvents[$log] -join " or EventID="
        $queryXml += @"
  <Query Id="$i" Path="$log">
    <Select Path="$log">*[System[(EventID=$ids)]]</Select>
  </Query>
"@
        $i++
    }
    $queryXml += "</QueryList>"

    try {
        $events = Get-WinEvent -FilterXml $queryXml -ErrorAction SilentlyContinue
        if (-not $events) {
            Write-Host "Keine passenden USB-Stick-Ereignisse gefunden." -ForegroundColor Yellow
            return
        }

        $timeline = @()

        $id207List = $events | Where-Object { $_.Id -eq 207 } | Sort-Object TimeCreated

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $ts = $evt.TimeCreated
            $id = $evt.Id
            $log = $evt.LogName
            $info = ""
            $color = "White"

            switch ($log) {
                "Microsoft-Windows-Kernel-PnP/Configuration" {
                    $devID = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DeviceInstanceId'}).'#text'
                    if ($devID -match "USBSTOR" ) {
                        switch ($id) {
                            400 { 
                                $info = "USB INSTALL: ($devID)"
                                $color = "Green"
                            }
                            410 { 
                                $info = "USB UNPLUG: ($devID)"
                                $color = "Yellow"
                            }
                            420 { 
                                $info = "USB UNINSTALL: $devID"
                                $color = "Red"
                            }
                        }
                    }
                }
                "Microsoft-Windows-Kernel-ShimEngine/Operational" {
                    $devName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DeviceName'}).'#text'
                    if ($devName -match "USBSTOR") {
                        $closest = $id207List | Where-Object {
                            ($_.TimeCreated -ge $ts) -and 
                            ($_.TimeCreated -le $ts.AddSeconds(5))
                        } | Select-Object -First 1

                        if ($closest) {
                            $xml207 = [xml]$closest.ToXml()
                            $model = ($xml207.Event.EventData.Data | Where-Object {$_.Name -eq 'DriveModel'}).'#text'
                            $serial = ($xml207.Event.EventData.Data | Where-Object {$_.Name -eq 'DriveSerial'}).'#text'
                            $info = "USB PLUGIN: $model, Serial: $serial"
                        } else {
                            $info = "USB PLUGIN ($devName)"
                        }
                        $color = "Cyan"
                    }
                }
            }

            if ($info) {
                $timeline += [PSCustomObject]@{
                    Time     = $ts
                    EventID  = $id
                    LogName  = $log
                    Info     = $info
                    Color    = $color
                }
            }
        }

        $timeline | Sort-Object Time | ForEach-Object {
            Write-Host "[$($_.Time)] $($_.Info)" -ForegroundColor $_.Color
        }

    }
    catch {
        Write-Host "Fehler beim Abrufen der USB-Timeline: $_" -ForegroundColor Red
    }
}

function Menu {
    Clear-Host
    do {
        Write-Host "======================" -ForegroundColor Cyan
        Write-Host "        MENU" -ForegroundColor Cyan
        Write-Host "======================" -ForegroundColor Cyan
        Write-Host "1. Quick Scan"
        Write-Host "2. Defender Scan"
        Write-Host "3. USB Scan"
        Write-Host "4. Beenden"
        Write-Host ""
        $choice = Read-Host "Bitte eine Option wählen (1-4)"

        switch ($choice) {
            '1' {
                QuickScan
                Pause
            }
            '2' {
                DefenderScan
                Pause
            }
            '3' {
                USBScan
                Pause
            }
            '4' {
                Write-Host "Exiting..." -ForegroundColor Yellow
            }
            Default {
                Write-Host "Wrong input." -ForegroundColor Red
                Pause
            }
        }
        Clear-Host
    } while ($choice -ne '4')
}

function Pause {
    Write-Host ""
    Read-Host "Press Enter..."
}

function QuickScan {
    Write-Host "`n===== QUICK SCAN STARTED =====" -ForegroundColor Green

    Get-AssistantStore
    Get-SusSystemFiles
    Get-PrefetchBypass
    Get-ProcessInfo
    Get-Tasks
    Get-EfiScan
    Get-UnsignedSystemFiles

    Write-Host "`n===== QUICK SCAN FINISHED =====" -ForegroundColor Green
}

function DefenderScan {
    Write-Host "`n===== DEFENDER SCAN STARTED =====" -ForegroundColor Green
    Get-DefenderEvents
    Write-Host "`n===== DEFENDER SCAN FINISHED =====" -ForegroundColor Green
}

function USBScan {
    Write-Host "`n===== USB SCAN STARTED =====" -ForegroundColor Green
    Get-UsbStickTimeline
    Write-Host "`n===== USB SCAN FINISHED =====" -ForegroundColor Green
}

Menu
