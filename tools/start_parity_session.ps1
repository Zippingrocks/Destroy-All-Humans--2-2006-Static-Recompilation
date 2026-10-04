#requires -Version 7.0
<#
.SYNOPSIS
Start one parity process on its own inactive Windows desktop.
.EXAMPLE
.\tools\start_parity_session.ps1 -Mode LaunchXemu
.EXAMPLE
.\tools\start_parity_session.ps1 -Mode LaunchRecomp -PrepareOnly
.NOTES
Each invocation allocates a new run directory and new logs/manifests. No process
is stopped, no previous PID is trusted, and the interactive desktop is untouched.
The launcher manages desktop lifetime; killing it prematurely is unsupported.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('LaunchXemu', 'LaunchRecomp')]
    [string]$Mode,
    [string]$SessionDirectory,
    [string]$RecompExecutable,
    [string]$RecompMap,
    [string]$ExtractionDirectory,
    [string]$GameSavesDirectory,
    [string]$GameFilesDirectory,
    [string[]]$RecompArguments = @(),
    [hashtable]$Environment = @{},
    [ValidateRange(1024, 65535)][int]$GdbPort = 1236,
    [ValidateRange(1024, 65535)][int]$QmpPort = 4446,
    [switch]$PrepareOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
if (-not $SessionDirectory) { $SessionDirectory = Join-Path $project 'diagnostics\codex_parity_20260925' }
if (-not $RecompExecutable) { $RecompExecutable = Join-Path $project 'build-parity\Release\dah2_recomp.exe' }
if (-not $RecompMap) { $RecompMap = Join-Path $project 'build-parity\Release\dah2_recomp.map' }
if (-not $ExtractionDirectory) { $ExtractionDirectory = Join-Path $project 'Destroy All Humans! 2 (USA, Europe) (En,Fr,De,Es,It).xiso' }
if (-not $GameSavesDirectory) { $GameSavesDirectory = Join-Path $project 'game_saves' }
if (-not $GameFilesDirectory) { $GameFilesDirectory = Join-Path $project 'game_files' }
$SessionDirectory = [IO.Path]::GetFullPath($SessionDirectory)
$launcher = Join-Path $PSScriptRoot 'BackgroundDesktopLauncher.exe'

function Assert-PlainPath([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ([bool]$item.PSIsContainer -ne $Directory) { throw "Unexpected path type: $Path" }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "A real private file/directory is required, not a junction or symbolic link: $Path"
    }
}

function Copy-PrivateTree([string]$Source, [string]$Destination) {
    Assert-PlainPath $Source $true
    $links = @(Get-ChildItem -LiteralPath $Source -Recurse -Force -Attributes ReparsePoint)
    if ($links.Count) { throw "Refusing to copy writable state containing a reparse point: $($links[0].FullName)" }
    if (Test-Path -LiteralPath $Destination) { throw "Refusing to overwrite staged state: $Destination" }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse
    Assert-PlainPath $Destination $true
}

function Write-NewJson([string]$Path, [object]$Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}

function New-RunDirectory([string]$Parent) {
    [IO.Directory]::CreateDirectory($Parent) | Out-Null
    Assert-PlainPath $Parent $true
    for ($number = 1; $number -le 100000; $number++) {
        $candidate = Join-Path $Parent "run$number"
        if (Test-Path -LiteralPath $candidate) { continue }
        try {
            New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
            return $candidate
        } catch {
            if (Test-Path -LiteralPath $candidate) { continue }
            throw
        }
    }
    throw "No free run directory under $Parent"
}

function ConvertTo-WindowsArgument([string]$Value) {
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * ($slashes * 2 + 1))).Append('"')
        } else {
            [void]$builder.Append(('\' * $slashes)).Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(('\' * ($slashes * 2))).Append('"')
    return $builder.ToString()
}

function Get-XemuPath([string]$Config, [string]$Key) {
    $matches = [regex]::Matches($Config, ('(?m)^\s*' + [regex]::Escape($Key) + '\s*=\s*(?<value>''[^'']*''|"(?:[^"\\]|\\.)*")\s*(?:#.*)?$'))
    if ($matches.Count -ne 1) { throw "Expected one quoted $Key in private xemu.toml." }
    $value = $matches[0].Groups['value'].Value
    if ($value.StartsWith("'")) { return $value.Substring(1, $value.Length - 2) }
    return ($value | ConvertFrom-Json)
}

function Assert-LoopbackPortFree([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() }
    catch { throw "Local debugger port $Port is occupied. Choose another port or manage the known owning process separately." }
    finally { $listener.Stop() }
}

Assert-PlainPath $launcher $false
if ($Mode -eq 'LaunchXemu') {
    if ($GdbPort -eq $QmpPort) { throw 'GDB and QMP must use distinct ports.' }
    $emulator = Join-Path $SessionDirectory 'xemu'
    $executable = Join-Path $emulator 'xemu.exe'
    $configSource = Join-Path $emulator 'xemu.toml'
    Assert-PlainPath $emulator $true
    Assert-PlainPath $executable $false
    Assert-PlainPath $configSource $false
    $configText = Get-Content -LiteralPath $configSource -Raw
    $audio = [regex]::Match($configText, '(?ms)^\[audio\]\s*(?<body>.*?)(?=^\[|\z)').Groups['body'].Value
    if ($audio -notmatch '(?m)^\s*volume_limit\s*=\s*0\s*(?:#.*)?$') {
        throw 'Private xemu config must set [audio] volume_limit = 0 for background operation.'
    }
    $inputConfig = [regex]::Match($configText, '(?ms)^\[input\]\s*(?<body>.*?)(?=^\[|\z)').Groups['body'].Value
    if ($inputConfig -notmatch '(?m)^\s*auto_bind\s*=\s*false\s*(?:#.*)?$') {
        throw 'Private xemu config must set [input] auto_bind = false.'
    }
    $bindings = [regex]::Match($configText, '(?ms)^\[input\.bindings\]\s*(?<body>.*?)(?=^\[|\z)').Groups['body'].Value
    foreach ($binding in [regex]::Matches($bindings, '(?m)^\s*port[1-4]\s*=\s*(?<value>.+?)\s*$')) {
        if ($binding.Groups['value'].Value -notmatch '^([''"])(keyboard)?\1\s*(?:#.*)?$') {
            throw 'Private xemu config must leave controller ports unbound or bound only to its isolated keyboard.'
        }
    }
    $privatePrefix = [IO.Path]::GetFullPath($emulator).TrimEnd('\') + '\'
    foreach ($key in @('hdd_path', 'eeprom_path')) {
        $asset = [IO.Path]::GetFullPath((Get-XemuPath $configText $key))
        if (-not $asset.StartsWith($privatePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$key must point to private session assets under $emulator"
        }
        Assert-PlainPath $asset $false
    }
    $eepromSource = [IO.Path]::GetFullPath((Get-XemuPath $configText 'eeprom_path'))
    if (-not $PrepareOnly) {
        Assert-LoopbackPortFree $GdbPort
        Assert-LoopbackPortFree $QmpPort
    }
    $run = New-RunDirectory (Join-Path $SessionDirectory 'xemu_runs')
    $privateEeprom = Join-Path $run 'eeprom.bin'
    Copy-Item -LiteralPath $eepromSource -Destination $privateEeprom
    $config = Join-Path $run 'xemu.toml'
    $privateEepromLiteral = "'" + $privateEeprom + "'"
    if ($privateEeprom.Contains("'")) { throw 'The session path cannot contain an apostrophe for literal TOML paths.' }
    $configText = [regex]::Replace($configText, '(?m)^\s*eeprom_path\s*=.*$', [Text.RegularExpressions.MatchEvaluator]{ param($match) "eeprom_path = $privateEepromLiteral" })
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))
    $childArguments = @(
        '-config_path', $config, '-snapshot', '-net', 'none',
        '-gdb', "tcp:127.0.0.1:$GdbPort",
        '-qmp', "tcp:127.0.0.1:$QmpPort,server=on,wait=off",
        '-name', ('DAH2_CODEX_PRIVATE_' + (Split-Path $run -Leaf)), '-S'
    )
    $workingDirectory = $emulator
    $kind = 'xemu'
} else {
    foreach ($directory in @($ExtractionDirectory, $GameSavesDirectory, $GameFilesDirectory)) {
        Assert-PlainPath $directory $true
    }
    Assert-PlainPath $RecompExecutable $false
    Assert-PlainPath (Join-Path $GameSavesDirectory 'Cache') $true
    Assert-PlainPath (Join-Path $GameFilesDirectory 'default.xbe') $false
    Assert-PlainPath (Join-Path $ExtractionDirectory 'default.xbe') $false
    foreach ($name in @('blocks', 'movies', 'TDATA', 'UDATA')) {
        Assert-PlainPath (Join-Path $ExtractionDirectory $name) $true
    }
    $run = New-RunDirectory (Join-Path $SessionDirectory 'recomp_runs')
    $executable = Join-Path $run 'dah2_recomp.exe'
    Copy-Item -LiteralPath $RecompExecutable -Destination $executable
    if (Test-Path -LiteralPath $RecompMap -PathType Leaf) {
        Copy-Item -LiteralPath $RecompMap -Destination (Join-Path $run 'dah2_recomp.map')
    }
    # The runtime hardcodes this optical-root name; only bulk retail data is shared.
    $privateExtraction = Join-Path $run 'Destroy All Humans! 2 (USA, Europe) (En,Fr,De,Es,It).xiso'
    New-Item -ItemType Directory -Path $privateExtraction | Out-Null
    foreach ($name in @('blocks', 'movies')) {
        New-Item -ItemType Junction -Path (Join-Path $privateExtraction $name) -Target ([IO.Path]::GetFullPath((Join-Path $ExtractionDirectory $name))) | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $ExtractionDirectory 'default.xbe') -Destination (Join-Path $privateExtraction 'default.xbe')
    foreach ($name in @('TDATA', 'UDATA')) {
        Copy-PrivateTree (Join-Path $ExtractionDirectory $name) (Join-Path $privateExtraction $name)
    }
    Copy-PrivateTree $GameSavesDirectory (Join-Path $run 'game_saves')
    $privateGameFiles = Join-Path $run 'game_files'
    New-Item -ItemType Directory -Path $privateGameFiles | Out-Null
    Copy-Item -LiteralPath (Join-Path $GameFilesDirectory 'default.xbe') -Destination (Join-Path $privateGameFiles 'default.xbe')
    $childArguments = $RecompArguments
    $workingDirectory = $run
    $kind = 'recomp'
}

$manifestPath = Join-Path $run 'background.json'
$stdoutPath = Join-Path $run 'stdout.log'
$stderrPath = Join-Path $run 'stderr.log'
$launchRecordPath = Join-Path $run 'launch.json'
$rawArguments = (($childArguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' ')
$record = [ordered]@{
    schemaVersion = 1
    mode = $Mode
    preparedUtc = [DateTime]::UtcNow.ToString('o')
    sessionDirectory = $SessionDirectory
    runDirectory = $run
    executable = [IO.Path]::GetFullPath($executable)
    executableSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    workingDirectory = $workingDirectory
    arguments = $rawArguments
    launcher = $launcher
    backgroundManifestPath = $manifestPath
    stdoutPath = $stdoutPath
    stderrPath = $stderrPath
    launchRecordPath = $launchRecordPath
    launcherPid = $null
    childPid = $null
    desktop = $null
    status = 'prepared'
}
if ($kind -eq 'xemu') {
    $record.configPath = $config
    $record.eepromPath = $privateEeprom
    $record.qmpPort = $QmpPort
    $record.gdbPort = $GdbPort
    $record.initialGuestState = 'paused'
} else {
    $record.saveSource = [IO.Path]::GetFullPath($GameSavesDirectory)
    $record.extractionSource = [IO.Path]::GetFullPath($ExtractionDirectory)
    $record.xbeSha256 = (Get-FileHash -LiteralPath (Join-Path $privateGameFiles 'default.xbe') -Algorithm SHA256).Hash
    $record.sharedOpticalSubdirectories = @('blocks', 'movies')
}
Write-NewJson (Join-Path $run 'prepared.json') $record
if ($PrepareOnly) {
    $record | ConvertTo-Json -Depth 8
    return
}

# Only the desktop launcher is started from this process. It creates the actual
# game process with lpDesktop set before the child's first instruction executes.
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $launcher
$start.WorkingDirectory = $run
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
foreach ($argument in @('--exe', $executable, '--cwd', $workingDirectory,
    '--stdout', $stdoutPath, '--stderr', $stderrPath, '--manifest', $manifestPath, '--args', $rawArguments)) {
    $start.ArgumentList.Add($argument)
}
foreach ($key in $Environment.Keys) { $start.Environment[[string]$key] = [string]$Environment[$key] }
$launcherProcess = [Diagnostics.Process]::Start($start)
$record.launcherPid = $launcherProcess.Id
$record.status = 'launcher_started'
$deadline = [DateTime]::UtcNow.AddSeconds(10)
$observed = $null
while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $candidate = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            if ($candidate.status -in @('running', 'exited', 'launcher_error')) {
                $observed = $candidate
                break
            }
        } catch { } # The launcher rewrites its short status file in place.
    }
    if ($launcherProcess.HasExited) { break }
    Start-Sleep -Milliseconds 100
}
if ($observed) {
    $record.status = $observed.status
    if ($observed.PSObject.Properties['childPid']) { $record.childPid = $observed.childPid }
    if ($observed.PSObject.Properties['desktop']) { $record.desktop = $observed.desktop }
    if ($observed.PSObject.Properties['exitCode']) { $record.childExitCode = $observed.exitCode }
    if ($observed.PSObject.Properties['error']) { $record.launcherError = $observed.error }
} elseif ($launcherProcess.HasExited) {
    $record.status = 'launcher_exited_before_manifest'
    $record.launcherExitCode = $launcherProcess.ExitCode
} else {
    $record.status = 'manifest_pending'
}
Write-NewJson $launchRecordPath $record
$record | ConvertTo-Json -Depth 8
if ($record.status -in @('launcher_error', 'launcher_exited_before_manifest', 'manifest_pending')) {
    throw "Launch status is $($record.status); inspect $launchRecordPath and $manifestPath. No process has been terminated."
}
