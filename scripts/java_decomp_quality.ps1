param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$OutDir = $(Join-Path (Get-Location) ("docs/quality/java-decomp-" + (Get-Date -Format "yyyyMMdd-HHmmss"))),

    [int]$Rounds = 3,

    [string]$UnravelPath = $(Join-Path ((go env GOPATH).Trim()) "bin\unravel.exe"),

    [string]$CfrJar = "tools\cfr.jar",

    [string]$JdCliJar = "tools\jd-cli.jar"
)

$ErrorActionPreference = "Stop"

function Write-Log([string]$Message) {
    Write-Host $Message
}

function Invoke-CommandCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$WorkingDirectory = (Get-Location).Path
    )

    $prevErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $exitCode
            Output   = ($output | Out-String)
        }
    } finally {
        $ErrorActionPreference = $prevErrorActionPreference
    }
}

function Get-TreeFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    if (-not (Test-Path $Root)) {
        return [pscustomobject]@{
            Files      = 0
            Lines      = 0
            Fingerprint = ""
        }
    }

    $files = Get-ChildItem -Path $Root -Recurse -File | Sort-Object FullName
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $lineCount = 0
    $builder = New-Object System.Text.StringBuilder

    foreach ($file in $files) {
        $relative = Get-RelativePath -Root $Root -Path $file.FullName
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $fileHash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
        $null = $builder.AppendLine("$relative::$fileHash")

        if ($file.Extension -ieq ".java") {
            $content = [System.IO.File]::ReadAllText($file.FullName)
            $lineCount += ($content -split "`n").Count
        }
    }

    $fingerprintBytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $fingerprint = [System.BitConverter]::ToString($sha.ComputeHash($fingerprintBytes)).Replace("-", "").ToLowerInvariant()

    return [pscustomobject]@{
        Files       = $files.Count
        Lines       = $lineCount
        Fingerprint = $fingerprint
    }
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $pathFull = [System.IO.Path]::GetFullPath($Path)

    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathFull.Substring($rootFull.Length).Replace('\', '/')
    }

    return [System.IO.Path]::GetFileName($pathFull)
}

function Get-RelativeDiff {
    param(
        [Parameter(Mandatory = $true)] [string]$Left,
        [Parameter(Mandatory = $true)] [string]$Right
    )

    $leftFiles = Get-ChildItem -Path $Left -Recurse -File | ForEach-Object {
        [pscustomobject]@{
            Relative = Get-RelativePath -Root $Left -Path $_.FullName
            Hash = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash
        }
    }

    $rightFiles = Get-ChildItem -Path $Right -Recurse -File | ForEach-Object {
        [pscustomobject]@{
            Relative = Get-RelativePath -Root $Right -Path $_.FullName
            Hash = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash
        }
    }

    $leftMap = @{}
    foreach ($item in $leftFiles) {
        $leftMap[$item.Relative] = $item.Hash
    }

    $rightMap = @{}
    foreach ($item in $rightFiles) {
        $rightMap[$item.Relative] = $item.Hash
    }

    $onlyLeft = @()
    $onlyRight = @()
    $different = @()

    foreach ($rel in $leftMap.Keys) {
        if (-not $rightMap.ContainsKey($rel)) {
            $onlyLeft += $rel
            continue
        }
        if ($leftMap[$rel] -ne $rightMap[$rel]) {
            $different += $rel
        }
    }

    foreach ($rel in $rightMap.Keys) {
        if (-not $leftMap.ContainsKey($rel)) {
            $onlyRight += $rel
        }
    }

    [pscustomobject]@{
        OnlyLeft  = ($onlyLeft | Sort-Object)
        OnlyRight = ($onlyRight | Sort-Object)
        Different = ($different | Sort-Object)
    }
}

$InputPath = (Resolve-Path $InputPath).Path
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Log "Installing current workspace..."
$install = Invoke-CommandCapture -FilePath "go" -Arguments @("install", ".")
if ($install.ExitCode -ne 0) {
    throw "go install failed:`n$($install.Output)"
}

if (-not (Test-Path $UnravelPath)) {
    $UnravelPath = (Join-Path ((go env GOPATH).Trim()) "bin\unravel.exe")
}

if (-not (Test-Path $UnravelPath)) {
    throw "unravel binary not found at $UnravelPath"
}

$goVersion = (Invoke-CommandCapture -FilePath "go" -Arguments @("version")).Output.Trim()
$javaVersion = (cmd /c 'java -version 2>&1' | Out-String).Trim()

$runs = @()
for ($i = 1; $i -le $Rounds; $i++) {
    $runDir = Join-Path $OutDir ("unravel-run-$i")
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

    Write-Log "Running unravel pass $i/$Rounds..."
    $result = Invoke-CommandCapture -FilePath $UnravelPath -Arguments @("java", "decompile", "--no-ai", "--output", $runDir, $InputPath)
    if ($result.ExitCode -ne 0) {
        throw "unravel run $i failed:`n$($result.Output)"
    }

    $fingerprint = Get-TreeFingerprint -Root $runDir
    $runs += [pscustomobject]@{
        Run = $i
        Dir = $runDir
        Output = $result.Output
        JudgeSeen = ($result.Output -match 'Judge:\s*codex')
        Files = $fingerprint.Files
        Lines = $fingerprint.Lines
        Fingerprint = $fingerprint.Fingerprint
    }
}

$cfrDir = Join-Path $OutDir "cfr"
$jdDir = Join-Path $OutDir "jd-cli"
New-Item -ItemType Directory -Force -Path $cfrDir, $jdDir | Out-Null

$cfrStatus = "skipped"
if (Test-Path $CfrJar) {
    Write-Log "Running CFR..."
    $cfr = Invoke-CommandCapture -FilePath "java" -Arguments @("-jar", $CfrJar, "--silent", "true", "--outputdir", $cfrDir, $InputPath)
    if ($cfr.ExitCode -ne 0) {
        throw "CFR failed:`n$($cfr.Output)"
    }
    $cfrStatus = "ok"
}

$jdStatus = "skipped"
if (Test-Path $JdCliJar) {
    Write-Log "Running JD-CLI..."
    $jd = Invoke-CommandCapture -FilePath "java" -Arguments @("-jar", $JdCliJar, "--skipResources", "--outputDirStructured", $jdDir, $InputPath)
    if ($jd.ExitCode -ne 0) {
        throw "JD-CLI failed:`n$($jd.Output)"
    }
    $jdStatus = "ok"
}

$deterministic = $true
$baseline = $runs[0].Fingerprint
foreach ($run in $runs) {
    if ($run.Fingerprint -ne $baseline) {
        $deterministic = $false
    }
}

$cfrDiff = $null
if (Test-Path $cfrDir) {
    $cfrDiff = Get-RelativeDiff -Left $runs[0].Dir -Right $cfrDir
}

$jdDiff = $null
if (Test-Path $jdDir) {
    $jdDiff = Get-RelativeDiff -Left $runs[0].Dir -Right $jdDir
}

$reportPath = Join-Path $OutDir "quality-report.md"
$report = New-Object System.Text.StringBuilder

$null = $report.AppendLine("# Java Decompilation Quality Report")
$null = $report.AppendLine("")
$null = $report.AppendLine("- Input: $InputPath")
$null = $report.AppendLine("- Workspace install: go install .")
$null = $report.AppendLine("- Go: $goVersion")
$null = $report.AppendLine("- Java: $javaVersion")
$null = $report.AppendLine("- Rounds: $Rounds")
$null = $report.AppendLine("- Deterministic: $deterministic")
$null = $report.AppendLine("")
$null = $report.AppendLine("## Unravel Runs")
foreach ($run in $runs) {
    $null = $report.AppendLine("- Run $($run.Run): files=$($run.Files) lines=$($run.Lines) fingerprint=$($run.Fingerprint) judge=codex:$($run.JudgeSeen)")
}
$null = $report.AppendLine("")
$null = $report.AppendLine("## External Decompilers")
$null = $report.AppendLine("- CFR: $cfrStatus")
$null = $report.AppendLine("- JD-CLI: $jdStatus")
$null = $report.AppendLine("")

if ($cfrDiff) {
    $null = $report.AppendLine("### Unravel vs CFR")
    $null = $report.AppendLine("- Only in unravel: $($cfrDiff.OnlyLeft.Count)")
    $null = $report.AppendLine("- Only in CFR: $($cfrDiff.OnlyRight.Count)")
    $null = $report.AppendLine("- Different hashes: $($cfrDiff.Different.Count)")
    $null = $report.AppendLine("")
}

if ($jdDiff) {
    $null = $report.AppendLine("### Unravel vs JD-CLI")
    $null = $report.AppendLine("- Only in unravel: $($jdDiff.OnlyLeft.Count)")
    $null = $report.AppendLine("- Only in JD-CLI: $($jdDiff.OnlyRight.Count)")
    $null = $report.AppendLine("- Different hashes: $($jdDiff.Different.Count)")
    $null = $report.AppendLine("")
}

$null = $report.AppendLine("## Notes")
$null = $report.AppendLine("- Nested-class imports are normalized to source form (MethodHandles.Lookup).")
$null = $report.AppendLine("- The judge path auto-detects codex when present on PATH.")

[System.IO.File]::WriteAllText($reportPath, $report.ToString())
Write-Log "Wrote $reportPath"
Write-Host $report.ToString()
