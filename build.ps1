<#
.SYNOPSIS
    Builds webdav-server and puts the finished programs in public\.

.DESCRIPTION
    Runs the tests, then publishes three single files, each running on the .NET 10 runtime installed on the computer
    (https://dotnet.microsoft.com/download/dotnet/10.0):

        webdav-server-linux-x64-needs-dotnet          the server, for x64 Linux (ASP.NET Core Runtime)
        webdav-server-win-x64-needs-dotnet.exe        the server, for x64 Windows (ASP.NET Core Runtime)
        webdav-server-admin-win-x64-needs-dotnet.exe  the admin window, for x64 PCs (Desktop Runtime)

    public\ is emptied and gets the new files, with VERSION and SHA256SUMS, all directly inside it. The version is read
    from VERSION; -Bump or -Version builds a new one, and VERSION is changed once the build succeeds.

.PARAMETER Bump
    Raises the version before building: major (2.0.0.0), minor (1.1.0.0), patch (1.0.1.0) or revision (1.0.0.1).

.PARAMETER Version
    Sets the version before building, as major.minor.patch.revision.

.PARAMETER SkipTests
    Builds without running the tests first.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Bump revision
#>
[CmdletBinding()]
param(
    [ValidateSet('major', 'minor', 'patch', 'revision')] [string] $Bump,
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')] [string] $Version,
    [switch] $SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$versionFile = Join-Path $root 'VERSION'
$public = Join-Path $root 'public'
# dotnet publishes outside the repository first, so that public\ only changes once the build has worked.
$out = Join-Path ([IO.Path]::GetTempPath()) 'webdav-server-publish'

function Step([string] $text) { Write-Host "`n== $text" -ForegroundColor Cyan }

function Invoke-Dotnet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($args -join ' ') failed (exit code $LASTEXITCODE)." }
}

# .NET 10 SDK
$sdks = @(& dotnet --list-sdks 2>$null)
if (-not ($sdks | Where-Object { $_ -match '^10\.' })) {
    throw 'The .NET 10 SDK is needed to build: https://dotnet.microsoft.com/download/dotnet/10.0'
}

# The version: VERSION, changed first by -Version or -Bump.
$current = (Get-Content $versionFile -Raw).Trim()
if ($current -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { throw "VERSION holds '$current', not major.minor.patch.revision." }
$major, $minor, $patch, $revision = [int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4]
$next = $current
if ($Version) { $next = $Version }
elseif ($Bump -eq 'major') { $next = "$($major + 1).0.0.0" }
elseif ($Bump -eq 'minor') { $next = "$major.$($minor + 1).0.0" }
elseif ($Bump -eq 'patch') { $next = "$major.$minor.$($patch + 1).0" }
elseif ($Bump -eq 'revision') { $next = "$major.$minor.$patch.$($revision + 1)" }
if ($next -ne $current) { Write-Host "Version $current -> $next (VERSION is changed once the build succeeds)" }
Write-Host "Building webdav-server $next"

if (-not $SkipTests) {
    Step 'Tests'
    Invoke-Dotnet test --project (Join-Path $root 'tests\WebDavServer.Tests\WebDavServer.Tests.csproj') --nologo
}

$builds = @(
    @{ Project = 'src\WebDavServer\WebDavServer.csproj'; Runtime = 'linux-x64'; From = 'webdav-server'; To = 'webdav-server-linux-x64-needs-dotnet' },
    @{ Project = 'src\WebDavServer\WebDavServer.csproj'; Runtime = 'win-x64'; From = 'webdav-server.exe'; To = 'webdav-server-win-x64-needs-dotnet.exe' },
    @{ Project = 'src\WebDavServer.Admin\WebDavServer.Admin.csproj'; Runtime = 'win-x64'; From = 'webdav-server-admin.exe'; To = 'webdav-server-admin-win-x64-needs-dotnet.exe' }
)
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
foreach ($build in $builds) {
    Step $build.To
    Invoke-Dotnet publish (Join-Path $root $build.Project) -c Release -r $build.Runtime "-p:Version=$next" -o (Join-Path $out $build.To) --nologo
}

# public\ holds only the latest build. A program in it that is running can't be replaced: that is checked first, so
# that public\ isn't left half emptied.
Step 'public\'
if (Test-Path $public) {
    foreach ($file in Get-ChildItem $public -File -Force) {
        try { [IO.File]::Open($file.FullName, 'Open', 'ReadWrite', 'None').Dispose() }
        catch { throw "$($file.Name) is in use, probably running: close it and build again." }
    }
    Get-ChildItem $public -Force | Remove-Item -Recurse -Force
}
else { New-Item -ItemType Directory $public | Out-Null }

$sums = foreach ($build in $builds) {
    $file = Join-Path $public $build.To
    Copy-Item (Join-Path (Join-Path $out $build.To) $build.From) $file
    '{0}  {1:N1} MB' -f $build.To, ((Get-Item $file).Length / 1MB) | Write-Host
    "$((Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant())  $($build.To)"
}
[IO.File]::WriteAllText((Join-Path $public 'VERSION'), "$next`n")
[IO.File]::WriteAllText((Join-Path $public 'SHA256SUMS'), (($sums -join "`n") + "`n"))
Remove-Item $out -Recurse -Force
if ($next -ne $current) { [IO.File]::WriteAllText($versionFile, "$next`n") }

Write-Host "`nwebdav-server $next is in $public" -ForegroundColor Green
