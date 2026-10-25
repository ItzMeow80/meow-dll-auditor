<#
================================================================================
  MEOW  -  DLL Injection & Cheat Auditor
  Author: ItzMeow80
  Version 7.0
================================================================================

  WHAT IT DOES
  Inspects every running process and reports DLLs that may have been
  injected (LoadLibrary injection, manual mapping, shellcode).

  LEVEL 1 - DLL AUDIT
  Walks the module list of each process and classifies every file:
    [HIGH]   malicious - investigate immediately
               KEYWORD       path/DLL contains cheat or injector words
                             (e.g. ...\build\injection\...) even if signed
               FILE_MISSING  the DLL no longer exists on disk
               PATH+SIG      untrusted folder AND unsigned
               EXE           the process main executable is suspicious
    [MEDIUM] review - invalid signature inside a Microsoft/app folder,
             or the process has a debugger attached
    [OK]     signed and stored in a trusted folder

  Whitelist (known legitimate behaviour, never reported):
    - NGEN native images     C:\Windows\assembly\NativeImages_v*
    - Windows Defender       C:\ProgramData\Microsoft\Windows Defender\
    - JNA                    %TEMP%\jna\jna*.dll
    - Bun addon runtime      %TEMP%\.bun-*
    - Minecraft natives      lwjgl*, OpenAL*, glfw*, jinput* under .minecraft

  LEVEL 2 - DEEP MEMORY SCAN (catches bypassed cheats)
  Manually mapped cheats and shellcode never show up in the module list:
  they allocate memory by hand. This pass reads process memory directly and
  looks for:
    [HIGH]   PE 'MZ' header inside private executable memory -> hidden module
    [MEDIUM] process is being debugged
    INFO     executable and write+execute (WX) regions per process

  MENU
    1  Full scan           (every process)
    2  High-risk targets   (classic injection targets)
    3  Specific processes  (chosen by you)
    4  Combined            (high-risk + full)
    5  Deep memory scan    (high-risk targets)
    6  Deep scan           (specific processes)
    7  Save report
    0  Exit

  COMMAND LINE (administrator recommended)
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool.ps1"
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool.ps1" -Auto -Deep
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool.ps1" -Targets javaw -Auto -Deep

  PARAMETERS
    -Targets     process names (e.g. javaw,notepad)
    -Auto        no menu: run once and exit
    -Deep        with -Auto, also run the deep memory scan
    -OutputDir   report folder (default: Desktop\MEOW_report)
================================================================================
#>

param(
    [string[]]$Targets,
    [string]$OutputDir = "$env:USERPROFILE\Desktop\MEOW_report",
    [switch]$Auto,
    [switch]$Deep
)

$ErrorActionPreference = 'SilentlyContinue'
$ToolName    = 'MEOW DLL Injection & Cheat Auditor'
$ToolVersion = '7.0'
$ToolAuthor  = 'ItzMeow80'

# ---------------- Console: UTF-8 so the block banner renders correctly --------
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { [Console]::InputEncoding  = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8
try { chcp 65001 | Out-Null } catch { }

# ---------------- Colours (ANSI) ----------------
$esc = [char]27
$green  = "$esc[38;5;114m"; $red = "$esc[38;5;203m"; $yellow = "$esc[38;5;221m"
$purple = "$esc[38;5;141m"; $dim = "$esc[38;5;244m"; $cyan = "$esc[38;5;110m"
$reset  = "$esc[0m"

# ---------------- Native API (deep memory scan) ----------------
if (-not ('MeowAudit.Native' -as [type])) {
    Add-Type -Namespace MeowAudit -Name Native -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, int len);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
[DllImport("ntdll.dll")]
public static extern int NtQueryInformationProcess(IntPtr h, int cls, ref int info, int len, out int retLen);
public const int PROCESS_QUERY_INFORMATION = 0x0400;
public const int PROCESS_VM_READ           = 0x0010;
[StructLayout(LayoutKind.Sequential)]
public struct MBI {
    public IntPtr BaseAddress; public IntPtr AllocationBase;
    public uint AllocationProtect; public UIntPtr RegionSize;
    public uint State; public uint Protect; public uint Type;
}
"@
}

# ---------------- Trust rules ----------------
# System / vendor folders: an unsigned DLL here is only flagged as [MEDIUM]
$script:trustedRoots = @(
    "$env:SystemRoot\",
    "${env:ProgramFiles}\",
    "${env:ProgramFiles(x86)}\",
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\",
    "$env:ProgramData\Microsoft\Windows Defender\"
)

# Whole paths that are always benign (documented)
$script:whitelistPatterns = @(
    "$env:SystemRoot\assembly\NativeImages_v*",
    "$env:SystemRoot\Microsoft.NET\assembly\*",
    "$env:TEMP\jna\jna*.dll",
    "$env:TEMP\.bun-*"
)

# Known native library names accepted inside .minecraft
$script:MinecraftNatives = '^(lwjgl|OpenAL|jinput|glfw|jawt)'

# Cheat / injector keywords: [HIGH] even when signed
$script:KeywordHint = 'injection|inject|cheat|aimbot|triggerbot|wallhack|esp[-_.]|bypass|manual[-_]?map|payload|crack|hack'

# ---------------- High-risk target list ----------------
$script:HighRisk = @(
    # interpreters / scripting hosts
    'javaw', 'java', 'cmd', 'powershell', 'pwsh', 'powershell_ise',
    # LOLBins (commonly used for lateral injection)
    'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'regasm', 'regsvcs',
    'msbuild', 'installutil', 'msiexec', 'certutil', 'bitsadmin', 'cmstp',
    'control', 'dxdiag', 'eventvwr', 'mmc', 'msdt', 'presentationhost',
    'verifier', 'werfault', 'wmic',
    # editors / notes
    'notepad', 'notepad++', 'write',
    # browsers
    'chrome', 'msedge', 'firefox', 'brave', 'opera', 'opera_gx', 'vivaldi',
    # games and launchers
    'steam', 'steamwebhelper', 'epicgameslauncher', 'leagueclient', 'leagueclientux',
    'valorant', 'riotclientservices', 'cs2', 'csgo', 'fortnite', 'gta5', 'r5apex',
    # shell and everyday apps
    'explorer', 'taskmgr', 'taskhostw', 'searchindexer', 'sihost',
    'discord', 'slack', 'teams', 'telegram', 'spotify', 'obs64',
    '7zfm', 'winrar', 'winrar64'
)

# ---------------- State ----------------
$script:allRows  = New-Object System.Collections.Generic.List[object]
$script:findings = @{ HIGH  = [System.Collections.Generic.List[string]]::new()
                      MEDIUM= [System.Collections.Generic.List[string]]::new()
                      INFO  = [System.Collections.Generic.List[string]]::new() }
$script:denied   = New-Object System.Collections.Generic.List[string]
$script:runs     = @()
$script:sigCache = @{}

# ---------------- Core helpers ----------------
function Get-SigCached {
    param($path)
    if ($script:sigCache.ContainsKey($path)) { return $script:sigCache[$path] }
    $sig = Get-AuthenticodeSignature -FilePath $path
    $entry = [PSCustomObject]@{
        Status = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
        Signer = if ($sig -and $sig.SignerCertificate) {
                     $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*', '$1'
                 } else { '' }
    }
    $script:sigCache[$path] = $entry
    return $entry
}

function Get-FileSha256 {
    param($path)
    if (-not (Test-Path -LiteralPath $path)) { return 'file not found' }
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    catch { return 'hash failed' }
}

# Risk level of a file: 'HIGH' | 'MEDIUM' | ''
function Get-RiskLevel {
    param($path, $sigStatus, $procDir)

    # 1) keywords: always suspicious, even when signed
    $leaf = Split-Path $path -Leaf
    if ($path -match $script:KeywordHint -or $leaf -match $script:KeywordHint) { return 'HIGH' }

    # 2) file vanished from disk
    if (-not (Test-Path -LiteralPath $path)) { return 'HIGH' }

    # 3) documented whitelist
    foreach ($p in $script:whitelistPatterns) { if ($path -like $p) { return '' } }

    # 4) inside .minecraft: only known natives allowed, anything else is odd
    if ($path -like "*\.minecraft\*") {
        if ($leaf -match $script:MinecraftNatives) { return '' }
        return 'HIGH'
    }

    # 5) valid signature -> trusted anywhere
    if ($sigStatus -eq 'Valid') { return '' }

    # 6) unsigned but inside a Microsoft/app folder -> worth a review
    foreach ($root in $script:trustedRoots) { if ($path -like "$root*") { return 'MEDIUM' } }
    if ($procDir -and $path -like "$procDir*") { return 'MEDIUM' }

    # 7) unsigned and outside every trusted folder -> suspicious
    return 'HIGH'
}

# ---------------- LEVEL 1: DLL audit ----------------
function Invoke-ModuleAudit {
    param([string[]]$ProcessNames, [string]$Label = 'custom')
    $nProc = 0; $nMod = 0; $nHigh = 0
    $names = @($ProcessNames | Select-Object -Unique)
    $total = $names.Count; $idx = 0

    foreach ($name in $names) {
        $idx++
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }
        $nProc++
        $nameMod = 0; $nameHigh = 0

        foreach ($proc in $procs) {
            # --- check the main executable ---
            $procDir = $null; $procPath = $null
            try { $procPath = $proc.Path; if ($procPath) { $procDir = Split-Path $procPath -Parent } } catch { }
            if ($procPath) {
                $pSig = Get-SigCached -path $procPath
                if ((Get-RiskLevel -path $procPath -sigStatus $pSig.Status -procDir $procDir) -eq 'HIGH') {
                    $nameHigh++; $nHigh++
                    $script:findings.HIGH.Add("[EXE] $($proc.ProcessName) (PID $($proc.Id)) - suspicious main executable -> $procPath (signature: $($pSig.Status))")
                }
            }

            try { $modules = $proc.Modules }
            catch { $script:denied.Add("$($proc.ProcessName) (PID $($proc.Id))"); continue }

            $nMod += $modules.Count; $nameMod += $modules.Count
            $procHigh = 0

            foreach ($m in $modules) {
                $path = $m.FileName
                $sigInfo = Get-SigCached -path $path
                $level = Get-RiskLevel -path $path -sigStatus $sigInfo.Status -procDir $procDir

                $script:allRows.Add([PSCustomObject]@{
                    Process    = $proc.ProcessName; PID = $proc.Id
                    DLL        = $m.ModuleName; FullPath = $path
                    SizeKB     = [math]::Round($m.ModuleMemorySize / 1KB)
                    Company    = $m.FileVersionInfo.CompanyName
                    FileVersion= $m.FileVersionInfo.FileVersion
                    Signature  = $sigInfo.Status; Signer = $sigInfo.Signer
                    Level      = $level; Scope = $Label
                })

                if ($level -eq 'HIGH') {
                    $procHigh++; $nHigh++
                    $reason = if ($path -match $script:KeywordHint -or $m.ModuleName -match $script:KeywordHint) { 'KEYWORD' }
                              elseif (-not (Test-Path -LiteralPath $path)) { 'FILE_MISSING' }
                              else { 'PATH+SIG' }
                    $script:findings.HIGH.Add("[$reason] $($proc.ProcessName) (PID $($proc.Id)) - $($m.ModuleName) -> $path (signature: $($sigInfo.Status))")
                }
                elseif ($level -eq 'MEDIUM') {
                    $script:findings.MEDIUM.Add("$($proc.ProcessName) (PID $($proc.Id)) - $($m.ModuleName) -> $path (signature: $($sigInfo.Status))")
                }
            }

            $nameHigh += $procHigh
            if ($procHigh -gt 0) {
                Write-Host "$red    [!] $($proc.ProcessName) (PID $($proc.Id)): $procHigh suspicious DLL(s)$reset"
            }
        }

        # progress line - process name only, no flags
        $tag = if ($nameHigh -gt 0) { "$yellow  [$idx/$total] $($name.PadRight(22)) $nameMod DLL  -  $nameHigh flagged$reset" }
               else                 { "$dim   [$idx/$total] $($name.PadRight(22)) $nameMod DLL$reset" }
        Write-Host $tag
    }
    $procWord = if ($nProc -eq 1) { 'process' } else { 'processes' }
    if ($nProc -gt 0) { $script:runs += "DLL audit/$Label : $nProc $procWord, $nMod DLLs, $nHigh [HIGH]" }
    return "$nProc $procWord / $nMod DLLs / $nHigh [HIGH]"
}

# ---------------- LEVEL 2: deep memory scan ----------------
function Invoke-DeepScan {
    param([string[]]$ProcessNames, [string]$Label = 'deep')
    if (-not ('MeowAudit.Native' -as [type])) {
        Write-Host "$red  [!] Native API not loaded: deep scan unavailable$reset"
        return
    }

    $access = [MeowAudit.Native]::PROCESS_QUERY_INFORMATION -bor [MeowAudit.Native]::PROCESS_VM_READ
    $nProc = 0; $nHigh = 0
    $names = @($ProcessNames | Select-Object -Unique)
    $total = $names.Count; $idx = 0

    foreach ($name in $names) {
        $idx++
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }
        foreach ($proc in $procs) {
            $h = [MeowAudit.Native]::OpenProcess($access, $false, $proc.Id)
            if ($h -eq [IntPtr]::Zero) {
                $script:denied.Add("$($proc.ProcessName) (PID $($proc.Id)) [deep]")
                continue
            }
            $nProc++
            Write-Host "$dim  [deep $idx/$total] $($proc.ProcessName) (PID $($proc.Id))...$reset" -NoNewline

            $mzFound = 0; $execRegions = 0; $execKB = 0; $wxRegions = 0; $wxKB = 0
            $addr = [IntPtr]::Zero
            $mbi = New-Object MeowAudit.Native+MBI
            $len = [Runtime.InteropServices.Marshal]::SizeOf($mbi)

            while ($true) {
                $r = [MeowAudit.Native]::VirtualQueryEx($h, $addr, [ref]$mbi, $len)
                if ($r -eq 0) { break }

                $committed = ($mbi.State -eq 0x1000)
                $prot   = $mbi.Protect -band 0xFF
                $isExec = ($prot -eq 0x10) -or ($prot -eq 0x20) -or ($prot -eq 0x40) -or ($prot -eq 0x80)
                $isWX   = ($prot -eq 0x40) -or ($prot -eq 0x80)
                $unbacked = ($mbi.Type -eq 0x20000) -or ($mbi.Type -eq 0x40000)  # MEM_PRIVATE / MEM_MAPPED

                if ($committed -and $isExec -and $unbacked) {
                    $sizeKB = [math]::Round($mbi.RegionSize.ToUInt64() / 1KB)
                    $execRegions++; $execKB += $sizeKB
                    if ($isWX) { $wxRegions++; $wxKB += $sizeKB }

                    # 'MZ' = PE header: a hidden module inside private executable memory
                    $buf = New-Object byte[] 2
                    $read = 0
                    if ([MeowAudit.Native]::ReadProcessMemory($h, $mbi.BaseAddress, $buf, 2, [ref]$read)) {
                        if ($read -ge 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) {
                            $mzFound++; $nHigh++
                            $script:findings.HIGH.Add("[MANUAL_MAP] $($proc.ProcessName) (PID $($proc.Id)) - hidden module (PE header in private executable memory) @ $($mbi.BaseAddress), $sizeKB KB")
                        }
                    }
                }

                $size = $mbi.RegionSize.ToUInt64()
                $next = [IntPtr]::new([long]$mbi.BaseAddress + [long]$size)
                if ([long]$next -le [long]$addr) { break }
                $addr = $next
            }

            # debugger attached?
            $dbg = 0; $ret = 0
            if ([MeowAudit.Native]::NtQueryInformationProcess($h, 7, [ref]$dbg, 4, [ref]$ret) -eq 0) {
                if ($dbg -ne 0 -and $dbg -ne -1) {
                    $script:findings.MEDIUM.Add("[DEBUGGER] $($proc.ProcessName) (PID $($proc.Id)) - user-mode debugger attached")
                }
            }
            [MeowAudit.Native]::CloseHandle($h) | Out-Null

            $script:findings.INFO.Add("[MEMORY] $($proc.ProcessName) (PID $($proc.Id)) - exec: $execRegions regions/$execKB KB, WX: $wxRegions/$wxKB KB")

            if ($mzFound -gt 0) {
                Write-Host "$red  <- $mzFound hidden module(s) found!$reset"
            } else {
                $wxNote = if ($wxRegions -gt 0) { ", WX $wxRegions/$wxKB KB" } else { '' }
                Write-Host "$dim  exec $execRegions/$execKB KB$wxNote - no hidden module$reset"
            }
        }
    }
    $procWord = if ($nProc -eq 1) { 'process' } else { 'processes' }
    if ($nProc -gt 0) { $script:runs += "deep/$Label : $nProc $procWord, $nHigh [HIGH]" }
    return "$nProc $procWord / $nHigh [HIGH]"
}

# ---------------- Helpers ----------------
function Resolve-ProcessNames {
    param([string[]]$Names)
    $found = @(); $missing = @()
    # -File passes the whole list as a single string, so split on commas too
    foreach ($raw in $Names) {
        foreach ($n in ($raw -split ',')) {
            $clean = ($n.Trim() -replace '\.exe$', '')
            if (-not $clean) { continue }
            if (Get-Process -Name $clean -ErrorAction SilentlyContinue) { $found += $clean }
            else { $missing += $clean }
        }
    }
    $found = @($found | Select-Object -Unique)
    if ($missing.Count -gt 0) {
        Write-Host "$yellow  [!] Not running, skipped: $($missing -join ', ')$reset"
    }
    return $found
}

function Get-AllProcessNames {
    return Get-Process | Select-Object -ExpandProperty ProcessName -Unique | Sort-Object
}

# ---------------- Report ----------------
function New-Report {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $txt = "$OutputDir\report_$stamp.txt"
    $csv = "$OutputDir\report_$stamp.csv"
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $high = $script:findings.HIGH.Count
    $med  = $script:findings.MEDIUM.Count
    $procs = ($script:allRows | Select-Object PID -Unique).Count

    # SHA256 of suspicious files, for VirusTotal
    $hashLines = @()
    foreach ($line in $script:findings.HIGH) {
        if ($line -match '->\s+(\S+)') {
            $p = $Matches[1]
            $hashLines += "  $((Get-FileSha256 -path $p))  $p"
        }
    }

    $verdict = if ($high -gt 0) { "SUSPICIOUS: $high finding(s) to investigate" } else { "CLEAN: no [HIGH] findings" }

    @"
================================================================================
  $ToolName  v$ToolVersion
  Author: $ToolAuthor
================================================================================
  Date:         $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host:         $env:COMPUTERNAME ($env:USERNAME)
  Processes:    $procs analysed, $($script:denied.Count) not accessible
  DLLs:         $($script:allRows.Count)
  [HIGH]:       $high
  [MEDIUM]:     $med
  VERDICT:      $verdict
--------------------------------------------------------------------------------
  Scan passes run:
    $($script:runs -join "`n    ")
================================================================================

[HIGH] - investigate immediately
$(if ($high -gt 0) { $script:findings.HIGH -join "`n" } else { "(none)" })

SHA256 of suspicious files (paste into https://www.virustotal.com):
$(if ($hashLines.Count -gt 0) { $hashLines -join "`n" } else { "(none)" })

[MEDIUM] - review
$(if ($med -gt 0) { $script:findings.MEDIUM -join "`n" } else { "(none)" })

INFO - executable memory per process (exec = unbacked executable regions, WX = write+execute):
$(($script:findings.INFO | Select-Object -First 300) -join "`n")

Processes not accessible (administrator rights required):
$(if ($script:denied.Count -gt 0) { ($script:denied | Select-Object -Unique) -join "`n" } else { "(none)" })

Applied whitelist (these are NOT findings):
  - NGEN:      $env:SystemRoot\assembly\NativeImages_v*
  - Defender:  $env:ProgramData\Microsoft\Windows Defender\
  - JNA:       $env:TEMP\jna\jna*.dll
  - Bun:       $env:TEMP\.bun-*
  - Minecraft: lwjgl/OpenAL/glfw/jinput natives under .minecraft

Full DLL breakdown (CSV): $csv
"@ | Out-File $txt -Encoding UTF8

    $script:allRows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "$purple Report (TXT): $txt$reset"
    Write-Host "$purple Report (CSV): $csv$reset"
}

# ---------------- Box drawing helpers ----------------
$script:BoxInner = 66

function Write-BoxRule {
    Write-Host ("  +" + ("=" * $script:BoxInner) + "+") -ForegroundColor White
}

function Write-BoxTitle {
    param([string]$Text, [ConsoleColor]$Color = 'Magenta')
    $pad = [Math]::Max(1, $script:BoxInner - 1 - $Text.Length)
    Write-Host "  | " -NoNewline -ForegroundColor White
    Write-Host $Text -NoNewline -ForegroundColor $Color
    Write-Host (" " * $pad) -NoNewline
    Write-Host "|" -ForegroundColor White
}

function Write-BoxRow {
    param([string]$Label, [string]$Value, [ConsoleColor]$ValueColor = 'Gray')
    $lbl   = $Label.PadRight(30)
    $pad   = [Math]::Max(1, $script:BoxInner - 1 - ($lbl.Length + $Value.Length))
    Write-Host "  |  " -NoNewline -ForegroundColor White
    Write-Host $lbl -NoNewline -ForegroundColor Gray
    Write-Host $Value -NoNewline -ForegroundColor $ValueColor
    Write-Host (" " * $pad) -NoNewline
    Write-Host "|" -ForegroundColor White
}

function Show-Summary {
    $high = $script:findings.HIGH.Count
    $med  = $script:findings.MEDIUM.Count

    Write-Host ""
    Write-BoxRule
    Write-BoxTitle "S U M M A R Y   -   $ToolName  v$ToolVersion"
    Write-BoxRule
    if ($script:runs.Count -gt 0) {
        Write-BoxRow -Label "Scan passes run" -Value "$($script:runs.Count)" -ValueColor Cyan
    }
    Write-BoxRow -Label "DLLs analysed" -Value "$($script:allRows.Count)" -ValueColor White
    Write-BoxRow -Label "[HIGH]   investigate now" -Value "$high" -ValueColor $(if ($high -gt 0) { 'Red' } else { 'Green' })
    Write-BoxRow -Label "[MEDIUM] review" -Value "$med" -ValueColor $(if ($med -gt 0) { 'Yellow' } else { 'Green' })
    Write-BoxRow -Label "Processes not accessible" -Value "$($script:denied.Count)" -ValueColor DarkGray
    Write-BoxRule

    if ($script:runs.Count -gt 0) {
        foreach ($r in $script:runs) { Write-Host "    $r" -ForegroundColor DarkGray }
    }

    if ($high -gt 0) {
        Write-Host ""
        Write-Host "  [HIGH] $high finding(s) to investigate:" -ForegroundColor Red
        foreach ($l in $script:findings.HIGH) { Write-Host "    $l" -ForegroundColor Red }

        Write-Host ""
        Write-Host "  SHA256 of suspicious files (paste into https://www.virustotal.com):" -ForegroundColor DarkGray
        foreach ($l in $script:findings.HIGH) {
            if ($l -match '->\s+(\S+)') {
                $p = $Matches[1]
                $hash = Get-FileSha256 -path $p
                $short = if ($hash.Length -gt 32) { $hash.Substring(0, 32) + '...' } else { $hash }
                Write-Host "    $short  $((Split-Path $p -Leaf))" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host ""
        Write-Host "  No suspicious DLLs or hidden memory modules found." -ForegroundColor Green
    }

    if ($med -gt 0) {
        Write-Host ""
        Write-Host "  [MEDIUM] $med item(s) to review (invalid signature, debugger):" -ForegroundColor Yellow
        foreach ($l in $script:findings.MEDIUM) { Write-Host "    $l" -ForegroundColor DarkYellow }
    }

    Write-Host ""
    if ($high -gt 0) {
        Write-BoxRule
        Write-BoxTitle "VERDICT: SUSPICIOUS  -  $high finding(s) detected" -Color Red
        Write-BoxRule
    } else {
        Write-BoxRule
        Write-BoxTitle "VERDICT: CLEAN  -  no issues detected" -Color Green
        Write-BoxRule
    }
    Write-Host ""
}

function Show-Banner {
    Write-Host ""
    # Block-letter ASCII art: MEOW
    $art = @(
        '███╗   ███╗ ███████╗  ██████╗  ██╗    ██╗'
        '████╗ ████║ ██╔════╝ ██╔═══██╗ ██║    ██║'
        '██╔████╔██║ ██████╗   ██║   ██║ ██║ █╗ ██║'
        '██║╚██╔╝██║ ██╔══╝   ██║   ██║ ██║███╗██║'
        '██║ ╚═╝ ██║ ███████╗ ╚██████╔╝ ╚███╔███╔╝'
        '╚═╝     ╚═╝ ╚══════╝  ╚═════╝  ╚══╝╚══╝  '
    )
    foreach ($line in $art) { Write-Host "  $line" -ForegroundColor Magenta }

    # Cat + title box (padding computed at runtime: never misaligned)
    Write-Host ""
    $cat    = @('/\_/\', '( o.o )', '> ^ <')
    $row1   = "  $ToolName"
    $row2   = "  v$ToolVersion  -  Author: $ToolAuthor"
    $inner  = [Math]::Max($row1.Length, $row2.Length) + 1
    $rule   = "+" + ("=" * $inner) + "+"
    $pad1   = " " * ($inner - $row1.Length)
    $pad2   = " " * ($inner - $row2.Length)

    for ($i = 0; $i -lt 4; $i++) {
        $left = if ($i -lt 3) { $cat[$i].PadRight(10) } else { " " * 10 }
        if ($i -eq 0) {
            Write-Host "  $left  " -ForegroundColor Yellow -NoNewline
            Write-Host $rule -ForegroundColor White
        } elseif ($i -eq 1) {
            Write-Host "  $left  " -ForegroundColor Yellow -NoNewline
            Write-Host "|" -ForegroundColor White -NoNewline
            Write-Host $row1 -ForegroundColor White -NoNewline
            Write-Host $pad1 -NoNewline
            Write-Host "|" -ForegroundColor White
        } elseif ($i -eq 2) {
            Write-Host "  $left  " -ForegroundColor Yellow -NoNewline
            Write-Host "|" -ForegroundColor White -NoNewline
            Write-Host ("  v$ToolVersion") -ForegroundColor Cyan -NoNewline
            Write-Host "  -  Author: " -NoNewline -ForegroundColor White
            Write-Host $ToolAuthor -ForegroundColor Magenta -NoNewline
            Write-Host $pad2 -NoNewline
            Write-Host "|" -ForegroundColor White
        } else {
            Write-Host (" " * 14) -NoNewline
            Write-Host $rule -ForegroundColor White
        }
    }
    Write-Host ""

    Write-Host "    Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Host: $env:COMPUTERNAME - User: $env:USERNAME" -ForegroundColor DarkGray
    Write-Host "    Reports: $OutputDir" -ForegroundColor DarkGray

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "    WARNING: not running as administrator." -ForegroundColor Yellow
        Write-Host "    Some protected system processes cannot be analysed." -ForegroundColor Yellow
    }
    Write-Host ""
}

function Show-Menu {
    Write-Host "  ${cyan}[1]$reset Full scan           - every process (main EXE + DLLs)"
    Write-Host "  ${cyan}[2]$reset High-risk targets   - classic injection targets"
    Write-Host "  ${cyan}[3]$reset Specific processes  - chosen by you (e.g. javaw,notepad)"
    Write-Host "  ${cyan}[4]$reset Combined            - high-risk + full scan"
    Write-Host "  ${cyan}[5]$reset ${yellow}Deep memory scan$reset     - hunt hidden modules (manual map)"
    Write-Host "  ${cyan}[6]$reset Deep scan on chosen  - same, on processes you select"
    Write-Host "  ${cyan}[7]$reset Save report          - write TXT + CSV"
    Write-Host "  ${cyan}[0]$reset Exit"
    Write-Host ""
}

# ---------------- Automatic mode (no menu) ----------------
if ($Auto) {
    Show-Banner
    if ($Targets) {
        $list = Resolve-ProcessNames -Names $Targets
        if ($list.Count -gt 0) {
            Write-Host "$cyan  DLL audit: $(Invoke-ModuleAudit -ProcessNames $list -Label 'auto')$reset"
            if ($Deep) { Write-Host "$cyan  Deep scan: $(Invoke-DeepScan -ProcessNames $list -Label 'auto')$reset" }
        } else {
            Write-Host "$yellow  None of the requested processes are running.$reset"
        }
    } else {
        $all = Get-AllProcessNames
        Write-Host "$cyan  DLL audit: $(Invoke-ModuleAudit -ProcessNames (@($script:HighRisk) + @($all)) -Label 'auto')$reset"
        if ($Deep) {
            Write-Host "$cyan  Deep scan: $(Invoke-DeepScan -ProcessNames (@($script:HighRisk) + @($all)) -Label 'auto')$reset"
        }
    }
    Show-Summary
    New-Report
    return
}

# ---------------- Interactive mode ----------------
Show-Banner
$exit = $false
while (-not $exit) {
    Show-Menu
    $choice = Read-Host "  Select an option"

    switch ($choice) {
        '1' {
            Write-Host "$purple`n  >>> Full scan in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-ModuleAudit -ProcessNames (Get-AllProcessNames) -Label 'full')$reset"
            Show-Summary
        }
        '2' {
            Write-Host "$purple`n  >>> High-risk scan in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-ModuleAudit -ProcessNames $script:HighRisk -Label 'high-risk')$reset"
            Show-Summary
        }
        '3' {
            $in = Read-Host "  Comma-separated process names (e.g. javaw,notepad,cmd)"
            if ($in) {
                $list = Resolve-ProcessNames -Names ($in -split ',')
                if ($list.Count -gt 0) {
                    Write-Host "$cyan  Result: $(Invoke-ModuleAudit -ProcessNames $list -Label 'custom')$reset"
                    Show-Summary
                } else {
                    Write-Host "$yellow  None of the requested processes are running - nothing to analyse.$reset"
                }
            }
        }
        '4' {
            Write-Host "$purple`n  >>> Combined scan in progress (may take a few minutes)...$reset"
            $all = Get-AllProcessNames
            Write-Host "$cyan  Result: $(Invoke-ModuleAudit -ProcessNames (@($script:HighRisk) + @($all)) -Label 'combined')$reset"
            Show-Summary
        }
        '5' {
            Write-Host "$purple`n  >>> Deep memory scan in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-DeepScan -ProcessNames $script:HighRisk -Label 'high-risk')$reset"
            Show-Summary
        }
        '6' {
            $in = Read-Host "  Processes for the deep scan (e.g. javaw,Discord)"
            if ($in) {
                $list = Resolve-ProcessNames -Names ($in -split ',')
                if ($list.Count -gt 0) {
                    Write-Host "$cyan  Result: $(Invoke-DeepScan -ProcessNames $list -Label 'deep-custom')$reset"
                    Show-Summary
                } else {
                    Write-Host "$yellow  None of the requested processes are running.$reset"
                }
            }
        }
        '7' { Show-Summary; New-Report }
        '0' { $exit = $true }
        default { Write-Host "$yellow  Invalid option: choose a number from 0 to 7.$reset" }
    }
    if (-not $exit) { Write-Host "" }
}

if ($script:allRows.Count -gt 0 -or $script:findings.HIGH.Count -gt 0) {
    Write-Host "$dim  Saving report...$reset"
    New-Report
}
Write-Host ""
Write-Host "$purple  Audit complete. Meow!$reset"
Write-Host "$dim  $ToolName v$ToolVersion - $ToolAuthor$reset"
Write-Host ""
