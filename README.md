[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=22&pause=1200&color=00FFB3&center=true&vCenter=true&width=850&lines=MEOW+DLL+Injection+%26+Cheat+Auditor;%7C+Level1+-+DLL+Module+Audit%7C+Level2+-+Deep+Memory+Scan%7C+Manual-Map+%26+Shellcode+Hunt;%7C+Zero-Noise+Policy+%C2%B7+Windows+Forensics)](https://readme-typing-svg.demolab.com)

---

### `about`

```
$ ./meow-auditor --info
```

```
Tool      :  MEOW DLL Injection & Cheat Auditor
Version   :  7.0
Author    :  ItzMeow80
Target    :  Injected DLLs, manual-mapped cheats, hidden modules (any process)
Type      :  PowerShell forensic auditor - module audit + native memory scan
Vectors   :  Disk · Process · Memory
Severity  :  [ HIGH ]
```

---

## 📦 Contents

```
MEOW_DLL_Tool.ps1    single-file tool - no install, no external dependencies
                     Level 1  DLL module audit  (LoadLibrary injection)
                     Level 2  deep memory scan  (manual map / shellcode)
                     interactive menu, or -Auto CLI mode
```

## 🚀 Quick start

One command does everything — full audit of every process **plus** the deep memory scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\MEOW_DLL_Tool.ps1 -Auto -Deep
```

Run it from an **administrator** PowerShell, then read the verdict box at the bottom.
Reports (TXT + CSV) are written to `Desktop\MEOW_report`.

That's it — no menus, no options to pick. The tool scans, prints `[HIGH]` findings
with SHA256 hashes ready for VirusTotal, and saves the report.

## 🔎 Detection logic

**`[HIGH]` — investigate immediately**

```
KEYWORD       path/DLL contains cheat or injector words
              (injection, cheat, aimbot, bypass, manual-map, payload...)
              raised even when the file is signed

FILE_MISSING  the DLL no longer exists on disk (phantom module)

PATH+SIG      unsigned file outside every trusted folder

EXE           the process main executable itself fails the checks

MANUAL_MAP    PE 'MZ' header found inside private executable memory
              (the classic bypass: module injected without ever
              appearing in the module list - caught by Level 2)
```

**`[MEDIUM]` — review**

```
invalid signature inside a Microsoft / Program Files / app folder
user-mode debugger attached to the process
```

**Whitelist (never reported)**

```
NGEN native images      C:\Windows\assembly\NativeImages_v*
Windows Defender        C:\ProgramData\Microsoft\Windows Defender\
JNA                      %TEMP%\jna\jna*.dll
Bun addon runtime        %TEMP%\.bun-*
Minecraft natives        lwjgl / OpenAL / glfw / jinput under .minecraft
```

Valid Authenticode signature → trusted in any location.

## ⚠️ Known limitations

1. Administrator rights are required for full coverage — without them protected processes (lsass, csrss, services...) cannot be opened and are listed as "not accessible".

2. Level 2 only sees what is in memory **at scan time** — a manual-map module injected after the scan is invisible. Re-scan while the target is running.

3. `[MEDIUM]` is expected on unsigned vendor binaries (Electron apps, ffmpeg, Spotify Lite, node addons) — it is a review queue, not an alert.

4. No cloud reputation lookup: the report prints SHA256 hashes of every `[HIGH]` file so you can check them on VirusTotal manually.

5. Whitelist is path-based by design — a malicious file dropped inside an whitelisted path would be missed. Keep it minimal.

---

## 🛠️ Arsenal

[![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Windows Forensics](https://img.shields.io/badge/Windows_Forensics-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/windows/security/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![Minecraft](https://img.shields.io/badge/Minecraft-62B47A?style=for-the-badge&logo=minecraft&logoColor=white)](https://www.minecraft.net/)

---

**Made by MEOW** · `ItzMeow80` · v7.0 · Zero-noise policy: no `[HIGH]` without evidence
