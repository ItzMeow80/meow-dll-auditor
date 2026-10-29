# Changelog

All notable changes to the MEOW DLL Injection & Cheat Auditor.

## [8.1] - 2026-10-29

### Fixed
- ``[HIDDEN_MODULE]`` false positives on brand-new processes: a process younger than its ``LdrInitializeThunk`` has ntdll + exe mapped by the kernel but is not yet registered in PEB.Ldr or EnumProcessModulesEx, so the bootstrap itself was reported as "not in loader list" (reproduced deterministically: transient ``cmd.exe`` shells flagged ntdll twice each, 1484 KB + 4 KB exec regions). The deep scan now probes ``PEB_LDR_DATA.Initialized``, retries after 250 ms and defers hidden-module findings only while the loader is still mid-init. Detection in every stable process is unchanged.

### Added
- SS quiet list: ``hollow_detector.exe`` (operator's process-hollowing detector) never raises ``[HIGH]``

## [8.0] - 2026-10-28

### Added
- Live injector detection: system-wide handle-triad scan (PROCESS_CREATE_THREAD | VM_OPERATION | VM_WRITE), every candidate verified with DuplicateHandle + GetProcessId before reporting
- Integrity scan (L3): hidden DLLs, stomped modules, RunPE, IAT/ntdll hooks, shellcode threads
- Persistence audit (L4): registry autostart + IFEO hijack points
- System audit (L5): kernel drivers, BYOVD shortlist, boot config, Sysmon
- TXT + CSV reports, SHA256 export for VirusTotal, `-Watch` mode, interactive menu
- Whitelist entries for known-good natives (lz4-java temp natives, client odin natives, JNA, Bun, NGEN)
- Optional per-machine whitelist MEOW_whitelist.txt in the report folder (one -like pattern per line): silences operator-vouched files on this machine only, keyword hits are never silenced
- Built-in SS quiet list: unsigned x64dbg builds, CercaParole, MeowImportsChecker, SSTool and Shard never raise [HIGH] on any machine; real detections (autoclicker files, Praise.exe, keyword hits) keep reporting

### Fixed
- Extended-length paths (\\?\C:\...) no longer break path rules - a client's own native modules were reported [PATH+SIG] HIGH
- Manual-map false positives: raw SEC_IMAGE regions are compared against disk with a skip mask (image base, .reloc, fothk)
- WOW64 module enumeration: EnumProcessModulesEx(LIST_MODULES_ALL) instead of Process.Modules
- Full scan runs in about 30-45 seconds (parallel signature verification, memoized risk cache)

## [7.0] - 2026-10-25

### Added
- Initial public release: Level 1 DLL audit + Level 2 deep memory scan