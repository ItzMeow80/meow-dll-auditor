# Changelog

All notable changes to the MEOW DLL Injection & Cheat Auditor.

## [8.0] - 2026-10-28

### Added
- Live injector detection: system-wide handle-triad scan (PROCESS_CREATE_THREAD | VM_OPERATION | VM_WRITE), every candidate verified with DuplicateHandle + GetProcessId before reporting
- Integrity scan (L3): hidden DLLs, stomped modules, RunPE, IAT/ntdll hooks, shellcode threads
- Persistence audit (L4): registry autostart + IFEO hijack points
- System audit (L5): kernel drivers, BYOVD shortlist, boot config, Sysmon
- TXT + CSV reports, SHA256 export for VirusTotal, `-Watch` mode, interactive menu
- Whitelist entries for known-good natives (lz4-java temp natives, client odin natives, JNA, Bun, NGEN)
- Optional per-machine whitelist MEOW_whitelist.txt in the report folder (one -like pattern per line): silences operator-vouched files on this machine only, keyword hits are never silenced

### Fixed
- Extended-length paths (\\?\C:\...) no longer break path rules - a client's own native modules were reported [PATH+SIG] HIGH
- Manual-map false positives: raw SEC_IMAGE regions are compared against disk with a skip mask (image base, .reloc, fothk)
- WOW64 module enumeration: EnumProcessModulesEx(LIST_MODULES_ALL) instead of Process.Modules
- Full scan runs in about 30-45 seconds (parallel signature verification, memoized risk cache)

## [7.0] - 2026-10-25

### Added
- Initial public release: Level 1 DLL audit + Level 2 deep memory scan