# Changelog

All notable changes to the MEOW DLL Injection & Cheat Auditor.

## [8.3] - 2026-10-30

### Changed
- Report noise cut (presentation only - CSV keeps the full per-process data, no detection rule changed):
- Loaded-module MEDIUM findings are now **one line per file** instead of one per process: the same DLL loaded in N processes prints once with ``(N procs)`` (was: e.g. 6 identical ``ffmpeg.dll`` lines for 6 Lunar Client instances).
- ``[MEMORY]`` INFO lines are listed only when the process carries actual signal (write+execute regions, orphan MEM_IMAGE, hidden module or mid-init loader). The clean majority (``WX: 0/0``) is replaced by one summary line: ``N processes deep-scanned, M listed, K clean omitted`` (was one flat line per process - 178 lines in a typical run).
- The "Processes not accessible" list no longer lists a process twice (level-1 entry + deep ``[deep]`` entry for the same PID).
- HIGH findings are untouched: still one line per process, all keyword/hash/whitelist rules unchanged.
## [8.2] - 2026-10-30

### Added
- Hash whitelist (content-addressed): the operator toolset is silenced by SHA256 only - mc-ss-tool.exe, CMake's CompilerIdCXX.exe, MeowClientFucker.exe, MeowDoomsdayFucker.exe and both SS-Shellcode-Scanner.exe copies no longer raise ``[PATH+SIG]``. Only those exact bytes are silenced anywhere: a different file with the same name still reports, and keyword matches are checked first so hashes can never hide a keyword hit.
- ``MEOW_whitelist.txt`` now accepts ``sha256:<64 hex>`` lines alongside ``-like`` path patterns, for vouching one file per machine without re-releasing the tool.
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