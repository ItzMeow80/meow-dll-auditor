<#
================================================================================
  MEOW  -  DLL Injection & Cheat Auditor
  Author: ItzMeow80
  Version 8.2
================================================================================

  WHAT IT DOES
  Inspects running process memory and reports injected DLLs, hidden
  (manual-mapped / reflective) modules, memory patching and persistence.

  LEVEL 1 - DLL AUDIT
  Walks the module list of each process and classifies every file:
    [HIGH]   malicious - investigate immediately
               KEYWORD       path/DLL contains cheat or injector words
               FILE_MISSING  the DLL no longer exists on disk
               PATH+SIG      untrusted folder AND unsigned
               EXE           the process main executable is suspicious
    [MEDIUM] review - invalid signature inside a Microsoft/app folder
    [OK]     signed and stored in a trusted folder
  Module lists come from EnumProcessModulesEx(LIST_MODULES_ALL) - the only
  reliable source for WOW64 targets (.NET Process.Modules misses the whole
  32-bit set there and used to flood the report with false positives).

  LEVEL 2 - DEEP MEMORY SCAN
  One C# walk over every committed region. A hidden module is only reported
  when a FULL PE header validates at the allocation base (kills JIT false
  positives) and it is not a known module (manual map / reflective load /
  section-object mapping). Then a system-wide handle triad scan reports the
  live injector itself:
    INJECTOR    a process holds PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE
                on another process (the CreateRemoteThread/WriteProcessMemory
                triad). Every candidate handle is verified with
                DuplicateHandle+GetProcessId before reporting.

  LEVEL 3 - INTEGRITY SCAN
    HIDDEN_DLL   module visible in one enumeration view but not the other
    STOMPED      module memory bytes differ from the file on disk
    RUNPE        main image in memory differs from the EXE on disk (hollowing)
    IAT_HOOK     import slot points outside every known module
    NTDLL_HOOK   ntdll .text in memory differs from the on-disk copy
    THREAD_EXEC  thread start address inside unbacked memory (shellcode)
    DEBUG_PORT   process is being debugged (classic pre-injection step)

  LEVEL 4 - PERSISTENCE
  Registry autostart + hijack points (AppInit, AppCertDlls, IFEO, Winlogon,
  COM overrides, LSP, service DLLs, Office add-ins, WMI subscriptions...).

  LEVEL 5 - SYSTEM
  Loaded kernel drivers (signature + BYOVD shortlist), boot config
  (testsigning / integrity checks), Secure Boot, Sysmon telemetry.

  SIGNATURES
  Authenticode status via parallel WinVerifyTrust (8 threads). Windows system
  DLLs that carry their signature in a catalog file (no embedded blob) are
  resolved through the catalog APIs, same result as Get-AuthenticodeSignature
  but ~40x faster.

  MENU
    1  Full scan           (every process - level 1)
    2  High-risk targets   (classic injection targets)
    3  Specific processes  (chosen by you)
    4  Combined            (high-risk + full)
    5  Deep memory scan    (level 2, high-risk targets)
    6  Deep scan on chosen (level 2, your processes)
    7  Integrity scan      (level 3, every process)
    8  Persistence audit   (level 4)
    9  System audit        (level 5)
    F  FULL PASS           (levels 1-5, the -FullScan engine)
    0  Exit

  COMMAND LINE (administrator recommended)
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool_v8.ps1" -FullScan
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool_v8.ps1" -Auto -Deep
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool_v8.ps1" -Targets javaw -Auto -Deep
    powershell -ExecutionPolicy Bypass -File ".\MEOW_DLL_Tool_v8.ps1" -FullScan -Watch 30

  PARAMETERS
    -Targets      process names (e.g. javaw,notepad)
    -Auto         no menu: run once and exit
    -Deep         with -Auto, also run the deep memory scan + integrity scan
    -FullScan     run EVERYTHING (levels 1-5); implies -Auto
    -Watch N      after the scan, re-run deep+integrity every N seconds
    -SkipPersist  with -FullScan, skip level 4 (persistence)
    -SkipSystem   with -FullScan, skip level 5 (drivers/boot/Sysmon)
    -OutputDir    report folder (default: Desktop\MEOW_report)
================================================================================
#>

param(
    [string[]]$Targets,
    [string]$OutputDir = "$env:USERPROFILE\Desktop\MEOW_report",
    [switch]$Auto,
    [switch]$Deep,
    [switch]$FullScan,
    [int]$Watch = 0,
    [switch]$SkipPersist,
    [switch]$SkipSystem
)

$ErrorActionPreference = 'SilentlyContinue'
$ToolName    = 'MEOW DLL Injection & Cheat Auditor'
$ToolVersion = '8.2'
$ToolAuthor  = 'ItzMeow80'
if ($FullScan) { $Auto = $true }

# ---------------- Console: UTF-8 so console codes render correctly -----------
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { [Console]::InputEncoding  = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8
try { chcp 65001 | Out-Null } catch { }

# ---------------- Colours (ANSI) ----------------
$esc = [char]27
$green  = "$esc[38;5;114m"; $red = "$esc[38;5;203m"; $yellow = "$esc[38;5;221m"
$purple = "$esc[38;5;141m"; $dim = "$esc[38;5;244m"; $cyan = "$esc[38;5;110m"
$reset  = "$esc[0m"

# ---------------- Native API -------------------------------------------------
if (-not ('MeowAudit.Native' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace MeowAudit {
public static class Native {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(int access, bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, int len);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll")]
    public static extern bool IsWow64Process(IntPtr h, out bool wow64);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr info, int len, out int retLen);
    // EntryPoint is mandatory here: without it P/Invoke resolves the METHOD
    // name "NtQueryInformationProcessInt", which ntdll does not export, and
    // the integrity pass died with EntryPointNotFoundException on first call.
    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    public static extern int NtQueryInformationProcessInt(IntPtr h, int cls, ref int info, int len, out int retLen);
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, out int retLen);
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int retLen);
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_READ           = 0x0010;
    public const int THREAD_QUERY_INFORMATION  = 0x0040;
    public const int LIST_MODULES_ALL          = 3;
    public const int LIST_MODULES_32BIT        = 1;
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase;
        public uint AllocationProtect; public UIntPtr RegionSize;
        public uint State; public uint Protect; public uint Type;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MODINFO { public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }

    // Read bytes out of a remote process. Returns null on failure.
    public static byte[] ReadMem(IntPtr h, long addr, int size) {
        byte[] buf = new byte[size]; int read;
        if (ReadProcessMemory(h, (IntPtr)addr, buf, size, out read) && read > 0) {
            if (read < size) { Array.Resize(ref buf, read); }
            return buf;
        }
        return null;
    }

    // ---- module enumeration via psapi -------------------------------------
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] lphModule, int cb, out int lpcbNeeded, int dwFilterFlag);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern int GetModuleFileNameExW(IntPtr h, IntPtr hModule, StringBuilder filename, int nSize);
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool GetModuleInformation(IntPtr h, IntPtr hModule, out MODINFO mi, int cb);

    // Full module list as "base|size|name|path" entries.
    // EnumProcessModulesEx(LIST_MODULES_ALL) is the only reliable source for
    // WOW64 targets: .NET's Process.Modules sees just the 64-bit subset there
    // (7 of 177 modules measured), which produced hundreds of false
    // HIDDEN_MODULE / IAT_HOOK findings in v8.0-pre.
    public static string[] EnumModulesEx(IntPtr h, int filter) {
        System.Collections.Generic.List<string> outp = new System.Collections.Generic.List<string>();
        try {
            int need = 0;
            IntPtr[] buf = new IntPtr[512];
            if (!EnumProcessModulesEx(h, buf, buf.Length * IntPtr.Size, out need, filter)) return outp.ToArray();
            if (need / IntPtr.Size > buf.Length) {
                buf = new IntPtr[need / IntPtr.Size];
                if (!EnumProcessModulesEx(h, buf, buf.Length * IntPtr.Size, out need, filter)) return outp.ToArray();
            }
            int count = Math.Min(buf.Length, need / IntPtr.Size);
            for (int i = 0; i < count; i++) {
                MODINFO mi;
                if (!GetModuleInformation(h, buf[i], out mi, Marshal.SizeOf(typeof(MODINFO)))) continue;
                StringBuilder sb = new StringBuilder(1024);
                GetModuleFileNameExW(h, buf[i], sb, sb.Capacity);
                string p = sb.ToString();
                string n = p;
                int li = p.LastIndexOf('\\');
                if (li >= 0 && li + 1 < p.Length) n = p.Substring(li + 1);
                outp.Add(mi.lpBaseOfDll.ToInt64() + "|" + (int)mi.SizeOfImage + "|" + n + "|" + p);
            }
        } catch { }
        return outp.ToArray();
    }

    // ---- PEB loader list walk (second opinion vs the API) -----------------
    // Returns "base|size|fullName" strings. Malware that hooks module
    // enumeration cannot hide entries here without patching the loader
    // structures themselves.
    public static string[] WalkPebLoaderList(IntPtr h, bool wow64) {
        try {
            if (wow64) return WalkPeb32(h);
            // x64: PROCESS_BASIC_INFORMATION is exactly 0x30 bytes on x64 and
            // NtQueryInformationProcess(ProcessBasicInformation) returns
            // STATUS_INFO_LENGTH_MISMATCH for larger buffers here (measured);
            // the PEB pointer lives at offset 8.
            IntPtr tmp = Marshal.AllocHGlobal(0x30);
            try {
                int ret;
                byte[] z = new byte[0x30];
                Marshal.Copy(z, 0, tmp, 0x30);
                if (NtQueryInformationProcess(h, 0, tmp, 0x30, out ret) != 0) return new string[0];
                long peb = Marshal.ReadInt64(tmp, 8);
                if (peb < 0x10000) return new string[0];
                return Walk64(h, peb);
            } finally { Marshal.FreeHGlobal(tmp); }
        } catch { return new string[0]; }
    }

    static string[] Walk64(IntPtr h, long peb) {
        // PEB.Ldr @ +0x18, PEB_LDR_DATA.InLoadOrderModuleList @ +0x10
        byte[] b = ReadMem(h, peb + 0x18, 8);
        if (b == null) return new string[0];
        long ldr = BitConverter.ToInt64(b, 0);
        if (ldr < 0x10000) return new string[0];
        b = ReadMem(h, ldr + 0x10, 8);
        if (b == null) return new string[0];
        long headAddr = ldr + 0x10;
        long cur = BitConverter.ToInt64(b, 0);
        System.Collections.Generic.List<string> outp = new System.Collections.Generic.List<string>();
        for (int i = 0; i < 1024 && cur >= 0x10000; i++) {
            byte[] ent = ReadMem(h, cur, 0x58);
            if (ent == null || ent.Length < 0x50) break;
            long flink  = BitConverter.ToInt64(ent, 0);
            long dllBase = BitConverter.ToInt64(ent, 0x30);   // DllBase
            int  size    = BitConverter.ToInt32(ent, 0x40);   // SizeOfImage
            short uLen   = BitConverter.ToInt16(ent, 0x48);   // FullDllName.Length
            long uBuf    = BitConverter.ToInt64(ent, 0x50);   // FullDllName.Buffer
            string name = "";
            if (uLen > 0 && uLen < 1024 && uBuf != 0) {
                byte[] nb = ReadMem(h, uBuf, uLen);
                if (nb != null) name = Encoding.Unicode.GetString(nb);
            }
            if (dllBase >= 0x10000) outp.Add(dllBase + "|" + size + "|" + name);
            if (flink == 0 || flink == headAddr) break;
            cur = flink;
        }
        return outp.ToArray();
    }

    // v8.1: loader-init race probe. A process younger than its
    // LdrInitializeThunk has ntdll + exe mapped by the kernel but NOT yet
    // registered in PEB.Ldr or EnumProcessModulesEx - RegionScan then
    // reports the bootstrap as "not in loader list" (measured: a cmd.exe
    // caught within its first milliseconds flagged ntdll twice, 1484 KB +
    // 4 KB exec regions). Callers use this to defer hidden-module findings
    // while the loader is still initializing.
    //   1 = loader initialized (module lists can be trusted)
    //   0 = loader mid-init (PEB.Ldr absent or Initialized == 0)
    //  -1 = could not determine (callers treat as 1: keep detecting)
    public static int GetLdrInitialized(IntPtr h, bool wow64) {
        try {
            if (!wow64) {
                IntPtr tmp = Marshal.AllocHGlobal(0x30);
                try {
                    int ret;
                    byte[] z = new byte[0x30];
                    Marshal.Copy(z, 0, tmp, 0x30);
                    if (NtQueryInformationProcess(h, 0, tmp, 0x30, out ret) != 0) return -1;
                    long peb = Marshal.ReadInt64(tmp, 8);
                    if (peb < 0x10000) return -1;
                    byte[] b = ReadMem(h, peb + 0x18, 8);          // PEB.Ldr
                    if (b == null || b.Length < 8) return -1;
                    long ldr = BitConverter.ToInt64(b, 0);
                    if (ldr < 0x10000) return 0;                    // not built yet
                    byte[] c = ReadMem(h, ldr + 4, 1);             // PEB_LDR_DATA.Initialized
                    if (c == null || c.Length < 1) return 0;
                    return (c[0] != 0) ? 1 : 0;
                } finally { Marshal.FreeHGlobal(tmp); }
            } else {
                // WOW64: 32-bit PEB via ProcessWow64Information (class 26);
                // PEB_LDR_DATA32.Initialized sits at the same +4 offset.
                IntPtr tmp = Marshal.AllocHGlobal(8);
                try {
                    int ret;
                    byte[] z = new byte[8];
                    Marshal.Copy(z, 0, tmp, 8);
                    if (NtQueryInformationProcess(h, 26, tmp, 8, out ret) != 0) return -1;
                    long peb32 = Marshal.ReadInt64(tmp, 0);
                    if (peb32 < 0x10000) return -1;
                    byte[] b = ReadMem(h, peb32 + 0x0C, 4);        // PEB32.Ldr
                    if (b == null || b.Length < 4) return -1;
                    long ldr = BitConverter.ToUInt32(b, 0);
                    if (ldr < 0x10000) return 0;
                    byte[] c = ReadMem(h, ldr + 4, 1);             // Initialized
                    if (c == null || c.Length < 1) return 0;
                    return (c[0] != 0) ? 1 : 0;
                } finally { Marshal.FreeHGlobal(tmp); }
            }
        } catch { return -1; }
    }

    static string[] WalkPeb32(IntPtr h) {
        // WOW64: ProcessWow64Information (class 26) returns the 32-bit PEB.
        // All structures below use 4-byte pointers:
        //   PEB32.Ldr @ +0x0C, PEB_LDR_DATA32.InLoadOrderModuleList @ +0x0C
        //   LDR_DATA_TABLE_ENTRY32: DllBase +0x18, SizeOfImage +0x20,
        //   FullDllName (UNICODE_STRING32) +0x24, Buffer +0x28
        IntPtr tmp = Marshal.AllocHGlobal(8);
        try {
            int ret;
            byte[] z = new byte[8];
            Marshal.Copy(z, 0, tmp, 8);
            if (NtQueryInformationProcess(h, 26, tmp, 8, out ret) != 0) return new string[0];
            long peb32 = Marshal.ReadInt64(tmp, 0);
            if (peb32 < 0x10000) return new string[0];
            byte[] b = ReadMem(h, peb32 + 0x0C, 4);
            if (b == null) return new string[0];
            long ldr = BitConverter.ToUInt32(b, 0);
            if (ldr < 0x10000) return new string[0];
            b = ReadMem(h, ldr + 0x0C, 4);
            if (b == null) return new string[0];
            long headAddr = ldr + 0x0C;
            long cur = BitConverter.ToUInt32(b, 0);
            System.Collections.Generic.List<string> outp = new System.Collections.Generic.List<string>();
            for (int i = 0; i < 1024 && cur >= 0x10000; i++) {
                byte[] ent = ReadMem(h, cur, 0x30);
                if (ent == null || ent.Length < 0x2C) break;
                long flink  = BitConverter.ToUInt32(ent, 0);
                long dllBase = BitConverter.ToUInt32(ent, 0x18);
                int  size    = BitConverter.ToInt32(ent, 0x20);
                short uLen   = BitConverter.ToInt16(ent, 0x24);
                long uBuf    = BitConverter.ToUInt32(ent, 0x28);
                string name = "";
                if (uLen > 0 && uLen < 1024 && uBuf != 0) {
                    byte[] nb = ReadMem(h, uBuf, uLen);
                    if (nb != null) name = Encoding.Unicode.GetString(nb);
                }
                if (dllBase >= 0x10000) outp.Add(dllBase + "|" + size + "|" + name);
                if (flink == 0 || flink == headAddr) break;
                cur = flink;
            }
            return outp.ToArray();
        } catch { return new string[0]; }
        finally { Marshal.FreeHGlobal(tmp); }
    }

    // Loaded kernel drivers via SystemModuleInformation (class 11).
    // Returns "fullName|imageBase|imageSize|shortName" entries.
    public static string[] QuerySystemModules() {
        System.Collections.Generic.List<string> outp = new System.Collections.Generic.List<string>();
        int len = 0x10000; int ret;
        IntPtr buf = IntPtr.Zero;
        for (int attempt = 0; attempt < 6; attempt++) {
            buf = Marshal.AllocHGlobal(len);
            int st = NtQuerySystemInformation(11, buf, len, out ret);
            if (st == 0) break;
            Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
            if (st == unchecked((int)0xC0000004) || ret > len) { len = ret + 0x1000; continue; }
            return outp.ToArray();
        }
        if (buf == IntPtr.Zero) return outp.ToArray();
        try {
            int count = Marshal.ReadInt32(buf, 0);
            bool p64 = IntPtr.Size == 8;
            int entrySize = p64 ? 296 : 284;
            int baseOff   = p64 ? 16 : 8;    // ImageBase within RTL_PROCESS_MODULE_INFORMATION
            int sizeOff   = p64 ? 24 : 12;   // ImageSize
            int otfOff    = p64 ? 38 : 26;   // OffsetToFileName (USHORT)
            int nameOff   = p64 ? 40 : 28;   // FullPathName[256]
            long off = p64 ? 8 : 4;
            for (int i = 0; i < count; i++) {
                long p = buf.ToInt64() + off + (long)i * entrySize;
                long ib = p64 ? Marshal.ReadInt64((IntPtr)p, baseOff) : Marshal.ReadInt32((IntPtr)p, baseOff);
                int  sz = Marshal.ReadInt32((IntPtr)p, sizeOff);
                int  otf = Marshal.ReadInt16((IntPtr)p, otfOff);
                string full = Marshal.PtrToStringAnsi((IntPtr)(p + nameOff)) ?? "";
                string shortName = Marshal.PtrToStringAnsi((IntPtr)(p + nameOff + otf)) ?? full;
                outp.Add(full + "|" + ib + "|" + sz + "|" + shortName);
            }
        } catch { }
        finally { Marshal.FreeHGlobal(buf); }
        return outp.ToArray();
    }

    // Parent PID of a process (InheritedFromUniqueProcessId). Used to tell
    // apart the full-access handle a parent legitimately keeps on the child
    // it just created with CreateProcess, from a handle on an unrelated
    // process (which is what an injector needs). -1 = unknown/protected.
    public static long GetParentPid(int pid) {
        IntPtr h = OpenProcess(0x1000 /*QUERY_LIMITED_INFORMATION*/, false, pid);
        if (h == IntPtr.Zero) h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return -1;
        try {
            IntPtr tmp = Marshal.AllocHGlobal(0x30);
            try {
                int ret;
                byte[] z = new byte[0x30];
                Marshal.Copy(z, 0, tmp, 0x30);
                if (NtQueryInformationProcess(h, 0, tmp, 0x30, out ret) != 0) return -1;
                return Marshal.ReadInt64(tmp, IntPtr.Size == 8 ? 0x28 : 0x14);
            } finally { Marshal.FreeHGlobal(tmp); }
        } finally { CloseHandle(h); }
    }

    // ---- live injector detection: system handle table triad --------------
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcH, IntPtr dstProc,
                                       out IntPtr dstH, int access, bool inherit, int options);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetProcessId(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    public const int PROCESS_DUP_HANDLE    = 0x0040;
    public const int DUPLICATE_SAME_ACCESS = 0x0002;
    // CreateRemoteThread + WriteProcessMemory + VirtualAllocEx rights triad
    public const uint INJECT_TRIAD = 0x0002 /*CREATE_THREAD*/ | 0x0008 /*VM_OPERATION*/ | 0x0020 /*VM_WRITE*/;

    // SystemExtendedHandleInformation (class 64): every open handle in the
    // system with its owner PID, handle value and granted access mask.
    // Candidates (granted access contains the injection triad) are then
    // VERIFIED: the handle is duplicated into this process and GetProcessId
    // is called on it - file/key/section handles that merely share those bit
    // patterns return 0 here and are dropped, so the access-mask filter alone
    // never produces a finding. Returns "ownerPid|targetPid|0xACC".
    public static string[] FindInjectionHandles() {
        System.Collections.Generic.List<string> outp = new System.Collections.Generic.List<string>();
        int len = 0x400000; int ret; IntPtr buf = IntPtr.Zero;
        for (int attempt = 0; attempt < 8; attempt++) {
            buf = Marshal.AllocHGlobal(len);
            int st = NtQuerySystemInformation(64, buf, len, out ret);
            if (st == 0) break;
            Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
            if (st == unchecked((int)0xC0000004) || ret > len) { len = ret + 0x100000; continue; }
            return outp.ToArray();
        }
        if (buf == IntPtr.Zero) return outp.ToArray();
        try {
            bool p64 = IntPtr.Size == 8;
            long count = p64 ? Marshal.ReadInt64(buf, 0) : Marshal.ReadInt32(buf, 0);
            int entrySize = p64 ? 40 : 24;   // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
            int pidOff    = p64 ? 8 : 4;
            int hOff      = p64 ? 16 : 8;
            int gaOff     = p64 ? 24 : 12;
            long off      = p64 ? 16 : 8;    // header: NumberOfHandles + Reserved
            uint me = GetCurrentProcessId();
            // group candidate handles by owner -> one OpenProcess per owner
            var byOwner = new System.Collections.Generic.Dictionary<int, System.Collections.Generic.List<long[]>>();
            for (long i = 0; i < count; i++) {
                long p = buf.ToInt64() + off + i * entrySize;
                uint ga = (uint)Marshal.ReadInt32((IntPtr)(p + gaOff));
                if ((ga & INJECT_TRIAD) != INJECT_TRIAD) continue;
                long pid = p64 ? Marshal.ReadInt64((IntPtr)(p + pidOff)) : Marshal.ReadInt32((IntPtr)(p + pidOff));
                long hv  = p64 ? Marshal.ReadInt64((IntPtr)(p + hOff))  : Marshal.ReadInt32((IntPtr)(p + hOff));
                if (pid <= 4 || pid == (long)me) continue;  // System/Idle/self: never an injector
                int ipid = (int)pid;
                if (!byOwner.ContainsKey(ipid)) byOwner[ipid] = new System.Collections.Generic.List<long[]>();
                byOwner[ipid].Add(new long[] { hv, ga });
            }
            foreach (var kv in byOwner) {
                IntPtr op = OpenProcess(PROCESS_DUP_HANDLE, false, kv.Key);
                if (op == IntPtr.Zero) continue;  // protected owner: cannot verify, do not guess
                int dups = 0;
                foreach (long[] cand in kv.Value) {
                    if (++dups > 1000) break;     // safety cap on pathological owners
                    IntPtr dup;
                    if (!DuplicateHandle(op, (IntPtr)cand[0], GetCurrentProcess(), out dup, 0, false, DUPLICATE_SAME_ACCESS)) continue;
                    try {
                        uint tpid = GetProcessId(dup);   // 0 => not a process handle
                        if (tpid != 0 && tpid != (uint)kv.Key) {
                            outp.Add(kv.Key + "|" + tpid + "|0x" + ((uint)cand[1]).ToString("X"));
                        }
                    } finally { CloseHandle(dup); }
                }
                CloseHandle(op);
            }
        } catch { }
        finally { Marshal.FreeHGlobal(buf); }
        return outp.ToArray();
    }
}
}
"@
}

# ---------------- SeDebugPrivilege (open protected processes) ---------------
if (-not ('MeowAudit.Token' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace MeowAudit {
public static class Token {
    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES tp, int len, IntPtr prev, IntPtr ret);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public static bool EnableDebugPrivilege() {
        try {
            IntPtr tok; int acc = 0x20 /*TOKEN_ADJUST_PRIVILEGES*/ | 0x8 /*TOKEN_QUERY*/;
            if (!OpenProcessToken(GetCurrentProcess(), acc, out tok)) return false;
            LUID luid; if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) { CloseHandle(tok); return false; }
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES(); tp.PrivilegeCount = 1; tp.Luid = luid; tp.Attributes = 0x2; // SE_PRIVILEGE_ENABLED
            bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(tok); return ok;
        } catch { return false; }
    }
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
}
}
"@
}
try { [MeowAudit.Token]::EnableDebugPrivilege() | Out-Null } catch { }

# ---------------- Fast scanning engine (performance) --------------------------
# Signature verification via WinVerifyTrust in parallel + all hot memory
# walks in C#. PowerShell loops over thousands of modules/regions/thunks were
# the main reason scans were slow (~38 s just for Authenticode + per-byte
# compare loops in PS). One C# call per process instead of thousands of PS
# iterations: full scan target ~30 s.
if (-not ('MeowAudit.Fast' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace MeowAudit {
public static class Fast {
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, int s, out int r);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(int a, bool i, int tid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, int l);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int c, out IntPtr i, int l, out int rl);
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pActionID, ref WINTRUST_DATA pWVTData);

    // catalog signature lookup (files signed via .cat, no embedded blob)
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, int dwFlags);
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, int dwFlags, IntPtr pwszHashAlgorithm, IntPtr pvReserved);
    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, int dwFlags);
    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, int dwFlags);
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);
    [DllImport("wintrust.dll", CharSet=CharSet.Unicode)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, out CATINFO lpCatInfo, int dwFlags);
    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);
    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFileW(string name, int access, int share, IntPtr sec, int disp, int flags, IntPtr tmpl);

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase;
        public uint AllocationProtect; public UIntPtr RegionSize;
        public uint State; public uint Protect; public uint Type;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct WINTRUST_FILE_INFO {
        public int cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile; public IntPtr pgKnownSubject;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct WINTRUST_DATA {
        public int cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData;
        public int dwUIChoice; public int fdwRevocationChecks; public int dwUnionChoice;
        public IntPtr pFile; public int dwStateAction; public IntPtr hWVTStateData;
        public IntPtr pwszURLReference; public int dwProvFlags; public int dwUIContext;
        public IntPtr pSignatureSettings;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct CATINFO { public int cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

    static readonly ConcurrentDictionary<string, string> SigStatus =
        new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    static readonly ConcurrentDictionary<string, string> SigSigner =
        new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    static readonly ConcurrentDictionary<string, byte[]> DiskHeads =
        new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
    static readonly ConcurrentDictionary<string, string> CatSigners =
        new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    static readonly Guid WT_ACTION = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // Read with fallback: RPM fails entirely if the range crosses an unreadable
    // page, so halve until it succeeds (returns partial allowed).
    static byte[] ReadTry(IntPtr h, long addr, int size) {
        int s = size;
        while (s >= 16) {
            byte[] buf = new byte[s]; int rd;
            if (ReadProcessMemory(h, (IntPtr)addr, buf, s, out rd) && rd > 0) {
                if (rd < s) { byte[] t = new byte[rd]; Array.Copy(buf, t, rd); return t; }
                return buf;
            }
            s = s / 2;
        }
        return null;
    }

    static string MapStatus(int st) {
        uint u = (uint)st;
        if ((u & 0x80000000) == 0) return "Valid";        // SUCCESS / informational
        if (u == 0x800B0100) return "NotSigned";           // TRUST_E_NOSIGNATURE
        if (u == 0x80096010) return "HashMismatch";        // TRUST_E_BAD_DIGEST
        return "NotTrusted";
    }

    static int VerifyOne(string path) {
        WINTRUST_FILE_INFO fi = new WINTRUST_FILE_INFO();
        fi.cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
        fi.pcwszFilePath = path;
        IntPtr pFi = Marshal.AllocHGlobal(fi.cbStruct);
        try {
            Marshal.StructureToPtr(fi, pFi, false);
            WINTRUST_DATA wd = new WINTRUST_DATA();
            wd.cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA));
            wd.dwUIChoice = 2;            // WTD_UI_NONE
            wd.fdwRevocationChecks = 0;   // no network revocation lookups
            wd.dwUnionChoice = 1;         // WTD_CHOICE_FILE
            wd.pFile = pFi;
            wd.dwProvFlags = 0x1000;      // WTD_CACHE_ONLY_URL_RETRIEVAL
            Guid act = WT_ACTION;
            return WinVerifyTrust(IntPtr.Zero, ref act, ref wd);
        } finally { Marshal.FreeHGlobal(pFi); }
    }

    // Is the file a member of a catalog that itself carries a valid embedded
    // signature? Returns the catalog signer's subject, else null. This mirrors
    // what Get-AuthenticodeSignature does for the ~73% of Windows system DLLs
    // that have no embedded blob (measured 331/450) - in native code so the
    // batch stays fast.
    static string CatalogSigner(string path) {
        try {
            // A catalog hash covers the WHOLE file: a multi-GB installer in
            // Downloads cost seconds of hashing here, and no Windows catalog
            // member is anywhere near this size. Skip = treat as NotSigned.
            FileInfo fi = new FileInfo(path);
            if (fi.Exists && fi.Length > 256L * 1024 * 1024) return null;
            IntPtr hFile = CreateFileW(path, unchecked((int)0x80000000) /*GENERIC_READ*/, 7 /*share rwd*/, IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero);
            if (hFile == IntPtr.Zero || hFile == (IntPtr)(-1)) return null;
            try {
                // SHA256 context first (modern catalogs), then legacy SHA1
                for (int alg = 0; alg < 2; alg++) {
                    IntPtr hCatAdmin = IntPtr.Zero;
                    bool got = alg == 0
                        ? CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero)
                        : CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0);
                    if (!got || hCatAdmin == IntPtr.Zero) continue;
                    try {
                        uint hlen = 32;
                        byte[] hash = new byte[hlen];
                        bool calc = alg == 0
                            ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hlen, hash, 0)
                            : CryptCATAdminCalcHashFromFileHandle(hFile, ref hlen, hash, 0);
                        if (!calc) continue;
                        byte[] h2 = new byte[hlen];
                        Array.Copy(hash, h2, (int)hlen);
                        IntPtr prev = IntPtr.Zero;
                        IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, h2, hlen, 0, ref prev);
                        if (hCatInfo == IntPtr.Zero) continue;
                        string catPath = null;
                        try {
                            CATINFO ci = new CATINFO();
                            ci.cbStruct = Marshal.SizeOf(typeof(CATINFO));
                            if (CryptCATCatalogInfoFromContext(hCatInfo, out ci, 0)) catPath = ci.wszCatalogFile;
                        } finally { CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0); }
                        if (string.IsNullOrEmpty(catPath)) return null;
                        string cached;
                        if (CatSigners.TryGetValue(catPath, out cached)) return cached;
                        string res = null;
                        // the catalog must itself carry a valid signature
                        if (MapStatus(VerifyOne(catPath)) == "Valid") {
                            try {
                                using (X509Certificate c = X509Certificate.CreateFromSignedFile(catPath)) { res = c.Subject; }
                            } catch { res = "(catalog signed)"; }
                        }
                        CatSigners[catPath] = res;
                        return res;
                    } finally { CryptCATAdminReleaseContext(hCatAdmin, 0); }
                }
            } finally { CloseHandle(hFile); }
        } catch { }
        return null;
    }

    // Batch signature verification across the parallel engine. ~900 files in
    // ~1-2 s (serial Get-AuthenticodeSignature measured ~38 s for the same
    // set). DOP follows the core count (capped at 16).
    public static void VerifySignatures(string[] paths) {
        if (paths == null) return;
        int dop = Environment.ProcessorCount;
        if (dop > 16) dop = 16;
        if (dop < 4) dop = 4;
        Parallel.ForEach(paths, new ParallelOptions { MaxDegreeOfParallelism = dop }, delegate(string p) {
            try {
                if (string.IsNullOrEmpty(p)) return;
                if (SigStatus.ContainsKey(p)) return;
                string st = MapStatus(VerifyOne(p));
                string sg = "";
                if (st == "Valid") {
                    try {
                        using (X509Certificate c = X509Certificate.CreateFromSignedFile(p)) { sg = c.Subject; }
                    } catch { }   // catalog-signed files have no embedded cert: signer comes from the catalog below
                } else if (st == "NotSigned") {
                    // most Windows system DLLs are catalog-signed only
                    string cat = CatalogSigner(p);
                    if (cat != null) { st = "Valid"; sg = cat; }
                }
                SigStatus[p] = st; SigSigner[p] = sg;
            } catch { }
        });
    }

    public static string GetSigStatus(string p) {
        string v;
        if (p != null && SigStatus.TryGetValue(p, out v)) return v;
        return null;
    }
    public static string GetSigSigner(string p) {
        string v;
        if (p != null && SigSigner.TryGetValue(p, out v)) return v;
        return "";
    }

    static byte[] DiskHead(string path) {
        byte[] b;
        if (DiskHeads.TryGetValue(path, out b)) return b;
        b = null;
        try {
            using (FileStream fs = File.OpenRead(path)) {
                b = new byte[512];
                int n = fs.Read(b, 0, 512);
                if (n < 512) { byte[] t = new byte[n]; Array.Copy(b, t, n); b = t; }
            }
        } catch { }
        DiskHeads[path] = b;
        return b;
    }

    // Memory-vs-disk header compare for one module. Excludes the relocated
    // ImageBase field (loader rewrites it - not tampering). Returns a reason
    // string when bytes differ, else null.
    public static string MemHeadDiff(IntPtr h, long addr, string path) {
        try {
            byte[] disk = DiskHead(path);
            if (disk == null || disk.Length < 64) return null;
            byte[] mem = ReadTry(h, addr, disk.Length);
            if (mem == null || mem.Length < 64) return null;
            int skipLo = -1, skipHi = -1;
            if (mem.Length > 0x40) {
                int e = BitConverter.ToInt32(mem, 0x3C);
                if (e > 0 && (e + 32) < mem.Length) {
                    ushort mg = BitConverter.ToUInt16(mem, e + 24);
                    if (mg == 0x20B) { skipLo = e + 48; skipHi = skipLo + 8; }
                    else if (mg == 0x10B) { skipLo = e + 52; skipHi = skipLo + 4; }
                }
            }
            int n = Math.Min(mem.Length, disk.Length);
            for (int i = 0; i < n; i++) {
                if (i >= skipLo && i < skipHi) continue;
                if (mem[i] != disk[i]) return "first diff at +0x" + i.ToString("X");
            }
            return null;
        } catch { return null; }
    }

    static bool InRanges(long[] rB, int[] rS, long v) {
        for (int i = 0; i < rB.Length; i++) {
            if (v >= rB[i] && v < rB[i] + rS[i]) return true;
        }
        return false;
    }

    // Follow a simple jump-stub (E9/EB rel, push/ret, mov eax/rax/r11 + jmp).
    // Returns the direct target, or -1 when the bytes are not a jump form.
    static long OneHopTarget(IntPtr h, long addr, out bool decoded) {
        decoded = false;
        byte[] b = ReadTry(h, addr, 24);
        if (b == null || b.Length < 5) return -1;
        bool x64 = IntPtr.Size == 8;
        if (b[0] == 0xE9) { decoded = true; return addr + 5 + BitConverter.ToInt32(b, 1); }
        if (b[0] == 0xEB) { decoded = true; return addr + 2 + (sbyte)b[1]; }
        if (!x64) {
            // 68 imm32 C3            push addr; ret
            if (b[0] == 0x68 && b[5] == 0xC3) { decoded = true; return BitConverter.ToInt32(b, 1); }
            // B8 imm32 FF E0         mov eax,imm; jmp eax
            if (b[0] == 0xB8 && b.Length > 6 && b[5] == 0xFF && b[6] == 0xE0) { decoded = true; return BitConverter.ToInt32(b, 1); }
            // FF 25 abs32            jmp dword ptr [abs]
            if (b[0] == 0xFF && b[1] == 0x25) {
                byte[] t = ReadTry(h, BitConverter.ToInt32(b, 2), 4);
                if (t != null && t.Length == 4) { decoded = true; return BitConverter.ToUInt32(t, 0); }
            }
        } else {
            // FF 25 rel32            jmp [rip+rel]
            if (b[0] == 0xFF && b[1] == 0x25) {
                byte[] t = ReadTry(h, addr + 6 + BitConverter.ToInt32(b, 2), 8);
                if (t != null && t.Length == 8) { decoded = true; return BitConverter.ToInt64(t, 0); }
            }
            // 48 B8 imm64 FF E0      mov rax,imm; jmp rax
            if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) { decoded = true; return BitConverter.ToInt64(b, 2); }
            // 49 BB imm64 41 FF E3   mov r11,imm; jmp r11
            if (b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3) { decoded = true; return BitConverter.ToInt64(b, 2); }
        }
        return -1;
    }

    // Does the first 32 bytes of a stub contain an absolute pointer into a
    // known module? Framework forwarding thunks (Chromium/CEF API forwarders,
    // Steam/overlay stubs) hard-code the address of the real implementation
    // as an immediate; self-contained malicious hooks reference only their own
    // payload instead.
    static bool StubRefsKnown(IntPtr h, long addr, long[] rB, int[] rS) {
        byte[] b = ReadTry(h, addr, 32);
        if (b == null || b.Length < 8) return false;
        for (int i = 0; i + 4 <= b.Length; i++) {
            long v = BitConverter.ToInt32(b, i);           // 32-bit immediates (x86 thunks)
            if (v > 0x10000 && InRanges(rB, rS, v)) return true;
        }
        for (int i = 0; i + 8 <= b.Length; i++) {
            long v = BitConverter.ToInt64(b, i);           // 64-bit immediates (x64 thunks)
            if (v > 0x10000 && InRanges(rB, rS, v)) return true;
        }
        return false;
    }

    // True when the import target is a legitimate framework forwarding stub:
    //   - it lives in a small MEM_PRIVATE executable region (not a module), AND
    //   - it either jumps straight into a known module, or hard-codes a known
    //     module address as an immediate (the real API implementation).
    // Real IAT hooks are trampolines to shellcode / manual-map code and fail
    // both tests (measured: 16 CEF thunks per Spotify process, 0 on clean).
    static bool IsForwardingThunk(IntPtr h, long val, long[] rB, int[] rS) {
        try {
            MBI mbi;
            if (VirtualQueryEx(h, (IntPtr)val, out mbi, Marshal.SizeOf(typeof(MBI))) == 0) return false;
            uint st = mbi.State;      // MEM_COMMIT = 0x1000
            uint ty = mbi.Type;       // MEM_PRIVATE = 0x20000
            if (st != 0x1000 || ty != 0x20000) return false;   // only private stub pages
            bool dec; long hop = OneHopTarget(h, val, out dec);
            if (dec && hop > 0x10000 && InRanges(rB, rS, hop)) return true;
            return StubRefsKnown(h, val, rB, rS);
        } catch { return false; }
    }

    // True when the slot value cannot be a resolved function address: the
    // region it points at is not MEM_COMMIT (FREE / RESERVE, or the value is
    // not even a canonical user address so the query fails). Resolved imports
    // always point at committed code; raw on-disk thunks of a never-bound
    // image (RVA / preferred-base VA) do not.
    static bool IsUnresolvedSlot(IntPtr h, long val) {
        try {
            MBI mbi;
            if (VirtualQueryEx(h, (IntPtr)val, out mbi, Marshal.SizeOf(typeof(MBI))) == 0) return true;
            return mbi.State != 0x1000;   // MEM_COMMIT
        } catch { return true; }
    }

    // Walk the import directory of a module (bulk thunk reads) and return
    // IAT entries that point outside every known module -> IAT hooking.
    public static long[] IatFindHooks(IntPtr h, long baseAddr, long[] rB, int[] rS) {
        List<long> hits = new List<long>();
        try {
            byte[] dos = ReadTry(h, baseAddr, 0x40);
            if (dos == null || dos.Length < 0x40 || dos[0] != 0x4D) return hits.ToArray();
            int e = BitConverter.ToInt32(dos, 0x3C);
            if (e < 0x40 || e > 0x1000) return hits.ToArray();
            byte[] nt = ReadTry(h, baseAddr + e, 0x200);
            if (nt == null || nt.Length < 0x200 || BitConverter.ToUInt32(nt, 0) != 0x4550) return hits.ToArray();
            ushort mg = BitConverter.ToUInt16(nt, 24);
            int ddOff; int step;
            if (mg == 0x20B) { ddOff = 144; step = 8; }
            else if (mg == 0x10B) { ddOff = 128; step = 4; }
            else return hits.ToArray();
            uint impRva = BitConverter.ToUInt32(nt, ddOff);
            if (impRva == 0) return hits.ToArray();
            for (int d = 0; d < 128; d++) {
                byte[] desc = ReadTry(h, baseAddr + impRva + d * 20, 20);
                if (desc == null || desc.Length < 20) break;
                uint ft = BitConverter.ToUInt32(desc, 16);
                if (ft == 0) break;
                long off = 0;
                while (off < 16384) {
                    byte[] chunk = ReadTry(h, baseAddr + ft + off, 4096);
                    if (chunk == null || chunk.Length < step) {
                        chunk = ReadTry(h, baseAddr + ft + off, step);
                        if (chunk == null || chunk.Length < step) break;
                    }
                    int cnt = chunk.Length / step;
                    bool term = false;
                    for (int t = 0; t < cnt; t++) {
                        ulong raw = step == 8 ? BitConverter.ToUInt64(chunk, t * step)
                                              : BitConverter.ToUInt32(chunk, t * step);
                        if (raw == 0) { term = true; break; }
                        bool ordinal = step == 8 ? (raw & 0x8000000000000000UL) != 0
                                                 : (raw & 0x80000000UL) != 0;
                        if (ordinal) continue;
                        long val = (long)raw;
                        if (val > 0x10000 && !InRanges(rB, rS, val)) {
                            // An image whose imports were never resolved (e.g.
                            // the kernel image SearchHost maps with
                            // DONT_RESOLVE_DLL_REFERENCES) still carries raw
                            // on-disk IAT values - RVAs / preferred-base VAs
                            // aimed at FREE addresses (measured: hits match the
                            // on-disk symcryptk/PSHED thunks byte for byte).
                            // A resolved import ALWAYS points at committed
                            // memory, so uncommitted targets are not hooks.
                            if (IsUnresolvedSlot(h, val)) continue;
                            // Triage: framework forwarding thunks (Chromium/CEF
                            // API forwarders, overlay stubs) redirect imports to
                            // small stubs in private RX memory that immediately
                            // call into a known module. Skip those; real IAT
                            // hooks land in code that is NOT part of any module
                            // (shellcode / manual-map trampoline).
                            if (IsForwardingThunk(h, val, rB, rS)) continue;
                            hits.Add(val);
                            if (hits.Count >= 16) return hits.ToArray();
                        }
                    }
                    off += (long)cnt * step;
                    if (term || chunk.Length < 4096) break;
                }
            }
        } catch { }
        return hits.ToArray();
    }

    // Compare ntdll .text in memory vs on disk (first 4 KB of the section) ->
    // inline hooks / unhooking / direct-syscall stubs.
    // The loader applies base relocations to absolute addresses baked into
    // .text; x86 ntdll is full of them (measured: ~19 KB of relocated dwords
    // per WOW64 process - first diff at .text+0x6, high word = base>>16).
    // Patch the disk copy with the actual load delta BEFORE comparing, so
    // relocation fixups never read as inline hooks, while real byte changes
    // still do.
    public static bool NtdllTampered(IntPtr h, long baseAddr, string diskPath) {
        try {
            byte[] disk = File.ReadAllBytes(diskPath);
            int e = BitConverter.ToInt32(disk, 0x3C);
            int optOff = e + 24;
            ushort magic = BitConverter.ToUInt16(disk, optOff);
            bool pe32 = (magic == 0x10B);
            int secOff = optOff + BitConverter.ToUInt16(disk, e + 20);
            ushort nsec = BitConverter.ToUInt16(disk, e + 6);
            int tRva = -1, tRaw = -1, tRawSz = -1;
            for (int i = 0; i < nsec; i++) {
                int so = secOff + i * 40;
                if (so + 40 > disk.Length) break;
                string nm = Encoding.ASCII.GetString(disk, so, 8).TrimEnd('\0');
                if (nm == ".text") {
                    tRva = BitConverter.ToInt32(disk, so + 12);
                    tRawSz = BitConverter.ToInt32(disk, so + 16);
                    tRaw = BitConverter.ToInt32(disk, so + 20);
                    break;
                }
            }
            if (tRva < 0 || tRaw < 0 || tRawSz <= 0) return false;
            int cmpLen = Math.Min(0x1000, tRawSz);
            if (tRaw + cmpLen > disk.Length) return false;
            byte[] cmp = new byte[cmpLen];
            Array.Copy(disk, tRaw, cmp, 0, cmpLen);

            // Rebase the disk .text with the loader's relocation fixups.
            long imgBase = pe32 ? BitConverter.ToUInt32(disk, optOff + 28)
                                : (long)BitConverter.ToUInt64(disk, optOff + 24);
            long delta = baseAddr - imgBase;
            if (delta != 0) {
                int ddOff = pe32 ? 96 : 112;                       // DataDirectory
                int relRva = BitConverter.ToInt32(disk, optOff + ddOff + 5 * 8);
                int relSz = BitConverter.ToInt32(disk, optOff + ddOff + 5 * 8 + 4);
                int relRaw = Rva2FileOff(disk, secOff, nsec, relRva);
                int end = Math.Min(relRaw + relSz, disk.Length);
                int pos = relRaw;
                while (relRva > 0 && pos >= 0 && pos + 8 <= end) {
                    uint pageRva = BitConverter.ToUInt32(disk, pos);
                    uint blk = BitConverter.ToUInt32(disk, pos + 4);
                    if (blk < 8 || pos + blk > end) break;
                    int n = (int)((blk - 8) / 2);
                    int pair = 0;                                   // HIGHADJ consumes next slot
                    for (int i = 0; i < n; i++) {
                        if (pair > 0) { pair--; continue; }
                        ushort ent = BitConverter.ToUInt16(disk, pos + 8 + i * 2);
                        int typ = ent >> 12;
                        long tgt = (long)pageRva + (ent & 0xFFF);
                        if (typ == 3 && pe32) {                     // IMAGE_REL_BASED_HIGHLOW
                            int ci = (int)(tgt - tRva);
                            if (tgt >= tRva && ci + 4 <= cmpLen) {
                                uint v = BitConverter.ToUInt32(cmp, ci);
                                BitConverter.GetBytes(unchecked(v + (uint)delta)).CopyTo(cmp, ci);
                            }
                        } else if (typ == 10 && !pe32) {            // IMAGE_REL_BASED_DIR64
                            int ci = (int)(tgt - tRva);
                            if (tgt >= tRva && ci + 8 <= cmpLen) {
                                ulong v = BitConverter.ToUInt64(cmp, ci);
                                BitConverter.GetBytes(unchecked(v + (ulong)delta)).CopyTo(cmp, ci);
                            }
                        } else if (typ == 4) { pair = 1; }          // HIGHADJ: paired word follows
                    }
                    pos += (int)blk;
                }
            }

            byte[] mem = ReadTry(h, baseAddr + tRva, cmpLen);
            if (mem == null || mem.Length < cmpLen) return false;
            using (SHA256 sha = SHA256.Create()) {
                byte[] hMem = sha.ComputeHash(mem, 0, cmpLen);
                byte[] hDsk = sha.ComputeHash(cmp, 0, cmpLen);
                for (int i = 0; i < hMem.Length; i++) { if (hMem[i] != hDsk[i]) return true; }
            }
            return false;
        } catch { return false; }
    }

    // PE RVA -> file offset (section table walk).
    static int Rva2FileOff(byte[] pe, int secOff, ushort nsec, int rva) {
        if (rva <= 0) return -1;
        for (int i = 0; i < nsec; i++) {
            int so = secOff + i * 40;
            if (so + 40 > pe.Length) break;
            uint va = BitConverter.ToUInt32(pe, so + 12);
            uint vs = BitConverter.ToUInt32(pe, so + 8);
            uint rp = BitConverter.ToUInt32(pe, so + 20);
            if (rva >= va && rva < va + Math.Max(vs, 1u)) return (int)(rp + ((uint)rva - va));
        }
        return -1;
    }

    // Threads whose start address is not inside any module -> shellcode /
    // manual-map entry point. Returns "tid|addr" strings.
    public static string[] ShellcodeThreads(IntPtr h, int[] tids, long[] rB, int[] rS) {
        List<string> hits = new List<string>();
        if (tids == null) return hits.ToArray();
        foreach (int tid in tids) {
            try {
                IntPtr th = OpenThread(0x0040 /*THREAD_QUERY_INFORMATION*/, false, tid);
                if (th == IntPtr.Zero) continue;
                IntPtr sa; int rl;
                if (NtQueryInformationThread(th, 9, out sa, IntPtr.Size, out rl) == 0) {
                    long v = sa.ToInt64();
                    if (v > 0x10000 && !InRanges(rB, rS, v)) {
                        MBI mbi;
                        if (VirtualQueryEx(h, (IntPtr)v, out mbi, Marshal.SizeOf(typeof(MBI))) != 0
                            && mbi.State == 0x1000 && mbi.Type != 0x1000000) {
                            hits.Add(tid + "|" + v.ToString("X"));
                        }
                    }
                }
                CloseHandle(th);
            } catch { }
        }
        return hits.ToArray();
    }

    static bool ValidPe(IntPtr h, long addr) {
        try {
            byte[] dos = ReadTry(h, addr, 0x40);
            if (dos == null || dos.Length < 0x40) return false;
            if (dos[0] != 0x4D || dos[1] != 0x5A) return false;
            int e = BitConverter.ToInt32(dos, 0x3C);
            if (e < 0x40 || e > 0x1000) return false;
            byte[] nt = ReadTry(h, addr + e, 0x60);
            if (nt == null || nt.Length < 0x60) return false;
            if (BitConverter.ToUInt32(nt, 0) != 0x4550) return false;
            ushort mach = BitConverter.ToUInt16(nt, 4);
            if (mach != 0x8664 && mach != 0x014C && mach != 0xAA64 && mach != 0x01C4) return false;
            int img = BitConverter.ToInt32(nt, 56);
            if (img <= 0 || img > 0x40000000) return false;
            return true;
        } catch { return false; }
    }

    static string TypeStr(uint t) {
        if (t == 0x1000000) return "IMAGE";
        if (t == 0x40000) return "MAPPED";
        if (t == 0x20000) return "PRIVATE";
        return "0x" + t.ToString("X");
    }

    // True when the image mapped at 'baseAddr' in process h corresponds to the
    // file on disk: headers + section content must match byte-for-byte, EXCEPT
    // for the bytes the OS itself rewrites when any SEC_IMAGE view gets mapped:
    // the ImageBase field, every target slot of the .reloc directory, and the
    // kernel-written "fothk" prefix (verified empirically: after these masks a
    // raw kernel-side SEC_IMAGE map of system images is byte-identical to disk
    // across kernel32/ntdll/kernelbase/user32/advapi32/gdi32/combase/ole32).
    // An unsigned, patched or repacked payload never passes all three gates
    // (signature + PE identity + this byte compare).
    public static bool RegionMatchesFile(IntPtr h, long baseAddr, string path) {
        try {
            byte[] disk = ReadAllShared(path);
            if (disk == null || disk.Length < 0x40 || disk[0] != 0x4D || disk[1] != 0x5A) return false;
            int lf = BitConverter.ToInt32(disk, 0x3C);
            if (lf < 0x40 || lf + 24 > disk.Length) return false;
            if (disk[lf] != 0x50 || disk[lf + 1] != 0x45 || disk[lf + 2] != 0 || disk[lf + 3] != 0) return false;
            int opt = lf + 24;
            ushort magic = BitConverter.ToUInt16(disk, opt);
            int soh = (int)BitConverter.ToUInt32(disk, opt + 60);   // SizeOfHeaders
            int soi = (int)BitConverter.ToUInt32(disk, opt + 56);   // SizeOfImage
            int nsec = BitConverter.ToUInt16(disk, lf + 6);
            int sizeOpt = BitConverter.ToUInt16(disk, lf + 20);
            if (soi < 0x1000 || soi > 0x20000000) return false;
            byte[] img = new byte[soi];
            int hdr = Math.Min(Math.Min(soh, disk.Length), soi);
            Buffer.BlockCopy(disk, 0, img, 0, hdr);
            int secOff = opt + sizeOpt;
            int[] secVa = new int[nsec], secRawPt = new int[nsec], secRawSz = new int[nsec];
            bool[] skip = new bool[soi];          // bytes the OS itself rewrites at map time
            int nread = 0;
            for (int i = 0; i < nsec; i++) {
                int o = secOff + i * 40;
                if (o + 40 > disk.Length) break;
                secVa[i] = (int)BitConverter.ToUInt32(disk, o + 12);
                secRawSz[i] = (int)BitConverter.ToUInt32(disk, o + 16);
                secRawPt[i] = (int)BitConverter.ToUInt32(disk, o + 20);
                nread = i + 1;
                // "fothk" (forwarder-thunk) prefix: the kernel writes a few bytes
                // there at map time (observed offsets 0x11-0x32 on Win11 system
                // images) without listing them in .reloc - tolerate a bounded
                // 0x80-byte prefix so vendor system images verify, without giving
                // an attacker a whole section to hide in.
                if (disk[o] == 'f' && disk[o + 1] == 'o' && disk[o + 2] == 't' && disk[o + 3] == 'h' && disk[o + 4] == 'k') {
                    for (int k = 0; k < 0x80 && secVa[i] + k >= 0 && secVa[i] + k < soi; k++) skip[secVa[i] + k] = true;
                }
                if (secRawPt[i] == 0 || secRawSz[i] == 0 || secVa[i] >= soi || secVa[i] < 0) continue;
                long len = Math.Min((long)secRawSz[i], (long)disk.Length - secRawPt[i]);
                len = Math.Min(len, (long)soi - secVa[i]);
                if (len <= 0) continue;
                Buffer.BlockCopy(disk, secRawPt[i], img, secVa[i], (int)len);
            }
            // bytes the OS legitimately rewrites when the image is mapped
            int ibOff = opt + ((magic == 0x20B) ? 24 : 28);          // ImageBase field
            for (int i = 0; i < 8 && ibOff + i >= 0 && ibOff + i < soi; i++) skip[ibOff + i] = true;
            int ddOff = opt + ((magic == 0x20B) ? 112 : 96);         // DataDirectory[5] = .reloc
            int needOpt = (magic == 0x20B) ? 160 : 144;
            if (sizeOpt >= needOpt && ddOff + 48 <= disk.Length) {
                uint relRva = BitConverter.ToUInt32(disk, ddOff + 40);
                uint relLen = BitConverter.ToUInt32(disk, ddOff + 44);
                int relFo = -1;
                if (relRva > 0 && relLen >= 8 && relLen <= 0x400000) {
                    for (int i = 0; i < nread; i++) {
                        if (secRawSz[i] <= 0 || secVa[i] < 0) continue;
                        if (relRva >= (uint)secVa[i] && relRva < (uint)secVa[i] + (uint)secRawSz[i]) {
                            relFo = secRawPt[i] + (int)(relRva - (uint)secVa[i]);
                            break;
                        }
                    }
                }
                if (relFo >= 0 && (long)relFo + relLen <= disk.Length) {
                    uint pos = 0;
                    while (pos + 8 <= relLen) {
                        int fo = relFo + (int)pos;
                        uint pageRva = BitConverter.ToUInt32(disk, fo);
                        uint bs = BitConverter.ToUInt32(disk, fo + 4);
                        if (bs < 8 || pos + bs > relLen) break;
                        for (uint e = 8; e + 2 <= bs; e += 2) {
                            ushort ent = BitConverter.ToUInt16(disk, fo + (int)e);
                            int type = ent >> 12;
                            if (type == 0) continue;                  // ABSOLUTE padding
                            int len = (type == 10) ? 8 : 4;           // DIR64 / HIGHLOW
                            int tgt = (int)pageRva + (ent & 0xFFF);
                            for (int i = 0; i < len; i++)
                                if (tgt + i >= 0 && tgt + i < soi) skip[tgt + i] = true;
                        }
                        pos += bs;
                    }
                }
            }
            byte[] remote = new byte[soi];
            int rd = 0;
            ReadProcessMemory(h, (IntPtr)baseAddr, remote, soi, out rd);
            if (rd != soi) return false;          // partial read: stay conservative
            for (int i = 0; i < soi; i++) if (!skip[i] && remote[i] != img[i]) return false;
            return true;
        } catch { return false; }
    }
    static byte[] ReadAllShared(string path) {
        try {
            using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Open,
                    System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete)) {
                byte[] b = new byte[(int)fs.Length];
                int off = 0, n;
                while (off < b.Length && (n = fs.Read(b, off, b.Length - off)) > 0) off += n;
                return (off == b.Length) ? b : null;
            }
        } catch { return null; }
    }

    // One walk over all memory regions of a process (replaces the PS loop).
    // Returns:
    //   "STAT|execRegions|execKB|wxRegions|wxKB|orphanImageCount"
    //   "PE|0x<allocBase>|<sizeKB>|<type>"   -> hidden PE (manual map / section)
    public static string[] RegionScan(IntPtr h, long[] known) {
        List<string> outp = new List<string>();
        long[] ks = known ?? new long[0];
        Array.Sort(ks);
        int exec = 0, execKB = 0, wx = 0, wxKB = 0, sec = 0;
        long addr = 0;
        try {
            while (true) {
                MBI mbi;
                int r = VirtualQueryEx(h, (IntPtr)addr, out mbi, Marshal.SizeOf(typeof(MBI)));
                if (r == 0) break;
                if (mbi.State == 0x1000) {
                    uint prot = mbi.Protect & 0xFF;
                    bool isExec = prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80;
                    if (isExec) {
                        long sz = (long)mbi.RegionSize;
                        int kb = (int)(sz / 1024);
                        exec++; execKB += kb;
                        bool isWx = prot == 0x40 || prot == 0x80;
                        if (isWx) { wx++; wxKB += kb; }
                        long ab = mbi.AllocationBase.ToInt64();
                        bool knownHit = Array.BinarySearch(ks, ab) >= 0;
                        if (!knownHit) {
                            if (ValidPe(h, ab)) {
                                outp.Add("PE|" + ab.ToString("X") + "|" + kb + "|" + TypeStr(mbi.Type));
                            }
                        }
                        if (mbi.Type == 0x1000000 && !knownHit) sec++;
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
        } catch { }
        outp.Insert(0, "STAT|" + exec + "|" + execKB + "|" + wx + "|" + wxKB + "|" + sec);
        return outp.ToArray();
    }
}
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
    "$env:TEMP\.bun-*",
    # lz4-java extracts a hashed native into Temp on every JVM start
    "$env:TEMP\liblz4-java-*.so",
    # --- SS quiet list (operator, 2026-10-28): known-good noise on ANY
    # machine, so an SS run does not drown in unsigned debugger builds and
    # operator tools. Real detections deliberately NOT here: autoclicker
    # files, Praise.exe, injector64.exe (keyword) keep reporting.
    "*\x64dbg-unsigned.exe",
    "*\x32dbg-unsigned.exe",
    "*\release\*\headless.exe",
    "*\CercaParole.*",
    "*\MeowImportsChecker.exe",
    "*\SSTool.exe",
    "*\Shard beta\Shard.exe",
    "*\hollow_detector.exe"      # process-hollowing detector (operator tool, 2026-10-29)
)

# ---------------- Hash whitelist (v8.2, content-addressed) ----------------
# SHA256 (lowercase) of the operator's own toolset, vouched 2026-10-30.
# Only these EXACT bytes are silenced anywhere - a different file that merely
# shares the name still reports as before, and keyword matches (rule 1) never
# reach this check, so keyword hits can never be hash-whitelisted away.
$script:whitelistHashes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
@(
    '39ae55d7af43d16149fc3235ebbeb8a74509b0a6ac46cf0d01592556acb4a3b0',  # CompilerIdCXX.exe (CMake compiler-id probe)
    'e8c55696ebb0ca8ecffa74a20e9860627886501905bb9112ac9fe2b3b5dd3935',  # mc-ss-tool.exe
    'ad436e3d6776c7c32023c76734139666d9c24c7b14b729ff47ba654af2021989',  # MeowClientFucker.exe
    'bc93aa88f8336478f44f8fbbfcb0ae54f1e9bf4e256a4c0ebf8e5b0ccdb61310',  # MeowDoomsdayFucker.exe
    '7f31bbd422815303bbd99d58a247a19937adc9bbcdd451a82d552505a379672d',  # SS-Shellcode-Scanner(1).exe (Downloads copy)
    '6237f5a43f8a2312213fade2bd36161b5746ebecd1c082d6bf6d02055be0d1e3'   # SS-Shellcode-Scanner.exe (both copies)
) | ForEach-Object { [void]$script:whitelistHashes.Add($_) }
$script:hashCache = @{}   # path -> sha256 (lowercase) or $null when unreadable

# Known native library names accepted inside .minecraft. 'odin' covers
# odin.dll / odinwrapper.dll shipped in client natives folders: rule 4 runs
# BEFORE the signature check, so even the Valid-signed odin.dll was reported.
$script:MinecraftNatives = '^(lwjgl|OpenAL|jinput|glfw|jawt|odin)'

# ---------------- Per-machine whitelist (operator-defined) ----------------
# <report folder>\MEOW_whitelist.txt: one '-like' pattern per line, or a
# 'sha256:<64 hex>' line (v8.2) to whitelist ONE file by content. '#' lines
# are comments. Silences files the operator has vouched for ON THIS MACHINE
# ONLY - the file is never bundled with the tool, so a screenshare target is
# still scanned with the full rule set. Keywords always beat it.
$script:userWhitelist = @()
$script:userWhitelistHashes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$wlFile = Join-Path $OutputDir 'MEOW_whitelist.txt'
try {
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $wlFile)) {
        $wlSeed = @'
# MEOW per-machine whitelist - one pattern per line (-like syntax), or a
# hash line: sha256:<64 hex>  (whitelists exactly that file content).
# Lines starting with # are ignored. Patterns match the FULL path, e.g.:
#   C:\Users\*\Downloads\my-tool.exe
#   C:\Tools\*\helper.dll
#   sha256:39ae55d7af43d16149fc3235ebbeb8a74509b0a6ac46cf0d01592556acb4a3b0
# Keyword matches (inject/cheat/...) are never silenced by this file.
# Everything listed here is silenced on THIS machine only.
'@
        [IO.File]::WriteAllText($wlFile, $wlSeed, [Text.UTF8Encoding]::new($false))
    }
    foreach ($rawLine in [IO.File]::ReadAllLines($wlFile)) {
        $l = $rawLine.Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $hm = [regex]::Match($l, '^(?:sha256[:=])?\s*([0-9a-fA-F]{64})$')
        if ($hm.Success) { [void]$script:userWhitelistHashes.Add($hm.Groups[1].Value) }
        else { $script:userWhitelist += $l }
    }
} catch { }

# Cheat / injector keywords: [HIGH] even when signed
$script:KeywordHint = 'injection|inject|cheat|aimbot|triggerbot|wallhack|esp[-_.]|bypass|manual[-_]?map|payload|crack|hack'

# Known-abused vulnerable drivers (BYOVD shortlist - extend as new ones appear)
$script:BYOVDDrivers = @(
    'winio.sys','winring0.sys','gdrv.sys','RTCore64.sys','dbutil_2_3.sys',
    'capcom.sys','asusio.sys','asUpIO.sys','kprocesshacker.sys','ntfsfltr.sys',
    'eneio.sys','winload.sys','procexp.sys','procexp104.sys','siwvid.sys',
    'zamguard64.sys','zam64.sys','hydraload.sys','dell_Sysdrv.sys','hpqkbfiltr.sys'
)

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
$script:pathExistsCache = @{}
$script:modCache = @{}     # PID -> module snapshot (shared by levels 1/2/3)
$script:fviCache = @{}     # path -> FileVersionInfo (version resource disk reads)
$script:diskHeadCache = @{}   # path -> first 512 bytes on disk
$script:seenFindings = [System.Collections.Generic.HashSet[string]]::new()
$script:pathQueue   = New-Object System.Collections.Generic.List[object]   # L4 deferred path checks
$script:riskCache  = @{}     # "path|sig" -> @(level, procDirSensitive) (Get-RiskLevel memo)

# ---------------- Core helpers ----------------
function Add-Finding {
    param([string]$Bucket, [string]$Line)
    if ($script:seenFindings.Add($Line)) { $script:findings[$Bucket].Add($Line) }
}

function Get-SigCached {
    param($path)
    if ($script:sigCache.ContainsKey($path)) { return $script:sigCache[$path] }
    # Fast engine first: paths pre-warmed by VerifySignatures (parallel
    # WinVerifyTrust + catalog lookup) come back instantly; anything else
    # falls back to the serial cmdlet (persistence refs are few).
    $fastStatus = $null
    try { if ('MeowAudit.Fast' -as [type]) { $fastStatus = [MeowAudit.Fast]::GetSigStatus($path) } } catch { }
    if ($null -ne $fastStatus) {
        $entry = [PSCustomObject]@{
            Status = $fastStatus
            Signer = [MeowAudit.Fast]::GetSigSigner($path)
        }
        $script:sigCache[$path] = $entry
        return $entry
    }
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

# Warm the parallel signature engine for a set of paths (no-op for paths
# already verified). One call verifies up to 8 files concurrently.
function Warm-Signatures {
    param([System.Collections.Generic.HashSet[string]]$Paths)
    if ($Paths.Count -eq 0) { return }
    if (-not ('MeowAudit.Fast' -as [type])) { return }
    try { [MeowAudit.Fast]::VerifySignatures([string[]]@($Paths)) } catch { }
}

# Test-Path is called thousands of times for the same few hundred files
# (one per loaded module); cache existence per unique path.
function Test-PathCached {
    param($path)
    if ($null -eq $path) { return $false }
    if ($script:pathExistsCache.ContainsKey($path)) { return $script:pathExistsCache[$path] }
    $ok = Test-Path -LiteralPath $path
    $script:pathExistsCache[$path] = $ok
    return $ok
}

# Module list shared by level 1/2/3. Source: EnumProcessModulesEx
# (LIST_MODULES_ALL) - .NET's Process.Modules only sees the 64-bit subset of
# WOW64 processes (measured: 7 of 177 modules for Spotify), which used to
# flood level 2/3 with false HIDDEN_MODULE / IAT_HOOK findings.
function Get-ProcModulesCached {
    param($proc)
    if ($script:modCache.ContainsKey($proc.Id)) { return $script:modCache[$proc.Id] }
    $snap = @()
    $h = [IntPtr]::Zero
    try {
        $access = [MeowAudit.Native]::PROCESS_QUERY_INFORMATION -bor [MeowAudit.Native]::PROCESS_VM_READ
        $h = [MeowAudit.Native]::OpenProcess($access, $false, $proc.Id)
    } catch { }
    if ($h -ne [IntPtr]::Zero) {
        try {
            foreach ($line in [MeowAudit.Native]::EnumModulesEx($h, [MeowAudit.Native]::LIST_MODULES_ALL)) {
                $p = $line -split '\|', 4
                if ($p.Count -ge 4 -and $p[3]) {
                    $snap += [PSCustomObject]@{ Base = [long]$p[0]; Size = [int]$p[1]; Name = $p[2]; Path = $p[3] }
                }
            }
        } catch { }
        [MeowAudit.Native]::CloseHandle($h) | Out-Null
    }
    if ($snap.Count -eq 0) {
        # fallback: .NET module list (fine for native x64 processes)
        try {
            foreach ($m in $proc.Modules) {
                $snap += [PSCustomObject]@{
                    Base = $m.BaseAddress.ToInt64(); Size = [int]$m.ModuleMemorySize
                    Name = $m.ModuleName; Path = $m.FileName
                }
            }
        } catch { $script:modCache[$proc.Id] = $false; return $false }   # access denied
    }
    if ($snap.Count -eq 0) { $script:modCache[$proc.Id] = $false; return $false }
    $script:modCache[$proc.Id] = $snap
    return $snap
}
function Reset-ModuleCache { $script:modCache = @{} }

# One Get-Process snapshot for a whole stage: calling Get-Process -Name once
# per process name re-enumerates all processes every time (194x on a busy box).
# Returns @{ name -> Process[] }.
function Select-TargetProcesses {
    param([string[]]$Names)
    $want = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Names) { if ($n) { [void]$want.Add($n) } }
    $map = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($want.Contains($p.ProcessName)) {
            if (-not $map.ContainsKey($p.ProcessName)) { $map[$p.ProcessName] = @() }
            $map[$p.ProcessName] += $p
        }
    }
    return $map
}

function Get-FileSha256 {
    param($path)
    if (-not (Test-Path -LiteralPath $path)) { return 'file not found' }
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    catch { return 'hash failed' }
}

# Extract the file path from a finding line ("... -> C:\path with space\file
# (signature: NotSigned)"). The old '\S+' split stopped at the first space and
# tried to hash "C:\Users\...\Desktop\JAILBREAK" instead of
# "C:\Users\...\Desktop\JAILBREAK MD\autoclicker3.dll".
function Get-FindingPath {
    param([string]$line)
    if ([string]::IsNullOrEmpty($line)) { return $null }
    if ($line -notmatch '->\s+(.+)$') { return $null }
    $p = $Matches[1].Trim()
    $p = $p -replace '\s+@ 0x[0-9A-Fa-f]+$', ''
    # one trailing annotation group (" (signature: ...)", " (module stomping ...)")
    # - non-greedy so paths that themselves contain "(...)" stay intact
    if ($p -match '^(.+?)(?: \([^()]*\))?$') { $p = $Matches[1] }
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    return $p
}

function Get-DiskHead {
    # First 512 bytes of a file on disk (cached) - for memory-vs-disk compare
    param($path)
    if ($script:diskHeadCache.ContainsKey($path)) { return $script:diskHeadCache[$path] }
    $head = $null
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $buf = New-Object byte[] 512
        $n = $fs.Read($buf, 0, 512); $fs.Close()
        if ($n -gt 0) { $head = $buf[0..($n-1)] }
    } catch { }
    $script:diskHeadCache[$path] = $head
    return $head
}

# Risk level of a file: 'HIGH' | 'MEDIUM' | ''
# Memoized on path+sig only. procDir is NOT part of the key: it only feeds
# rule 6b (unsigned file sitting next to its own process => MEDIUM), so the
# base verdict is computed once without it and the downgrade is re-applied on
# every hit. Keying on procDir exploded the key space across ~170 processes
# (3.3k misses x 1.4 ms per full scan) for one rule that never changes the
# keyword/missing/whitelist/Valid verdicts.
# Win32 can hand back extended-length paths (\\?\C:\...). They defeat every
# -like rule (procDir, trusted roots, whitelist), which reported Lunar
# Client's OWN .node modules as [PATH+SIG] HIGH. Normalize first, always.
function Get-CleanPath {
    param([string]$p)
    if ($p -and $p.StartsWith('\\?\')) {
        if ($p.StartsWith('\\?\UNC\')) { return ('\\' + $p.Substring(8)) }   # \\?\UNC\srv\sh -> \\srv\sh
        return $p.Substring(4)
    }
    return $p
}

# Hash whitelist probe (v8.2): only called when a verdict is about to be
# HIGH (rule 7a), so the cost is bounded by the number of suspects - valid
# signatures, trusted folders and whitelisted paths never hash anything.
# Cached per path; failure to hash is not a whitelist hit (fail closed).
function Test-HashWhitelisted {
    param([string]$path)
    if ((-not $script:whitelistHashes.Count) -and (-not $script:userWhitelistHashes.Count)) { return $false }
    if (-not $path) { return $false }
    $h = $null
    if ($script:hashCache.ContainsKey($path)) { $h = $script:hashCache[$path] }
    else {
        try {
            if (Test-PathCached -path $path) {
                $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            }
        } catch { $h = $null }
        $script:hashCache[$path] = $h
    }
    if (-not $h) { return $false }
    if ($script:whitelistHashes.Contains($h)) { return $true }
    if ($script:userWhitelistHashes.Count -gt 0 -and $script:userWhitelistHashes.Contains($h)) { return $true }
    return $false
}

function Get-RiskLevel {
    param($path, $sigStatus, $procDir)
    $path = Get-CleanPath $path
    if ($procDir) { $procDir = Get-CleanPath $procDir }
    $rkey = $path + [char]1 + $sigStatus
    $hit = $script:riskCache[$rkey]
    if ($null -eq $hit) {
        $base = Get-RiskLevelUncached -path $path -sigStatus $sigStatus -procDir $null
        # procDir matters only when the verdict reached the final fall-through
        # (rule 7). Probe once with procDir = first char of the path: rule 6b
        # always matches then (single literal char, no wildcard chars in the
        # pattern), while keyword/missing/minecraft HIGHs return before it =>
        # those must never be downgraded.
        $sens = $false
        if ($base -eq 'HIGH' -and $path -and $path.Length -ge 1) {
            $sens = (Get-RiskLevelUncached -path $path -sigStatus $sigStatus -procDir $path.Substring(0,1)) -eq 'MEDIUM'
        }
        $hit = @($base, $sens)
        $script:riskCache[$rkey] = $hit
    }
    if ($hit[1] -and $procDir -and $path -like "$procDir*") { return 'MEDIUM' }
    return $hit[0]
}

function Get-RiskLevelUncached {
    param($path, $sigStatus, $procDir)

    # 1) keywords: always suspicious, even when signed
    $leaf = Split-Path $path -Leaf
    if ($path -match $script:KeywordHint -or $leaf -match $script:KeywordHint) { return 'HIGH' }

    # 2) documented whitelist: always benign, whatever else is true. It must
    #    run BEFORE the missing-file rule: a temp helper (liblz4-java) can be
    #    wiped by a cleaner while its module is still loaded, and an approved
    #    name that is gone is not a finding.
    foreach ($p in $script:whitelistPatterns) { if ($path -like $p) { return '' } }

    # 2b) per-machine whitelist: operator-vouched files (MEOW_whitelist.txt)
    if ($script:userWhitelist) {
        foreach ($p in $script:userWhitelist) { if ($path -like $p) { return '' } }
    }

    # 3) file vanished from disk
    if (-not (Test-PathCached -path $path)) { return 'HIGH' }

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
    # 7a) hash whitelist (v8.2): reached only when the verdict would be HIGH;
    #     the file's own SHA256 must match a vouched hash. Keyword matches
    #     returned at rule 1, so hashes can never silence keyword hits.
    if (Test-HashWhitelisted -path $path) { return '' }
    return 'HIGH'
}

# ---------------- Remote memory helpers (PS wrappers) ----------------
function Get-ProcHandle {
    param($proc)
    $access = [MeowAudit.Native]::PROCESS_QUERY_INFORMATION -bor [MeowAudit.Native]::PROCESS_VM_READ
    return [MeowAudit.Native]::OpenProcess($access, $false, $proc.Id)
}

function Read-Remote {
    param([IntPtr]$h, [long]$addr, [int]$size)
    return [MeowAudit.Native]::ReadMem($h, $addr, $size)
}

# Validate a PE header at a remote address. Returns $null if not a plausible PE,
# else an object with Machine / SizeOfImage. This is what kills false positives
# on JIT regions that happen to contain 0x4D 0x5A.
function Test-RemotePe {
    param([IntPtr]$h, [long]$addr)
    $dos = Read-Remote $h $addr 0x40
    if (-not $dos -or $dos.Length -lt 0x40) { return $null }
    if ($dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) { return $null }               # 'MZ'
    $eLfanew = [BitConverter]::ToInt32($dos, 0x3C)
    if ($eLfanew -lt 0x40 -or $eLfanew -gt 0x1000) { return $null }
    $nt = Read-Remote $h ($addr + $eLfanew) 0x60
    if (-not $nt -or $nt.Length -lt 0x60) { return $null }
    if ([BitConverter]::ToUInt32($nt, 0) -ne 0x00004550) { return $null }     # 'PE\0\0'
    $machine = [BitConverter]::ToUInt16($nt, 4)
    if ($machine -notin 0x8664, 0x014C, 0xAA64, 0x01C4) { return $null }      # x64/x86/ARM64/ARM
    $sizeOfImage = [BitConverter]::ToInt32($nt, 56)                           # optional header +56
    if ($sizeOfImage -le 0 -or $sizeOfImage -gt 0x40000000) { return $null }  # sanity
    return [PSCustomObject]@{ Machine = $machine; SizeOfImage = $sizeOfImage }
}

# Module ranges (base, size) from the shared module snapshot
function Get-ModuleRanges {
    param($modules)
    $ranges = New-Object System.Collections.Generic.List[object]
    foreach ($m in $modules) {
        $ranges.Add([PSCustomObject]@{ Base = [long]$m.Base; Size = [long]$m.Size })
    }
    return $ranges
}

function Test-InRanges {
    param($ranges, [long]$addr)
    foreach ($r in $ranges) {
        if ($addr -ge $r.Base -and $addr -lt ($r.Base + $r.Size)) { return $true }
    }
    return $false
}

# ---------------- .NET registry helpers (level 4 speed) ----------------
# Get-ItemProperty costs 10-30 ms per key: the Services + COM enumeration
# alone took ~27 s in early v8 runs. One OpenSubKey + GetValue in .NET is
# ~0.1 ms with the same results.
function Open-RegKey {
    param([string]$Path)
    $hive = if ($Path -like 'HKLM:*' -or $Path -like 'HKEY_LOCAL_MACHINE:*') { [Microsoft.Win32.Registry]::LocalMachine }
            elseif ($Path -like 'HKCU:*' -or $Path -like 'HKEY_CURRENT_USER:*') { [Microsoft.Win32.Registry]::CurrentUser }
            else { $null }
    if (-not $hive) { return $null }
    $sub = $Path -replace '^[^:]+:\\', ''
    try { return $hive.OpenSubKey($sub) } catch { return $null }
}

# Depth-first walk of a .NET RegistryKey tree: emits @{ Name; Key } objects.
function Get-RegSubTree {
    param($Key, [int]$Depth = 0)
    if ($Depth -gt 7 -or -not $Key) { return }
    foreach ($n in $Key.GetSubKeyNames()) {
        $sk = $null
        try { $sk = $Key.OpenSubKey($n) } catch { }
        if (-not $sk) { continue }
        [PSCustomObject]@{ Name = $n; Key = $sk }
        Get-RegSubTree -Key $sk -Depth ($Depth + 1)
    }
}

# ---------------- LEVEL 1: DLL audit ----------------
function Invoke-ModuleAudit {
    param([string[]]$ProcessNames, [string]$Label = 'custom')
    $nProc = 0; $nMod = 0; $nHigh = 0
    $names = @($ProcessNames | Select-Object -Unique)
    $total = $names.Count; $idx = 0

    # --- Phase A: one process snapshot, collect every unique module path,
    # then verify all signatures in parallel (8 threads). Serial
    # Get-AuthenticodeSignature measured ~38 s for ~900 files; the parallel
    # engine does it in ~1-2 s. ---
    $byName = Select-TargetProcesses -Names $names
    $pathSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) {
        if (-not $byName.ContainsKey($name)) { continue }
        foreach ($proc in $byName[$name]) {
            try { if ($proc.Path) { [void]$pathSet.Add($proc.Path) } } catch { }
            $mods = Get-ProcModulesCached $proc
            if ($mods -and $mods -ne $false) {
                foreach ($m in $mods) { if ($m.Path) { [void]$pathSet.Add((Get-CleanPath $m.Path)) } }
            }
        }
    }
    if ($pathSet.Count -gt 0) {
        Write-Host "$dim  [signatures] verifying $($pathSet.Count) files in parallel...$reset"
        Warm-Signatures -Paths $pathSet
    }

    foreach ($name in $names) {
        $idx++
        if (-not $byName.ContainsKey($name)) { continue }
        $procs = $byName[$name]
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
                    Add-Finding HIGH "[EXE] $($proc.ProcessName) (PID $($proc.Id)) - suspicious main executable -> $procPath (signature: $($pSig.Status))"
                }
            }

            $modules = Get-ProcModulesCached $proc
            if ($modules -eq $false) {
                $script:denied.Add("$($proc.ProcessName) (PID $($proc.Id))"); continue
            }
            if (-not $modules) { continue }

            $nMod += $modules.Count; $nameMod += $modules.Count
            $procHigh = 0

            foreach ($m in $modules) {
                $path = Get-CleanPath $m.Path
                # inline cache lookup: Phase A pre-warms every module path, so
                # the PS function call itself (measured ~260 ms/6.9k calls)
                # would dominate; only rare misses go through Get-SigCached
                $sigInfo = if ($path) { $script:sigCache[$path] } else { $null }
                if ($null -eq $sigInfo) { $sigInfo = Get-SigCached -path $path }
                $level = Get-RiskLevel -path $path -sigStatus $sigInfo.Status -procDir $procDir

                # version resource = extra disk read per module; cache per path
                $fvi = $script:fviCache[$path]
                if ($null -eq $fvi) {
                    $fvi = try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path) } catch { $null }
                    $script:fviCache[$path] = $fvi
                }

                $script:allRows.Add([PSCustomObject]@{
                    Process    = $proc.ProcessName; PID = $proc.Id
                    DLL        = $m.Name; FullPath = $path
                    SizeKB     = [math]::Round($m.Size / 1KB)
                    Company    = if ($fvi) { $fvi.CompanyName } else { $null }
                    FileVersion= if ($fvi) { $fvi.FileVersion } else { $null }
                    Signature  = $sigInfo.Status; Signer = $sigInfo.Signer
                    Level      = $level; Scope = $Label
                })

                if ($level -eq 'HIGH') {
                    $procHigh++; $nHigh++
                    $reason = if ($path -match $script:KeywordHint -or $m.Name -match $script:KeywordHint) { 'KEYWORD' }
                              elseif (-not (Test-PathCached -path $path)) { 'FILE_MISSING' }
                              else { 'PATH+SIG' }
                    Add-Finding HIGH "[$reason] $($proc.ProcessName) (PID $($proc.Id)) - $($m.Name) -> $path (signature: $($sigInfo.Status))"
                }
                elseif ($level -eq 'MEDIUM') {
                    Add-Finding MEDIUM "$($proc.ProcessName) (PID $($proc.Id)) - $($m.Name) -> $path (signature: $($sigInfo.Status))"
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
    # Close-the-injector-proof: PE files lying on disk in the user drop
    # locations but loaded nowhere. Paths already audited as live modules are
    # skipped (no duplicate lines while the injector is still running), so the
    # findings below only cover what a process snapshot cannot see.
    Invoke-DwellScan -LoadedPaths $pathSet
    return "$nProc $procWord / $nMod DLLs / $nHigh [HIGH]"
}

# ---------------- Dwell scan: files that outlive the injector ----------------
# Level 1 only scores modules loaded in LIVE processes: close the injector and
# every HIGH finding vanishes - even though injector.exe and the payload DLL
# are still sitting on disk. This pass walks Downloads + Desktop, skips every
# path already audited above (loaded somewhere = already scored) and runs the
# remaining loose PE files through the very same Get-RiskLevel rules, so the
# verdict survives closing the process. Temp is deliberately excluded: 20k+
# extracted installer files there would be pure noise and slow the scan down.
function Invoke-DwellScan {
    param($LoadedPaths)
    $roots = @("$env:USERPROFILE\Downloads", [Environment]::GetFolderPath('Desktop'))
    $cand = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in $roots) {
        if ([string]::IsNullOrEmpty($root) -or -not (Test-Path -LiteralPath $root)) { continue }
        # manual stack walk: skips reparse points (junction loops) and an ACL'd
        # subdirectory only loses itself instead of aborting the whole root
        $stack = [System.Collections.Generic.Stack[string]]::new()
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                    if ($f -notmatch '\.(exe|dll|sys|ocx)$') { continue }
                    if ($LoadedPaths -and $LoadedPaths.Contains($f)) { continue }
                    [void]$cand.Add($f)
                }
                foreach ($sd in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    $attr = [System.IO.File]::GetAttributes($sd)
                    if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($sd) }
                }
            } catch { } # ACL on this directory: skip it, keep walking
        }
    }
    if ($cand.Count -eq 0) { return }
    Write-Host "$dim  [dwell] $($cand.Count) loose PE file(s) on disk (not loaded anywhere) - checking...$reset"
    # keyword verdicts need no signature check (checked first in Get-RiskLevel);
    # warm the rest through the parallel engine like Phase A does
    $needSig = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $cand) { if ($f -notmatch $script:KeywordHint) { [void]$needSig.Add($f) } }
    if ($needSig.Count -gt 0) { Warm-Signatures -Paths $needSig }
    $nHigh = 0; $nMed = 0
    foreach ($f in $cand) {
        $si = Get-SigCached -path $f
        $st = if ($si -and $si.Status) { $si.Status } else { 'Unknown' }
        $lvl = Get-RiskLevel -path $f -sigStatus $st -procDir $null
        if ($lvl -eq 'HIGH') {
            $nHigh++
            $kind = if ($f -match $script:KeywordHint) { 'KEYWORD' } else { 'PATH+SIG' }
            Add-Finding HIGH "[$kind] $(Split-Path $f -Leaf) - on disk, not loaded in any scanned process -> $f (signature: $st)"
        }
        elseif ($lvl -eq 'MEDIUM') {
            $nMed++
            Add-Finding MEDIUM "[PATH+SIG] $(Split-Path $f -Leaf) - on disk, not loaded in any scanned process -> $f (signature: $st)"
        }
    }
    $script:runs += "dwell : $($cand.Count) loose PE files (Downloads + Desktop), $nHigh [HIGH] / $nMed [MEDIUM]"
}

# ---------------- Legit section-map verification ----------------
# Vendor services (NetLimiter NLSvc, Acer NitroSense PSSvc, ...) memory-map
# their own signed DLL/driver with SEC_IMAGE just to read it: a full PE header
# validates at the allocation base but the file never enters the loader list -
# which looks exactly like a manual map. Before raising [HIDDEN_MODULE]: find a
# disk file with the same PE identity (machine/timestamp/size-of-image), require
# a VALID Authenticode signature and byte-compare the mapped image against that
# file's image layout (MeowAudit.Fast::RegionMatchesFile). All three match =>
# the memory holds the literal signed vendor bytes, nothing to report. An
# unsigned payload (typical cheat DLL), a deleted backing file or a patched /
# repacked image fails one of the checks and the [HIGH] fires exactly as
# before - real manual-map injection detection is unchanged.
function Confirm-LegitImageMap {
    param([IntPtr]$Handle, [long]$Base, [string]$ProcDir)
    try {
        $hdr = Read-Remote $Handle $Base 0x400
        if (-not $hdr -or $hdr.Length -lt 0x100 -or $hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { return $false }
        $lf = [BitConverter]::ToInt32($hdr, 0x3C)
        if ($lf -lt 0x40 -or $lf + 24 -gt $hdr.Length) { return $false }
        if ($hdr[$lf] -ne 0x50 -or $hdr[$lf + 1] -ne 0x45) { return $false }
        $machine = [BitConverter]::ToUInt16($hdr, $lf + 4)
        $stamp   = [BitConverter]::ToUInt32($hdr, $lf + 8)
        $soi     = [BitConverter]::ToUInt32($hdr, $lf + 24 + 56)
        if ($soi -lt 0x1000 -or $soi -gt 0x20000000) { return $false }

        # candidate trees: the process's own install folder first, then the
        # system trees where service helpers and drivers live
        $cands = @()
        if ($ProcDir -and (Test-Path -LiteralPath $ProcDir)) {
            $cands += Get-ChildItem -LiteralPath $ProcDir -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^(?i:\.dll|\.sys|\.ocx|\.cpl|\.exe)$' }
        }
        foreach ($sd in @("$env:SystemRoot\System32", "$env:SystemRoot\System32\drivers", "$env:SystemRoot\SysWOW64")) {
            if (-not (Test-Path -LiteralPath $sd)) { continue }
            $cands += Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^(?i:\.dll|\.sys|\.ocx|\.cpl|\.exe)$' }
        }
        foreach ($cand in $cands) {
            $fs = $null
            try {
                $fs = [System.IO.File]::Open($cand.FullName, 'Open', 'Read', 'ReadWrite')
                $head = New-Object byte[] 0x400
                $n = $fs.Read($head, 0, 0x400)
                if ($n -lt 0x40 -or $head[0] -ne 0x4D -or $head[1] -ne 0x5A) { continue }
                $lf2 = [BitConverter]::ToInt32($head, 0x3C)
                if ($lf2 -lt 0x40 -or $lf2 + 24 -gt $n) { continue }
                # PE identity: machine + TimeDateStamp + SizeOfImage
                if ([BitConverter]::ToUInt16($head, $lf2 + 4) -ne $machine) { continue }
                if ([BitConverter]::ToUInt32($head, $lf2 + 8) -ne $stamp) { continue }
                if ([BitConverter]::ToUInt32($head, $lf2 + 24 + 56) -ne $soi) { continue }
                # same image: signature must be Valid, then bytes must be equal
                $si = Get-SigCached -path $cand.FullName
                if ($si -and $si.Status -eq 'Valid' -and [MeowAudit.Fast]::RegionMatchesFile($Handle, $Base, $cand.FullName)) {
                    return $true
                }
            } catch { }
            finally { if ($fs) { $fs.Dispose() } }
        }
        return $false
    } catch { return $false }
}

# ---------------- LEVEL 2: deep memory scan ----------------
# v8: a hidden module is only reported when a FULL PE header validates at the
# allocation base (kills JIT false positives), and it also covers MEM_IMAGE
# regions whose allocation base is not a known module (section-object mapping).
function Invoke-DeepScan {
    param([string[]]$ProcessNames, [string]$Label = 'deep')
    if (-not ('MeowAudit.Native' -as [type])) {
        Write-Host "$red  [!] Native API not loaded: deep scan unavailable$reset"
        return
    }

    $nProc = 0; $nHigh = 0
    $names = @($ProcessNames | Select-Object -Unique)
    $total = $names.Count; $idx = 0
    $byName = Select-TargetProcesses -Names $names

    foreach ($name in $names) {
        $idx++
        if (-not $byName.ContainsKey($name)) { continue }
        $procs = $byName[$name]
        foreach ($proc in $procs) {
            $h = Get-ProcHandle $proc
            if ($h -eq [IntPtr]::Zero) {
                $script:denied.Add("$($proc.ProcessName) (PID $($proc.Id)) [deep]")
                continue
            }
            $nProc++
            Write-Host "$dim  [deep $idx/$total] $($proc.ProcessName) (PID $($proc.Id))...$reset" -NoNewline

            # known module bases (API list + PEB loader list: catches modules
            # hidden from EnumProcessModulesEx even before their bytes are
            # inspected)
            $knownList = New-Object System.Collections.Generic.List[long]
            $wow64 = $false
            [MeowAudit.Native]::IsWow64Process($h, [ref]$wow64) | Out-Null
            $cachedMods = Get-ProcModulesCached $proc
            if ($cachedMods -and $cachedMods -ne $false) {
                foreach ($m in $cachedMods) { [void]$knownList.Add($m.Base) }
            }
            foreach ($pebEntry in [MeowAudit.Native]::WalkPebLoaderList($h, $wow64)) {
                $parts = $pebEntry -split '\|', 3
                if ($parts.Count -ge 1 -and $parts[0]) { [void]$knownList.Add([long]$parts[0]) }
            }

            # v8.1 loader-init race: a process younger than LdrInitializeThunk
            # has ntdll + exe mapped by the kernel but not registered in any
            # loader list, so RegionScan reports the bootstrap itself as
            # "not in loader list" (reproduced: 4 transient cmd.exe shells
            # flagged ntdll twice each - 1484 KB + 4 KB exec regions).
            # Transient shells finish init within a few ms: probe once, wait
            # 250 ms, probe again. Still mid-init => hidden-module findings
            # are deferred for this process (stats still collected); a real
            # manual map in any stable process is reported exactly as before.
            $ldrState = [MeowAudit.Native]::GetLdrInitialized($h, $wow64)
            if ($ldrState -eq 0) {
                Start-Sleep -Milliseconds 250
                $ldrState = [MeowAudit.Native]::GetLdrInitialized($h, $wow64)
            }

            # One C# walk over every region (the old PS loop did thousands of
            # [MeowAudit.Native] calls + per-region byte reads from PowerShell).
            $res = [MeowAudit.Fast]::RegionScan($h, $knownList.ToArray())
            $mzFound = 0; $execRegions = 0; $execKB = 0; $wxRegions = 0; $wxKB = 0; $secMapped = 0; $legitMaps = 0
            foreach ($line in $res) {
                if ($line.StartsWith('STAT|')) {
                    $s = $line.Substring(5) -split '\|'
                    if ($s.Count -ge 5) {
                        $execRegions = [int]$s[0]; $execKB = [int]$s[1]
                        $wxRegions   = [int]$s[2]; $wxKB   = [int]$s[3]
                        $secMapped   = [int]$s[4]
                    }
                } elseif ($line.StartsWith('PE|')) {
                    if ($ldrState -eq 0) { continue }   # v8.1: loader mid-init = bootstrap, not injection
                    $p = $line -split '\|', 4
                    if ($p.Count -ge 4) {
                        $allocBase = [Convert]::ToInt64($p[1], 16)
                        # vendor SEC_IMAGE data-map of a signed file => not an
                        # injection; only report what fails that proof
                        $procDir = $null
                        try { $pp = $proc.Path; if ($pp) { $procDir = Split-Path $pp -Parent } } catch { }
                        if (Confirm-LegitImageMap -Handle $h -Base $allocBase -ProcDir $procDir) {
                            $legitMaps++
                            continue
                        }
                        $mzFound++; $nHigh++
                        Add-Finding HIGH "[HIDDEN_MODULE] $($proc.ProcessName) (PID $($proc.Id)) - valid PE @ $([IntPtr]$allocBase), $($p[2]) KB, $($p[3]), not in loader list (manual map / reflective / section mapping)"
                    }
                }
            }

            [MeowAudit.Native]::CloseHandle($h) | Out-Null

            $initNote = if ($ldrState -eq 0) { ', loader mid-init (bootstrap images skipped)' } else { '' }
            $script:findings.INFO.Add("[MEMORY] $($proc.ProcessName) (PID $($proc.Id)) - exec: $execRegions regions/$execKB KB, WX: $wxRegions/$wxKB KB$(if($secMapped){', orphan MEM_IMAGE: '+$secMapped}else{''})$initNote")

            $lmNote = if ($legitMaps -gt 0) { ", $legitMaps vendor map(s) verified" } else { '' }
            if ($mzFound -gt 0) {
                Write-Host "$red  <- $mzFound hidden module(s) found!$lmNote$reset"
            } else {
                $wxNote = if ($wxRegions -gt 0) { ", WX $wxRegions/$wxKB KB" } else { '' }
                Write-Host "$dim  exec $execRegions/$execKB KB$wxNote$lmNote - no hidden module$reset"
            }
        }
    }
    # live injector hunt: system-wide handle triad scan (who is holding
    # injection rights on a process right now)
    Invoke-InjectorAudit

    $procWord = if ($nProc -eq 1) { 'process' } else { 'processes' }
    if ($nProc -gt 0) { $script:runs += "deep/$Label : $nProc $procWord, $nHigh [HIGH]" }
    return "$nProc $procWord / $nHigh [HIGH]"
}

# ---------------- Live injector detection (handle triad) -------------------
# Finds the PROCESS that performs injection right now, not only the traces it
# leaves in the victim. An injector must hold an open handle with
# PROCESS_CREATE_THREAD (0x02) + PROCESS_VM_OPERATION (0x08) +
# PROCESS_VM_WRITE (0x20) on its target - the CreateRemoteThread /
# WriteProcessMemory triad. The C# pass enumerates the whole system handle
# table (NtQuerySystemInformation class 64) and VERIFIES every candidate by
# duplicating the handle and calling GetProcessId, so file/key/section
# handles that merely share those access bits are dropped before reporting.
#
# False-positive filters (measured on a real desktop: browsers/terminals keep
# PROCESS_ALL_ACCESS handles on the children they spawn - 238 raw hits):
#   * known inspection/debug/AV/system tools        -> skipped
#   * handle restricted to the triad (+sync/query)  -> always reported
#     (a narrow triad is a deliberate injection mask, never a spawn handle)
#   * broad ALL_ACCESS handle                       -> only reported when the
#     target is neither the owner's child, nor the owner's parent, nor the
#     same app/vendor on disk
$script:InjectorToolAllow = @(
    'procexp','procexp64','procmon','procmon64',            # Sysinternals
    'processhacker','processhacker64','systeminformer',     # handle viewers
    'msmpeng','nisrv','securityhealthservice','sense',      # antivirus
    'csrss','wininit','winlogon','smss','services','lsass','conhost','openconsole',  # system/console
    'devenv','vsdbg','x64dbg','x32dbg','windbg','windbgx','ollydbg',   # debuggers
    'ida','ida64','dnspy','perfmon64'
)
function Invoke-InjectorAudit {
    if (-not ('MeowAudit.Native' -as [type])) { return }
    $res = [MeowAudit.Native]::FindInjectionHandles()
    if (-not $res -or $res.Count -eq 0) { return }
    $nHigh = 0; $nMed = 0; $nSkip = 0
    $procCache = @{}; $pathCache = @{}; $parentCache = @{}
    # bits a NON-injection handle may legally carry besides the triad
    $extraAllowed = 0x100000 -bor 0x1000 -bor 0x400   # SYNCHRONIZE | QUERY_LIMITED | QUERY_INFORMATION
    foreach ($l in $res) {
        $p = $l -split '\|', 3
        if ($p.Count -lt 3) { continue }
        $ownerPid = [int]$p[0]; $targetPid = [int]$p[1]
        $acc = [Convert]::ToInt32($p[2], 16)
        # narrow triad = exactly the injection rights (+sync/query bits):
        # this mask is only ever obtained by an explicit OpenProcess call,
        # never by CreateProcess or a spawn/inherit path
        $isNarrow = (($acc -band (-bnot ([MeowAudit.Native]::INJECT_TRIAD -bor $extraAllowed))) -eq 0)

        $owner = $null
        if ($procCache.ContainsKey($ownerPid)) { $owner = $procCache[$ownerPid] }
        else {
            try { $owner = Get-Process -Id $ownerPid -ErrorAction Stop } catch { $owner = $null }
            $procCache[$ownerPid] = $owner
        }
        $targetName = "PID $targetPid"; $targetPath = $null
        try {
            $tp = Get-Process -Id $targetPid -ErrorAction Stop
            $targetName = "$($tp.ProcessName) (PID $targetPid)"
            try { $targetPath = $tp.Path } catch { }
        } catch { }
        if (-not $owner) {
            Add-Finding MEDIUM "[INJECTOR] unknown process (PID $ownerPid) holds an injection-capable handle on $targetName"
            $nMed++; continue
        }
        $oName = $owner.ProcessName
        if ($script:InjectorToolAllow -contains $oName.ToLower()) { $nSkip++; continue }
        $oPath = $null
        try { $oPath = $owner.Path } catch { }
        $oSig = ''
        if ($oPath) { try { $oSig = (Get-SigCached -path $oPath).Status } catch { } }

        # ---- broad-handle noise filters (spawn / same-app / same-vendor) ----
        if (-not $isNarrow) {
            # spawn chain: walk the target's parent chain a few levels up - a
            # WebView/Electron launcher holds ALL_ACCESS on grandchildren too
            # (launcher -> browser main -> renderer), and that is still spawn
            if (-not $parentCache.ContainsKey($ownerPid)) { $parentCache[$ownerPid] = [MeowAudit.Native]::GetParentPid($ownerPid) }
            if (-not $parentCache.ContainsKey($targetPid)) { $parentCache[$targetPid] = [MeowAudit.Native]::GetParentPid($targetPid) }
            $chainHit = $false
            $cur = $targetPid
            for ($step = 0; $step -lt 4; $step++) {
                if ($cur -eq $ownerPid) { $chainHit = $true; break }
                if (-not $parentCache.ContainsKey($cur)) { $parentCache[$cur] = [MeowAudit.Native]::GetParentPid([int]$cur) }
                $cur = $parentCache[$cur]
                if ($cur -le 0) { break }
            }
            if (-not $chainHit) {
                # also walk the owner's own chain (owner may be a helper child
                # of the app that legitimately owns the target)
                $cur = $ownerPid
                for ($step = 0; $step -lt 4 -and -not $chainHit; $step++) {
                    if ($cur -eq $targetPid) { $chainHit = $true; break }
                    if (-not $parentCache.ContainsKey($cur)) { $parentCache[$cur] = [MeowAudit.Native]::GetParentPid([int]$cur) }
                    $cur = $parentCache[$cur]
                    if ($cur -le 0) { break }
                }
            }
            if ($chainHit) { $nSkip++; continue }
            # signed owner + unresolvable target = nothing to prove, not noise
            if ($oSig -eq 'Valid' -and -not $targetPath) { $nSkip++; continue }
            # same directory or same vendor folder on disk = app-internal IPC
            $oDir = if ($oPath) { Split-Path $oPath -Parent } else { $null }
            $tDir = if ($targetPath) { Split-Path $targetPath -Parent } else { $null }
            if ($oDir -and $tDir -and ($oDir -ieq $tDir)) { $nSkip++; continue }
            $oVendor = if ($oPath -and $oPath -match '^(?i)([a-z]:\\program files(?: \(x86\))?\\[^\\]+)') { $Matches[1] } else { $oDir }
            $tVendor = if ($targetPath -and $targetPath -match '^(?i)([a-z]:\\program files(?: \(x86\))?\\[^\\]+)') { $Matches[1] } else { $tDir }
            if ($oVendor -and $tVendor -and ($oVendor -ieq $tVendor)) { $nSkip++; continue }
        }

        # unsigned/unverifiable owner = live injector; signed = review
        $sev = 'MEDIUM'
        if (-not $oPath -or $oSig -ne 'Valid') { $sev = 'HIGH'; $nHigh++ } else { $nMed++ }
        $maskNote = if ($isNarrow) { 'narrow triad mask' } else { 'full-access handle' }
        $tail = if ($oPath) { " -> $oPath (signature: $(if($oSig){$oSig}else{'unknown'}))" } else { '' }
        Add-Finding $sev "[INJECTOR] $oName (PID $ownerPid) holds an open handle with rights 0x$($acc.ToString('X')) ($maskNote) on $targetName - live injection capability$tail"
    }
    if ($nHigh + $nMed -gt 0) {
        $skipNote = if ($nSkip -gt 0) { ", $nSkip spawn/same-app/tool handle(s) filtered out" } else { '' }
        Write-Host "$red  [injector] $nHigh live injector(s) and $nMed review-worthy holder(s) of injection handles$skipNote$reset"
        $script:runs += "injector : $nHigh [HIGH] / $nMed [MEDIUM]$skipNote"
    } elseif ($nSkip -gt 0) {
        Write-Host "$dim  [injector] injection-capable handles only on spawn/same-app/known-tool pairs ($nSkip filtered) - no unknown injector$reset"
    }
}

# ---------------- LEVEL 3: integrity scan ----------------
# Catches what a plain module list + memory sweep cannot:
#   HIDDEN_DLL    module in PEB loader list but not in EnumProcessModules (or vice versa)
#   STOMPED       module memory bytes differ from the file on disk
#   RUNPE         main image in memory differs from the EXE on disk
#   IAT_HOOK      import slot points outside every known module
#   NTDLL_HOOK    ntdll .text in memory differs from the on-disk copy
#   THREAD_EXEC   thread start address inside private/unbacked memory (shellcode)
#   DEBUG_PORT    process is being debugged (classic pre-injection step)
function Invoke-IntegrityScan {
    param([string[]]$ProcessNames, [string]$Label = 'integrity')
    if (-not ('MeowAudit.Native' -as [type])) {
        Write-Host "$red  [!] Native API not loaded: integrity scan unavailable$reset"
        return
    }
    $nProc = 0; $nHigh = 0
    $names = @($ProcessNames | Select-Object -Unique)
    $total = $names.Count; $idx = 0
    $byName = Select-TargetProcesses -Names $names

    foreach ($name in $names) {
        $idx++
        if (-not $byName.ContainsKey($name)) { continue }
        $procs = $byName[$name]
        foreach ($proc in $procs) {
            $h = Get-ProcHandle $proc
            if ($h -eq [IntPtr]::Zero) { continue }
            $nProc++
            Write-Host "$dim  [integrity $idx/$total] $($proc.ProcessName) (PID $($proc.Id))...$reset" -NoNewline
            $procHigh = 0

            $wow64 = $false
            [MeowAudit.Native]::IsWow64Process($h, [ref]$wow64) | Out-Null

            # ---- module set: FRESH EnumProcessModulesEx (not the L1 cache -
            # modules loaded after the L1 snapshot, e.g. by the CLR while we
            # scan, would appear as false HIDDEN_DLL vs the fresh PEB walk) ----
            $enumMap = @{}   # base -> on-disk path
            $rangeList = New-Object System.Collections.Generic.List[object]
            $freshMods = @()
            foreach ($mLine in [MeowAudit.Native]::EnumModulesEx($h, [MeowAudit.Native]::LIST_MODULES_ALL)) {
                $mp = $mLine -split '\|', 4
                if ($mp.Count -ge 4 -and $mp[3]) {
                    $freshMods += [PSCustomObject]@{ Base = [long]$mp[0]; Size = [int]$mp[1]; Name = $mp[2]; Path = $mp[3] }
                }
            }
            if ($freshMods.Count -eq 0) {
                # fallback: shared snapshot (fine for x64 processes)
                $cachedMods = Get-ProcModulesCached $proc
                if ($cachedMods -and $cachedMods -ne $false) { $freshMods = @($cachedMods) }
            }
            foreach ($m in $freshMods) {
                $mpath = $m.Path
                # WOW64: a 32-bit module (base < 4 GB) recorded as System32 was
                # really loaded from SysWOW64 (file system redirection); the
                # loader path and the on-disk bytes disagree, so comparing
                # memory against the 64-bit System32 copy flags EVERY module
                # as STOMPED (1166 false positives on 3 processes measured).
                if ($wow64 -and $m.Base -lt 0x100000000) {
                    $mm = [regex]::Match($mpath, '(?i)^([A-Z]:\\WINDOWS\\System32\\)(.+)$')
                    if ($mm.Success) {
                        $alt = "$env:SystemRoot\SysWOW64\" + $mm.Groups[2].Value
                        if (Test-PathCached -path $alt) { $mpath = $alt }
                    }
                }
                $enumMap[$m.Base] = $mpath
                $rangeList.Add([PSCustomObject]@{ Base = $m.Base; Size = [long]$m.Size; Path = $mpath })
            }

            # ---- module set from PEB loader list ----
            $pebMap = @{}    # base -> full path
            foreach ($pebEntry in [MeowAudit.Native]::WalkPebLoaderList($h, $wow64)) {
                $parts = $pebEntry -split '\|', 3
                if ($parts.Count -ge 3 -and $parts[0]) {
                    $pebMap[[long]$parts[0]] = $parts[2]
                    $rangeList.Add([PSCustomObject]@{ Base = [long]$parts[0]; Size = [long]$parts[1]; Path = $parts[2] })
                }
            }

            # ---- HIDDEN_DLL: the two views disagree ----
            # WOW64: the PEB walk sees only the 32-bit loader list, while the
            # ALL view also contains the 64-bit helper set (ntdll64, wow64.dll
            # ...) - comparing those against PEB32 would fabricate 6 false
            # HIDDEN_DLL per process. Diff against the 32-bit-only view there.
            $diffMap = $enumMap
            if ($wow64) {
                $diffMap = @{}
                foreach ($line in [MeowAudit.Native]::EnumModulesEx($h, [MeowAudit.Native]::LIST_MODULES_32BIT)) {
                    $p32 = $line -split '\|', 4
                    if ($p32.Count -ge 4 -and $p32[3]) { $diffMap[[long]$p32[0]] = $p32[3] }
                }
            }
            foreach ($b in $diffMap.Keys) {
                if (-not $pebMap.ContainsKey($b) -and $pebMap.Count -gt 0) {
                    $procHigh++; $nHigh++
                    Add-Finding HIGH "[HIDDEN_DLL] $($proc.ProcessName) (PID $($proc.Id)) - module in EnumProcessModules but NOT in PEB loader list -> $($diffMap[$b]) @ 0x$('{0:X}' -f $b) (hooked module enumeration)"
                }
            }
            foreach ($b in $pebMap.Keys) {
                if (-not $enumMap.ContainsKey($b) -and $enumMap.Count -gt 0 -and $pebMap[$b]) {
                    $procHigh++; $nHigh++
                    Add-Finding HIGH "[HIDDEN_DLL] $($proc.ProcessName) (PID $($proc.Id)) - module in PEB loader list but NOT in EnumProcessModules -> $($pebMap[$b]) @ 0x$('{0:X}' -f $b)"
                }
            }

            # ---- STOMPED / RUNPE: memory bytes vs disk bytes (C# compare) ----
            foreach ($kv in $enumMap.GetEnumerator()) {
                $path = $kv.Value
                if (-not $path -or -not (Test-PathCached -path $path)) { continue }
                # MemHeadDiff reads memory + disk head, excludes the relocated
                # ImageBase field, and returns null when the bytes match.
                $diff = [MeowAudit.Fast]::MemHeadDiff($h, $kv.Key, $path)
                if ($diff) {
                    $isMain = ($proc.Path -and $path -eq $proc.Path)
                    $procHigh++; $nHigh++
                    if ($isMain) {
                        Add-Finding HIGH "[RUNPE] $($proc.ProcessName) (PID $($proc.Id)) - main image in memory differs from EXE on disk -> $path (process hollowing / RunPE / herpaderping)"
                    } else {
                        Add-Finding HIGH "[STOMPED] $($proc.ProcessName) (PID $($proc.Id)) - $($path | Split-Path -Leaf) memory differs from disk -> $path (module stomping / in-memory patching)"
                    }
                }
            }

            # ---- IAT_HOOK: import slots pointing outside every module ----
            # ranges as parallel arrays for the C# walker (bulk thunk reads)
            $rB = [long[]]::new($rangeList.Count)
            $rS = [int[]]::new($rangeList.Count)
            for ($ri = 0; $ri -lt $rangeList.Count; $ri++) { $rB[$ri] = $rangeList[$ri].Base; $rS[$ri] = [int]$rangeList[$ri].Size }
            foreach ($kv in $enumMap.GetEnumerator()) {
                $hits = [MeowAudit.Fast]::IatFindHooks($h, $kv.Key, $rB, $rS)
                foreach ($val in $hits) {
                    $procHigh++; $nHigh++
                    $leaf = Split-Path $kv.Value -Leaf
                    Add-Finding HIGH "[IAT_HOOK] $($proc.ProcessName) (PID $($proc.Id)) - $leaf import slot points outside every module -> 0x$('{0:X}' -f $val) (IAT/EAT patching)"
                    break   # one report per module is enough
                }
            }

            # ---- NTDLL_HOOK: compare ntdll .text memory vs disk (C# SHA256) ----
            # WOW64 processes map TWO ntdll copies: the 64-bit one up high
            # (helper, NOT in the PEB32 list) and the real 32-bit one below
            # 4 GB. Pick the one in the process's own address space, else the
            # comparison cross-matches 32-vs-64-bit bytes (false NTDLL_HOOK).
            $ntdllPath = "$env:SystemRoot\System32\ntdll.dll"
            if ($wow64) { $ntdllPath = "$env:SystemRoot\SysWOW64\ntdll.dll" }
            if (Test-PathCached -path $ntdllPath) {
                $ntBase = 0
                foreach ($kv in $enumMap.GetEnumerator()) {
                    if ((Split-Path $kv.Value -Leaf) -ieq 'ntdll.dll') {
                        if ($wow64 -and $kv.Key -ge 0x100000000) { continue }   # skip 64-bit helper copy
                        $ntBase = $kv.Key; break
                    }
                }
                if ($ntBase -gt 0) {
                    if ([MeowAudit.Fast]::NtdllTampered($h, $ntBase, $ntdllPath)) {
                        $procHigh++; $nHigh++
                        Add-Finding HIGH "[NTDLL_HOOK] $($proc.ProcessName) (PID $($proc.Id)) - ntdll .text in memory differs from disk (inline hooks / unhooking / SysWhispers) -> $ntdllPath"
                    }
                }
            }

            # ---- THREAD_EXEC: thread starts in unbacked memory (shellcode) ----
            try {
                $tids = [int[]]::new($proc.Threads.Count)
                for ($ti = 0; $ti -lt $proc.Threads.Count; $ti++) { $tids[$ti] = $proc.Threads[$ti].Id }
                foreach ($hit in [MeowAudit.Fast]::ShellcodeThreads($h, $tids, $rB, $rS)) {
                    $tp = $hit -split '\|', 2
                    $procHigh++; $nHigh++
                    Add-Finding HIGH "[THREAD_EXEC] $($proc.ProcessName) (PID $($proc.Id)) - thread $($tp[0]) starts in unbacked memory @ 0x$($tp[1]) (shellcode / manual-map entry point)"
                }
            } catch { }

            # ---- DEBUG_PORT ----
            $dbg = 0; $retLen = 0
            if ([MeowAudit.Native]::NtQueryInformationProcessInt($h, 7, [ref]$dbg, 4, [ref]$retLen) -eq 0) {
                if ($dbg -ne 0) {
                    $procHigh++
                    Add-Finding MEDIUM "[DEBUG_PORT] $($proc.ProcessName) (PID $($proc.Id)) - debug port active (common pre-injection step)"
                }
            }
            # PEB image path tampering already surfaces as HIDDEN_DLL/RUNPE
            # through the loader-list diff, so no separate PEB_PATH query here.

            [MeowAudit.Native]::CloseHandle($h) | Out-Null
            if ($procHigh -gt 0) { Write-Host "$red  <- $procHigh anomaly(s)$reset" }
            else { Write-Host "$dim  consistent$reset" }
        }
    }
    $procWord = if ($nProc -eq 1) { 'process' } else { 'processes' }
    if ($nProc -gt 0) { $script:runs += "integrity/$Label : $nProc $procWord, $nHigh [HIGH]" }
    return "$nProc $procWord / $nHigh [HIGH]"
}

# ---------------- Shared: audit a DLL/EXE referenced by a persistence key -----
# Two-phase by design: Add-PathFinding only NORMALIZES and queues (level 4
# references ~800 registry paths; verifying each serially through the cmdlet
# fallback cost ~10 s of this stage). Invoke-PersistenceAudit then warms the
# parallel signature engine for the whole queue and flushes the findings.
function Add-PathFinding {
    param([string]$Origin, [string]$Path, [string]$Extra = '')
    if (-not $Path) { return }
    $clean = $Path.Trim('"', ' ')
    if ($clean -match '%') { $clean = [Environment]::ExpandEnvironmentVariables($clean) }
    if (-not ($clean -match '\.dll$|\.exe$|\.ocx$|\.sys$')) { return }
    # Normalize exotic path forms so existing files are not misread as missing
    # (these caused false [HIGH] on legitimate Windows components):
    #   \SystemRoot\System32\cdd.dll  -> C:\Windows\System32\cdd.dll
    #   \??\C:\...                     -> C:\...
    #   AppMon.dll (bare name)        -> C:\Windows\System32\AppMon.dll
    if ($clean -match '^\\SystemRoot\\') { $clean = "$env:SystemRoot" + $clean.Substring(11) }
    elseif ($clean -match '^\\??\\')     { $clean = $clean.Substring(4) }
    elseif ($clean -notmatch '^[A-Za-z]:\\' -and $clean -notmatch '^\\\\') {
        $sys32 = "$env:SystemRoot\System32\$clean"
        if (Test-Path -LiteralPath $sys32) { $clean = $sys32 }
    }
    if (-not (Test-Path -LiteralPath $clean)) {
        Add-Finding HIGH "[$Origin] target missing on disk -> $clean $Extra"
        return
    }
    $script:pathQueue.Add([PSCustomObject]@{ Origin = $Origin; Clean = $clean; Extra = $Extra })
}

# Flush the level-4 queue: parallel signatures first, then one cached lookup
# per path (this replaced the old serial ~12 ms/path cmdlet fallback).
function Invoke-PathQueue {
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($q in $script:pathQueue) { [void]$set.Add($q.Clean) }
    if ($set.Count -gt 0) {
        Write-Host "$dim  [persistence] verifying $($set.Count) files in parallel...$reset"
        Warm-Signatures -Paths $set
    }
    foreach ($q in $script:pathQueue) {
        # inline cache lookup (same as the L1 loop: 4.8k PS function calls
        # were ~1 s of pure call overhead on already-warmed paths)
        $sig = if ($q.Clean) { $script:sigCache[$q.Clean] } else { $null }
        if ($null -eq $sig) { $sig = Get-SigCached -path $q.Clean }
        $lvl = Get-RiskLevel -path $q.Clean -sigStatus $sig.Status -procDir $null
        if ($lvl -eq 'HIGH')       { Add-Finding HIGH   "[$($q.Origin)] $($q.Clean) (signature: $($sig.Status)) $($q.Extra)" }
        elseif ($lvl -eq 'MEDIUM') { Add-Finding MEDIUM "[$($q.Origin)] $($q.Clean) (signature: $($sig.Status)) $($q.Extra)" }
    }
    $script:pathQueue.Clear()
}

# ---------------- LEVEL 4: persistence / registry autostart audit -----------
function Invoke-PersistenceAudit {
    Write-Host "$dim  [persistence] registry autostart + hijack points...$reset"
    $nHigh = 0

    # --- AppInit_DLLs (injected into every user32-loading process) ---
    foreach ($hive in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $k = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue
        if ($k -and $k.LoadAppInit_DLLs -eq 1 -and $k.AppInit_DLLs) {
            foreach ($d in ($k.AppInit_DLLs -split '[,; ]+')) {
                if ($d) { Add-PathFinding -Origin 'APPINIT_DLLS' -Path $d -Extra '(LoadAppInit_DLLs=1 -> loaded into every user32 process)' }
            }
        }
    }

    # --- AppCertDlls (LSA loads these into every process-creating call) ---
    $acd = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
    if ($acd) {
        foreach ($p in $acd.PSObject.Properties) {
            if ($p.Name -notlike 'PS*') { Add-PathFinding -Origin 'APPCERT_DLLS' -Path $p.Value -Extra '(LSA process-creation hook)' }
        }
    }

    # --- VerifierDlls (Application Verifier providers, loaded on app start) ---
    $vds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\VerifierDlls' -ErrorAction SilentlyContinue
    if ($vds) {
        foreach ($p in $vds.PSObject.Properties) {
            if ($p.Name -notlike 'PS*' -and $p.Value) {
                $v = "$env:SystemRoot\System32\$($p.Value)"
                if (-not (Test-Path -LiteralPath $v)) { Add-PathFinding -Origin 'VERIFIER_DLLS' -Path $p.Value -Extra '(not in System32)' }
            }
        }
    }

    # --- IFEO Debugger (hijack: runs instead of the target) ---
    $ifeo = Open-RegKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if ($ifeo) {
        try {
            foreach ($subName in $ifeo.GetSubKeyNames()) {
                try { $sk = $ifeo.OpenSubKey($subName) }
                catch {
                    # IFEO subkeys are Users-readable by default; a denied one
                    # means someone is hiding the Debugger entry from readers
                    Add-Finding MEDIUM "[IFEO] subkey '$subName' denied to readers (hidden Image File Execution Options entry)"
                    continue
                }
                if (-not $sk) { continue }
                $dv = $sk.GetValue('Debugger')
                $sk.Close()
                if ($dv) { Add-PathFinding -Origin "IFEO($subName)" -Path $dv -Extra '(Image File Execution Options debugger)' }
            }
        } finally { $ifeo.Close() }
    }

    # --- AeDebug / WER (WerFault hijack) ---
    foreach ($ad in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug') {
        $dbg = (Get-ItemProperty -Path $ad -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        if ($dbg -and $dbg -notmatch 'drwtsn32|UnhandledException') {
            Add-Finding MEDIUM "[AEDEBUG] custom crash debugger -> $dbg"
        }
    }

    # --- SilentProcessExit MonitorProcess ---
    $sie = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue
    if ($sie -and $sie.MonitorProcess) { Add-PathFinding -Origin 'SILENT_EXIT' -Path $sie.MonitorProcess -Extra '(silent process exit monitor)' }

    # --- COR / CLR profiler env (injected into every .NET process) ---
    foreach ($ev in 'COR_ENABLE_PROFILER','COR_PROFILER','COR_PROFILER_PATH',
                    'CORECLR_ENABLE_PROFILER','CORECLR_PROFILER','CORECLR_PROFILER_PATH') {
        foreach ($scope in 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
                           'HKCU:\Environment') {
            $val = (Get-ItemProperty -Path $scope -Name $ev -ErrorAction SilentlyContinue).$ev
            if ($val -and $val -ne '0') {
                if ($val -match '\.dll') { Add-PathFinding -Origin "CLR_PROFILER($ev)" -Path $val -Extra '(.NET profiler -> injected into managed processes)' }
                else { Add-Finding MEDIUM "[CLR_PROFILER] $ev=$val (CLSID profiler registered under $scope)" }
            }
        }
    }

    # --- Winlogon Shell / Userinit / Notify ---
    $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe$') { Add-PathFinding -Origin 'WINLOGON_SHELL' -Path ($wl.Shell -split ',')[0] -Extra "(Shell='$($wl.Shell)')" }
        if ($wl.Userinit -and $wl.Userinit -notmatch 'userinit\.exe\s*,?\s*$') { Add-PathFinding -Origin 'WINLOGON_USERINIT' -Path ($wl.Userinit -split ',')[0] -Extra "(Userinit='$($wl.Userinit)')" }
    }
    $wn = Open-RegKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
    if ($wn) {
        try {
            foreach ($ntfName in $wn.GetSubKeyNames()) {
                $sk = try { $wn.OpenSubKey($ntfName) } catch { $null }
                if (-not $sk) { continue }
                $dl = $sk.GetValue('DllName')
                $sk.Close()
                if ($dl) { Add-PathFinding -Origin "WINLOGON_NOTIFY($ntfName)" -Path $dl -Extra '(legacy Winlogon notify)' }
            }
        } finally { $wn.Close() }
    }

    # --- COM hijack: HKCU overrides of CLSID InprocServer32 ---
    # (.NET registry walk: the PS Get-ChildItem/Get-ItemProperty version cost
    # ~7 s per hive on a busy CLSID key)
    foreach ($clsHive in 'HKCU:\SOFTWARE\Classes\CLSID', 'HKCU:\SOFTWARE\Classes\WOW6432Node\CLSID') {
        $clsRoot = Open-RegKey -Path $clsHive
        if (-not $clsRoot) { continue }
        try {
            foreach ($clsid in $clsRoot.GetSubKeyNames()) {
                $isp = try { $clsRoot.OpenSubKey("$clsid\InprocServer32") } catch { $null }
                if (-not $isp) { continue }
                $dv = $isp.GetValue('')
                $isp.Close()
                if ($dv) { Add-PathFinding -Origin "COM_HIJACK($clsid)" -Path "$dv" -Extra '(HKCU COM override)' }
            }
        } finally { $clsRoot.Close() }
    }

    # --- Winsock LSP chain (per-socket DLL injection) ---
    foreach ($cat in 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries',
                     'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog9\Catalog_Entries') {
        foreach ($entry in (Get-ChildItem -Path $cat -Recurse -ErrorAction SilentlyContinue)) {
            $item = (Get-ItemProperty -Path $entry.PSPath -Name 'PackedCatalogItem' -ErrorAction SilentlyContinue).PackedCatalogItem
            if ($item) {
                $dll = [System.Text.Encoding]::ASCII.GetString($item) -replace '[^\x20-\x7E]', ''
                if ($dll -match '[A-Za-z]:\\[^\"]+\.dll') { Add-PathFinding -Origin 'WINSOCK_LSP' -Path $Matches[0] -Extra '(LSP in socket chain)' }
            }
        }
    }

    # --- Netsh helper DLLs ---
    foreach ($nh in 'HKLM:\SOFTWARE\Microsoft\NetSh', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\NetSh') {
        $k = Get-ItemProperty -Path $nh -ErrorAction SilentlyContinue
        if ($k) {
            foreach ($p in $k.PSObject.Properties) {
                if ($p.Name -notlike 'PS*' -and $p.Value -match '\.dll') {
                    $full = if ($p.Value -match '[A-Za-z]:\\') { $p.Value } else { "$env:SystemRoot\System32\$($p.Value)" }
                    Add-PathFinding -Origin "NETSH($($p.Name))" -Path $full -Extra '(netsh helper)'
                }
            }
        }
    }

    # --- Print monitors / providers (loaded by the spooler) ---
    foreach ($pm in (Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue)) {
        $dv = (Get-ItemProperty -Path $pm.PSPath -Name 'Driver' -ErrorAction SilentlyContinue).Driver
        if ($dv) { Add-PathFinding -Origin "PRINT_MONITOR($($pm.PSChildName))" -Path $dv -Extra '(spooler-loaded monitor)' }
    }

    # --- Service DLLs (svchost-hosted services) - .NET walk, ~2.2 s -> ~0.2 s ---
    $svcRoot = Open-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'
    if ($svcRoot) {
        try {
            foreach ($svcName in $svcRoot.GetSubKeyNames()) {
                $sk = try { $svcRoot.OpenSubKey($svcName) } catch { $null }
                if (-not $sk) { continue }
                $img = $sk.GetValue('ImagePath')
                $par = try { $sk.OpenSubKey('Parameters') } catch { $null }
                $sdp = $null
                if ($par) { $sdp = $par.GetValue('ServiceDll'); $par.Close() }
                $sk.Close()
                if ($sdp) { Add-PathFinding -Origin "SERVICE_DLL($svcName)" -Path $sdp -Extra '(svchost service DLL)' }
                if ($img -and $img -match '\.dll') { Add-PathFinding -Origin "SERVICE_IMAGE($svcName)" -Path $img -Extra '(service image is a DLL)' }
            }
        } finally { $svcRoot.Close() }
    }

    # --- Office COM add-ins (VBA/Office macro & add-in load) ---
    foreach ($off in 'HKCU:\SOFTWARE\Microsoft\Office',
                     'HKLM:\SOFTWARE\Microsoft\Office',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office') {
        $offKey = Open-RegKey -Path $off
        if (-not $offKey) { continue }
        try {
            foreach ($node in (Get-RegSubTree -Key $offKey)) {
                if ($node.Name -match 'Addins|AddIns') {
                    $addin = $node.Key
                    foreach ($compName in $addin.GetSubKeyNames()) {
                        $comp = try { $addin.OpenSubKey($compName) } catch { $null }
                        if (-not $comp) { continue }
                        $mf = $comp.GetValue('Manifest')
                        $fb = $comp.GetValue('Filename')
                        $comp.Close()
                        if ($mf) { Add-PathFinding -Origin "OFFICE_ADDIN($compName)" -Path $mf -Extra '(Office add-in manifest)' }
                        if ($fb) { Add-PathFinding -Origin "OFFICE_ADDIN($compName)" -Path $fb -Extra '(Office add-in binary)' }
                    }
                }
            }
        } finally { $offKey.Close() }
    }

    # --- WMI permanent event subscription (fileless persistence) ---
    foreach ($ns in 'root\subscription', 'root\default') {
        foreach ($cls in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
            foreach ($obj in (Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction SilentlyContinue)) {
                $desc = ($obj | Out-String) -replace '\s+', ' '
                $hit = $false
                if ($cls -eq '__EventFilter' -and $obj.Query -match 'powershell|cmd\.exe|rundll32|mshta|wscript|cscript|regsvr32') { $hit = $true }
                if ($cls -eq 'CommandLineEventConsumer' -and $obj.CommandLineTemplate -match 'powershell|cmd\.exe|rundll32|mshta|wscript|cscript|regsvr32|certutil|bitsadmin') { $hit = $true }
                if ($cls -eq 'ActiveScriptEventConsumer' -and $obj.ScriptText) { $hit = $true }
                if ($hit) { Add-Finding HIGH "[WMI_PERSIST] $ns\$cls -> $($desc.Substring(0, [Math]::Min(160, $desc.Length)))" }
            }
        }
    }

    # --- Run / RunOnce keys ---
    foreach ($rk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
        $k = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
        if ($k) {
            foreach ($p in $k.PSObject.Properties) {
                if ($p.Name -notlike 'PS*' -and $p.Value -match '\.exe|\.dll|\.vbs|\.ps1|\.bat') {
                    $first = ([string]$p.Value).Trim('"').Split(' ')[0].Trim('"')
                    Add-PathFinding -Origin "RUN($($p.Name))" -Path $first -Extra '(logon autostart)'
                }
            }
        }
    }

    # --- flush the deferred path queue: parallel signatures, then findings ---
    Invoke-PathQueue

    $nHigh = $script:findings.HIGH.Count
    $script:runs += "persistence : registry audit complete"
    return "persistence audit complete"
}

# ---------------- LEVEL 5: system audit (drivers / boot / Sysmon) ----------
function Invoke-SystemAudit {
    Write-Host "$dim  [system] kernel drivers, boot config, Sysmon log...$reset"
    $nDrv = 0

    # --- loaded kernel drivers: signature + BYOVD shortlist ---
    $mods = @()
    try { $mods = [MeowAudit.Native]::QuerySystemModules() } catch { }

    # Phase A: normalize every driver path, then verify signatures in parallel
    $drvList = New-Object System.Collections.Generic.List[object]
    $drvPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $mods) {
        $p = $line -split '\|', 4
        if ($p.Count -lt 4) { continue }
        $full = $p[0]; $short = $p[3]
        $fsPath = $full -replace '^\\SystemRoot\\', "$env:SystemRoot\" `
                       -replace '^\\??\\', '' `
                       -replace '^\\\S+\\', "$env:SystemRoot\System32\"
        $leaf = if ($short) { $short } else { Split-Path $fsPath -Leaf }
        $drvList.Add([PSCustomObject]@{ Path = $fsPath; Leaf = $leaf })
        if (Test-PathCached -path $fsPath) { [void]$drvPaths.Add($fsPath) }
    }
    if ($drvPaths.Count -gt 0) { Warm-Signatures -Paths $drvPaths }

    foreach ($drv in $drvList) {
        $fsPath = $drv.Path; $leaf = $drv.Leaf
        $nDrv++

        # BYOVD: known-abused vulnerable driver, loaded right now
        if ($script:BYOVDDrivers -contains $leaf.ToLower()) {
            Add-Finding HIGH "[BYOVD] loaded driver '$leaf' is on the known-vulnerable/abused list -> $fsPath (terminate if the owning app is not expected)"
            continue
        }
        if (-not (Test-PathCached -path $fsPath)) { continue }
        $sig = Get-SigCached -path $fsPath
        if ($sig.Status -ne 'Valid') {
            # unsigned kernel driver = HIGH; Microsoft-signed = ok
            Add-Finding HIGH "[DRIVER] loaded driver is NOT validly signed: $fsPath (signature: $($sig.Status))"
        }
    }

    # --- boot config: testsigning / nointegritychecks open the door to any driver ---
    $bcd = bcdedit /enum '{current}' 2>$null | Out-String
    if ($bcd -match 'testsigning\s+Yes')  { Add-Finding HIGH "[BOOT] test signing is ENABLED (bcdedit testsigning) - unsigned drivers can load" }
    if ($bcd -match 'nointegritychecks\s+Yes') { Add-Finding HIGH "[BOOT] integrity checks are DISABLED (bcdedit nointegritychecks)" }
    if ($bcd -match 'hypervisorlaunchtype\s+Auto') { Add-Finding INFO  "[BOOT] hypervisorlaunchtype=Auto (VBS/HVCI active)" }

    # --- Secure Boot status ---
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if (-not $sb) { Add-Finding MEDIUM "[BOOT] Secure Boot is DISABLED" }
    } catch { Add-Finding INFO "[BOOT] Secure Boot state not queryable (legacy BIOS or access denied)" }

    # --- Sysmon: recent cross-process activity (if installed) ---
    try {
        $sysmon = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if ($sysmon.RecordCount -gt 0) {
            $since = (Get-Date).AddHours(-24)
            # Event 8 = CreateRemoteThread, Event 10 = ProcessAccess, Event 25 = ProcessTampering
            $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 8,10,25; StartTime = $since } -MaxEvents 400 -ErrorAction SilentlyContinue
            $nCrt = 0; $nTamper = 0; $nAccess = 0
            $crtLines = New-Object System.Collections.Generic.List[string]
            foreach ($e in $evts) {
                $xml = [xml]$e.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                switch ($e.Id) {
                    8 {
                        $nCrt++
                        $src = $data['SourceImage']; $tgt = $data['TargetImage']
                        # cross-process remote thread between unrelated images = injection
                        if ($src -and $tgt -and ((Split-Path $src -Leaf) -ne (Split-Path $tgt -leaf))) {
                            $crtLines.Add("      $(Split-Path $src -Leaf) -> $(Split-Path $tgt -Leaf) @ $($data['StartAddress'])")
                        }
                    }
                    10 { $nAccess++ }
                    25 { $nTamper++; Add-Finding HIGH "[TAMPER] Sysmon Event 25 (ProcessTampering) on $($data['ImageName']) @ $($e.TimeCreated)" }
                }
            }
            if ($nCrt -gt 0 -or $nTamper -gt 0) {
                Add-Finding MEDIUM "[SYSMON] last 24h: $nCrt CreateRemoteThread, $nAccess ProcessAccess, $nTamper ProcessTampering"
            }
            foreach ($l in ($crtLines | Select-Object -First 25)) { Add-Finding INFO "[SYSMON_CRT]$l" }
        }
    } catch { Add-Finding INFO "[SYSMON] not installed or log not queryable (optional: install Sysmon for live injection telemetry)" }

    $script:runs += "system : $nDrv kernel drivers, boot + Sysmon checked"
    return "$nDrv kernel drivers / boot / Sysmon"
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
    $hashed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $script:findings.HIGH) {
        $p = Get-FindingPath $line
        if ($p -and $hashed.Add($p) -and (Test-Path -LiteralPath $p)) {
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
  - LZ4:       $env:TEMP\liblz4-java-*.so
  - Minecraft: lwjgl/OpenAL/glfw/jinput/odin natives under .minecraft
  - Custom:    MEOW_whitelist.txt in this folder (patterns or sha256: lines, per machine)
  - SS quiet:  x64dbg unsigned builds / CercaParole / MeowImportsChecker / SSTool / Shard / hollow_detector
  - Hash:      SHA256 of operator toolset (mc-ss-tool / CompilerIdCXX / MeowClientFucker / MeowDoomsdayFucker / SS-Shellcode-Scanner)

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

function Show-FindingLegend {
    Write-Host "  ${dim}Finding tags:${reset}"
    Write-Host "    ${red}KEYWORD${reset}       cheat/injector words in path or DLL name"
    Write-Host "    ${red}FILE_MISSING${reset}  the file is gone from disk"
    Write-Host "    ${red}PATH+SIG${reset}      unsigned DLL in an untrusted folder"
    Write-Host "    ${red}EXE${reset}           suspicious main executable"
    Write-Host "    ${red}HIDDEN_MODULE${reset} valid PE in memory not in the loader list (manual map / reflective)"
    Write-Host "    ${red}HIDDEN_DLL${reset}    module enumeration views disagree (hooked enumeration)"
    Write-Host "    ${red}INJECTOR${reset}      live process holds injection-capable handles on another process"
    Write-Host "    ${red}STOMPED${reset}       module memory differs from the file on disk"
    Write-Host "    ${red}RUNPE${reset}         main image differs from the EXE on disk (hollowing)"
    Write-Host "    ${red}IAT_HOOK${reset}      import slot points outside every known module"
    Write-Host "    ${red}NTDLL_HOOK${reset}    ntdll .text differs from the on-disk copy"
    Write-Host "    ${red}THREAD_EXEC${reset}   thread starts in unbacked memory (shellcode)"
    Write-Host "    ${red}BYOVD${reset}         loaded known-vulnerable driver"
    Write-Host "    ${red}DRIVER${reset}        unsigned kernel driver loaded"
    Write-Host "    ${red}WMI_PERSIST${reset}   WMI event subscription persistence"
    Write-Host "    ${yellow}DEBUG_PORT${reset}    process is being debugged  /  registry hijacks = [MEDIUM]"
    Write-Host ""
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
            $p = Get-FindingPath $l
            if (-not $p) { continue }
            $hash = Get-FileSha256 -path $p
            $short = if ($hash.Length -gt 32) { $hash.Substring(0, 32) + '...' } else { $hash }
            Write-Host "    $short  $((Split-Path $p -Leaf))" -ForegroundColor DarkGray
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
    # ASCII-only block art: MEOW (renders in every console/codepage)
    $art = @(
        ' __  __    ___    ___   ____ '
        '|  \/  |  / _ \  / _ \ |  _ \'
        '| |\/| | | (_) || (_) || | | |'
        '| |  | |  \__, | \__,/ |_| |_|'
        '|_|  |_|    |_|   |_|  '
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
    Write-Host "  ${cyan}[7]$reset ${yellow}Integrity scan$reset      - stomping / RunPE / hooks / shellcode threads"
    Write-Host "  ${cyan}[8]$reset Persistence audit   - registry autostart + hijack points"
    Write-Host "  ${cyan}[9]$reset System audit        - drivers, boot config, Sysmon"
    Write-Host "  ${cyan}[F]$reset ${red}FULL PASS$reset            - levels 1-5 (the -FullScan engine)"
    Write-Host "  ${cyan}[0]$reset Exit"
    Write-Host ""
}

# ---------------- Full pass (the -FullScan engine) --------------------------
# Levels in order, each with its own elapsed-time line so the total is
# transparent. Level 3 runs before level 2 because it reuses the same module
# snapshot while it is still warm.
function Invoke-FullPass {
    param([string[]]$Names, [switch]$SkipPersist, [switch]$SkipSystem)
    $names = @($Names | Select-Object -Unique)
    $tTotal = [Diagnostics.Stopwatch]::StartNew()
    $t = [Diagnostics.Stopwatch]::StartNew()

    Write-Host "$purple`n  [L1] DLL audit - module list + parallel signatures$reset"
    Invoke-ModuleAudit -ProcessNames $names -Label 'full' | Out-Null
    Write-Host "$dim  [L1] done in $([int]$t.Elapsed.TotalSeconds) s$reset"

    $t.Restart()
    Write-Host "$purple`n  [L3] integrity scan - memory vs disk, IAT/ntdll hooks, shellcode threads$reset"
    Invoke-IntegrityScan -ProcessNames $names -Label 'full' | Out-Null
    Write-Host "$dim  [L3] done in $([int]$t.Elapsed.TotalSeconds) s$reset"

    $t.Restart()
    Write-Host "$purple`n  [L2] deep memory scan - hidden / manual-mapped modules$reset"
    Invoke-DeepScan -ProcessNames $names -Label 'full' | Out-Null
    Write-Host "$dim  [L2] done in $([int]$t.Elapsed.TotalSeconds) s$reset"

    if (-not $SkipPersist) {
        $t.Restart()
        Write-Host "$purple`n  [L4] persistence audit - registry autostart + hijack points$reset"
        Invoke-PersistenceAudit | Out-Null
        Write-Host "$dim  [L4] done in $([int]$t.Elapsed.TotalSeconds) s$reset"
    }

    if (-not $SkipSystem) {
        $t.Restart()
        Write-Host "$purple`n  [L5] system audit - drivers, boot config, Sysmon$reset"
        Invoke-SystemAudit | Out-Null
        Write-Host "$dim  [L5] done in $([int]$t.Elapsed.TotalSeconds) s$reset"
    }

    Write-Host "$cyan  All levels done in $([int]$tTotal.Elapsed.TotalSeconds) s$reset"
}

# ---------------- Automatic mode (no menu) ----------------
if ($Auto) {
    Show-Banner
    Show-FindingLegend
    if ($Targets) {
        $list = Resolve-ProcessNames -Names $Targets
        if ($list.Count -eq 0) {
            Write-Host "$yellow  None of the requested processes are running.$reset"
            return
        }
    } else {
        $list = Get-AllProcessNames
    }

    if ($FullScan) {
        Invoke-FullPass -Names $list -SkipPersist:$SkipPersist -SkipSystem:$SkipSystem
    } else {
        Write-Host "$cyan  DLL audit: $(Invoke-ModuleAudit -ProcessNames $list -Label 'auto')$reset"
        if ($Deep) {
            Write-Host "$cyan  Integrity scan: $(Invoke-IntegrityScan -ProcessNames $list -Label 'auto')$reset"
            Write-Host "$cyan  Deep scan: $(Invoke-DeepScan -ProcessNames $list -Label 'auto')$reset"
        }
    }

    # Watch mode: keep hunting post-scan injection every N seconds
    if ($Watch -gt 0) {
        Write-Host "$cyan  [watch] re-scanning deep+integrity every $Watch s (Ctrl+C to stop)$reset"
        while ($true) {
            Start-Sleep -Seconds $Watch
            Reset-ModuleCache
            $wNames = if ($Targets) { $list } else { Get-AllProcessNames }
            Invoke-IntegrityScan -ProcessNames $wNames -Label 'watch' | Out-Null
            Invoke-DeepScan -ProcessNames $wNames -Label 'watch' | Out-Null
            Write-Host "$dim  [watch] $(Get-Date -Format 'HH:mm:ss') - HIGH total: $($script:findings.HIGH.Count)$reset"
        }
    }

    Show-Summary
    New-Report
    return
}

# ---------------- Interactive mode ----------------
Show-Banner
Show-FindingLegend
$exit = $false
while (-not $exit) {
    Show-Menu
    $choice = (Read-Host "  Select an option").Trim()

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
        '7' {
            Write-Host "$purple`n  >>> Integrity scan in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-IntegrityScan -ProcessNames (Get-AllProcessNames) -Label 'integrity')$reset"
            Show-Summary
        }
        '8' {
            Write-Host "$purple`n  >>> Persistence audit in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-PersistenceAudit)$reset"
            Show-Summary
        }
        '9' {
            Write-Host "$purple`n  >>> System audit in progress...$reset"
            Write-Host "$cyan  Result: $(Invoke-SystemAudit)$reset"
            Show-Summary
        }
        'F' { $choice = 'F' }
        'f' {
            Write-Host "$purple`n  >>> FULL PASS (levels 1-5) in progress...$reset"
            Invoke-FullPass -Names (Get-AllProcessNames)
            Show-Summary
        }
        '0' { $exit = $true }
        default { Write-Host "$yellow  Invalid option: choose 0-9 or F.$reset" }
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
