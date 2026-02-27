#include "device.h"
#include <setupapi.h>
#include <initguid.h>

#pragma comment(lib, "setupapi.lib")

DEFINE_GUID(GUID_KSCATEGORY_RENDER,
    0x65E8773E, 0x8F56, 0x11D0,
    0xA3, 0xB9, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96);

DEFINE_GUID(GUID_KSCATEGORY_AUDIO,
    0x6994AD04, 0x93EF, 0x11D0,
    0xA3, 0xCC, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96);

static HANDLE try_open_category(const GUID* cat)
{
    HDEVINFO devs;
    SP_DEVICE_INTERFACE_DATA ifd;
    SP_DEVICE_INTERFACE_DETAIL_DATA_W* det;
    DWORD needed;
    HANDLE h;
    DWORD idx;

    devs = SetupDiGetClassDevsW(cat, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devs == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    for (idx = 0; idx < 32; idx++) {
        memset(&ifd, 0, sizeof(ifd));
        ifd.cbSize = sizeof(ifd);

        if (!SetupDiEnumDeviceInterfaces(devs, NULL, cat, idx, &ifd))
            break;

        needed = 0;
        SetupDiGetDeviceInterfaceDetailW(devs, &ifd, NULL, 0, &needed, NULL);

        det = (SP_DEVICE_INTERFACE_DETAIL_DATA_W*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (!SetupDiGetDeviceInterfaceDetailW(devs, &ifd, det, needed, NULL, NULL)) {
            HeapFree(GetProcessHeap(), 0, det);
            continue;
        }

        h = CreateFileW(
            det->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            NULL);

        if (h != INVALID_HANDLE_VALUE) {
            LOG_OK("device: %ls", det->DevicePath);
            HeapFree(GetProcessHeap(), 0, det);
            SetupDiDestroyDeviceInfoList(devs);
            return h;
        }

        HeapFree(GetProcessHeap(), 0, det);
    }

    SetupDiDestroyDeviceInfoList(devs);
    return INVALID_HANDLE_VALUE;
}

HANDLE device_open_ks(void)
{
    HANDLE h;

    h = try_open_category(&GUID_KSCATEGORY_RENDER);
    if (h != INVALID_HANDLE_VALUE) return h;

    h = try_open_category(&GUID_KSCATEGORY_AUDIO);
    if (h != INVALID_HANDLE_VALUE) return h;

    LOG_FAIL("no suitable ks device found");
    return INVALID_HANDLE_VALUE;
}

void device_close(HANDLE h)
{
    if (h && h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}