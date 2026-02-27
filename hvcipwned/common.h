#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned __int64 u64;
typedef unsigned __int32 u32;
typedef unsigned __int16 u16;
typedef unsigned __int8  u8;

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#define LOG_OK(fmt, ...)    printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf("[~] " fmt "\n", ##__VA_ARGS__)
#define LOG_FAIL(fmt, ...)  printf("[-] " fmt "\n", ##__VA_ARGS__)

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fnRtlGetVersion)(
    PRTL_OSVERSIONINFOW);

#endif