#ifndef KRW_H
#define KRW_H

#include "common.h"
#include "offsets.h"

typedef struct _KRW_CTX {
    HANDLE hdev;
    u64    kbase;
    u64    pipe_obj;
    u64    fake_table;
    HANDLE hevent;
    int    ready;
} KRW_CTX;

int  krw_init(KRW_CTX* ctx, HANDLE hdev);
void krw_free(KRW_CTX* ctx);
u64  krw_read64(KRW_CTX* ctx, u64 addr);
u32  krw_read32(KRW_CTX* ctx, u64 addr);
int  krw_write64(KRW_CTX* ctx, u64 addr, u64 val);

#endif