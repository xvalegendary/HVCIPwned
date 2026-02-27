#ifndef OFFSETS_H
#define OFFSETS_H

#include "common.h"

#define PID_SYSTEM 4

typedef struct _EPROCESS_OFFSETS {
    u32 unique_pid;
    u32 active_links;
    u32 token;
    u32 build;
} EPROCESS_OFFSETS;

int resolve_offsets(EPROCESS_OFFSETS* off);

#endif