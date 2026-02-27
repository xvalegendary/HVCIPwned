#ifndef TOKEN_H
#define TOKEN_H

#include "common.h"
#include "krw.h"
#include "offsets.h"

int token_elevate(KRW_CTX* ctx, EPROCESS_OFFSETS* off);
int token_spawn_shell(void);

#endif