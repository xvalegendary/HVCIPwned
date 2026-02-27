#ifndef DEVICE_H
#define DEVICE_H

#include "common.h"

HANDLE device_open_ks(void);
void   device_close(HANDLE h);

#endif