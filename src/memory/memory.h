#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>

typedef struct _MEMORY_ALLOC {
    LPVOID executionAddr;
} MEMORY_ALLOC;

WINBOOL ThreadNameAlloc(
    HANDLE hProcess,
    PBYTE shellcode,
    size_t shellcodeSize,
    MEMORY_ALLOC* moduleAllocOut
);

#endif
