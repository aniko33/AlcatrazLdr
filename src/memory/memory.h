#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>
#include <unwin.h>

typedef struct _MEMORY_ALLOC {
    LPVOID executionAddr;
} MEMORY_ALLOC;

WINBOOL ThreadNameAlloc(
    HANDLE hProcess,
    PBYTE shellcode,
    size_t shellcodeSize,
    MEMORY_ALLOC* moduleAllocOut
);

WINBOOL SleepObf(
    HANDLE hProcess,
    LPVOID ptrRegion,
    SIZE_T regionSize,
    ULONG time,
    UNICODE_STRING key
);

#endif
