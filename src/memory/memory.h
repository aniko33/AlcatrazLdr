#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>

typedef struct MODULE_STOMPING {
    LPVOID trampolineAddr;
    LPVOID shellcodeAddr;
} MODULE_STOMPING;

WINBOOL ModuleStomping(
    HANDLE hproc,
    char* pathTargetModule,
    PBYTE shellcode,
    size_t sizeShellcode,
    size_t sizePathTargetModule,
    MODULE_STOMPING* moduleStompingOut
);

#endif
