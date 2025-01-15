#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <unwin.h>

// { Macros }

/*
    Fast use of ADE - is a great option for all indirect-syscalls
*/
#define CallAde(SINNER, FUNCNAME, OUTSTATUS, ...)       \
    SINNER = NewSinner(FUNCNAME, GlobalAde);            \
    NewAde(SINNER.SyscallAddr);                         \
    OUTSTATUS = ExecuteAde( __VA_ARGS__ )               \

// { Externs }
FASTCALL void NewAde(PVOID SyscallAddr);
__attribute__((ms_abi)) NTSTATUS ExecuteAde();

// { Structs }
typedef struct Ade {
    PIMAGE_DOS_HEADER Base;
    PIMAGE_EXPORT_DIRECTORY Exports;
} Ade;

typedef struct AdeSinner {
    int Success;
    PVOID SyscallAddr;
} AdeSinner;

// { Functions }

Ade InitAde();
AdeSinner NewSinner(char* tFuncname, Ade ade);

#endif
