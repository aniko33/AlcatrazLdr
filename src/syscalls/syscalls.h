#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <unwin.h>

// { Macros }

/*
    Fast use of ADE - is a great option for all indirect-syscalls
*/
#define CallAde(SINNER, FUNCNAME, OUTSTATUS, ...)       \
    SINNER = NewSinner(FUNCNAME, GlobalAde);            \
    NewAde(SINNER.SyscallNumber);                       \
    OUTSTATUS = SINNER.Success ? ExecuteAde( __VA_ARGS__ ) : 0xFF

// { Externs }
FASTCALL VOID NewAde(int SyscallNumber);
NTSTATUS NTAPI ExecuteAde();
// __attribute__((ms_abi)) NTSTATUS ExecuteAde();

// { Structs }
typedef struct Ade {
    PIMAGE_DOS_HEADER Base;
    PIMAGE_EXPORT_DIRECTORY Exports;
} Ade;

typedef struct AdeSinner {
    int Success;
    int SyscallNumber;
} AdeSinner;

// { Functions }

Ade InitAde();
AdeSinner NewSinner(char* tFuncname, Ade ade);

#endif
