/* 
    Search SSNs and execute the syscalls
*/

#include <stdio.h>
#include <unwin.h>

#include "../debugging/debugging.h"
#include "syscalls.h"

Ade GlobalAde;

Ade InitAde() {
    PPEB peb = NtCurrentPeb();
    PPEB_LDR_DATA ldr               = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry     = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ldr->InMemoryOrderModuleList.Flink->Flink - 0x10); // 0x10 for 'padding'
    PIMAGE_DOS_HEADER dllPe         = (PIMAGE_DOS_HEADER) entry->DllBase;
    PIMAGE_NT_HEADERS dllPeNt       = (PIMAGE_NT_HEADERS) ((PBYTE)dllPe + dllPe->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE)dllPe + dllPeNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    Ade ade = { dllPe, exports };
    return ade;
}

AdeSinner NewSinner(char* tFuncname, Ade ade) {
    PDWORD exportsFuncs   = (PDWORD)((PBYTE)ade.Base + ade.Exports->AddressOfFunctions);
    PDWORD exportsNames   = (PDWORD)((PBYTE)ade.Base + ade.Exports->AddressOfNames);
    PWORD exportsOrdinals = (PWORD)((PBYTE) ade.Base + ade.Exports->AddressOfNameOrdinals);

    for (int i = 0; i < ade.Exports->NumberOfFunctions; i++) {
        char* funcName = (char*)((PBYTE)ade.Base + exportsNames[i]);
        PVOID funcAddr = ((PBYTE)ade.Base + exportsFuncs[exportsOrdinals[i]]);
        if (strcmp(funcName, tFuncname) == 0) {
            if ( *((PBYTE) funcAddr + 3) == 0xb8 ) {
                BYTE highSyscallNumber = *((PBYTE)funcAddr + 5);
                BYTE lowSyscallNumber = *((PBYTE)funcAddr + 4);
                AdeSinner sinner = {
                    .Success = 1,
                    (highSyscallNumber << 8) | lowSyscallNumber
                };

                return sinner;
            } else {
                AdeSinner sinner = {
                    0,
                    0
                };
            }
        }
    }

    AdeSinner sinner = { 0 };
    return sinner;
}
