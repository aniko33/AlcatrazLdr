/* 
    Search SSNs and execute the syscalls
*/

#include <unwin.h>

#include "syscalls.h"

extern FASTCALL void NewAde(PVOID SyscallAddr);
extern __attribute__((ms_abi)) NTSTATUS ExecuteAde();

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
            AdeSinner sinner = { 1, funcAddr + 3 };
            return sinner;
        }
    }

    AdeSinner sinner = { 0 };
    return sinner;
}
