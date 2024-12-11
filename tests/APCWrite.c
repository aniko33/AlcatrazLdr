#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <unwin.h>

#include "utils.h"

int main(int argc, char* argv[]) {
    HANDLE hThread;
    if (argc < 2) {
        printf("Usage: %s <pid>", argv[0]);
        return -1;
    }
    
    int pid = atoi(argv[1]);

    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    );

    if (hProc == 0x0) {
        printf("OpenProcess FAILED");
        return -1;
    }

    char message[] = "Lost in the Procedure!";
    char message2[] = "Welcome to APC's world";

    PVOID src  = VirtualAllocEx(
        hProc,
        NULL,
        sizeof(message),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    PVOID src2 = VirtualAllocEx(
        hProc,
        NULL,
        sizeof(message2),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!WriteProcessMemory(
        hProc,
        src,
        message,
        sizeof(message),
        NULL
    )) {
        printf("Unable to write message\n");
        return -1;
    }

    if (!WriteProcessMemory(
        hProc,
        src2,
        message2,
        sizeof(message2),
        NULL
    )) {
        printf("Unable to write message2\n");
        return -1;
    }

    PVOID dest = VirtualAllocEx(
        hProc,
        NULL,
        1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    PVOID dest2 = VirtualAllocEx(
        hProc,
        NULL,
        1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    printf("src: 0x%p\ndest: 0x%p\n", src, dest);
    printf("++++++++++++++++++++++++++++++++++++\n");
    printf("src: 0x%p\ndest: 0x%p\n", src2, dest2);


    DWORD tid;
    hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (PTHREAD_START_ROUTINE)SuspendThread,
        NtCurrentThread,
        CREATE_SUSPENDED,
        &tid
    );

    if (hThread == 0x0) {
        printf("CreateRemoteThread ERROR");
        return -1;
    }

    NtQueueApcThread(
        hThread,
        (LPVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlMoveMemory"),
        dest,
        src,
        (PVOID)sizeof(message)
    );
    
    printf("TID: %d/0x%x\n", tid, tid);

    NtQueueApcThread(
        hThread,
        (LPVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlMoveMemory"),
        dest2,
        src2,
        (PVOID)sizeof(message2)
    );

    ULONG count;
    NTSTATUS status = NtAlertResumeThread(hThread, &count);

    printf("0x%x\n", status);

    return 0;
}
