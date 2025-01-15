#include <windows.h>
#include <unwin.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

NTSTATUS status;

PSYSTEM_HANDLE_INFORMATION_EX GetHandleTable() {
    ULONG rsz = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleTable = malloc(0);

    do {
        handleTable = realloc(handleTable, rsz);
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            handleTable,
            rsz,
            &rsz
        );
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    return handleTable;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage %s <PID> [Type]", argv[0]);
        return -1;
    }

    int pid = atoi(argv[1]);
    HANDLE hproc;
    if (!(hproc = OpenProcess(
        PROCESS_DUP_HANDLE, 
        FALSE,
        pid
    ))) {
        printf("OpenProcess ERROR: 0x%x\n", GetLastError());
        return -1;
    }

    PSYSTEM_HANDLE_INFORMATION_EX handleTable = GetHandleTable();
    for (int i = 0; i < handleTable->NumberOfHandles; i++) {
        HANDLE handleDuplicated;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)handleTable->Handles[i];

        if (handleInfo.UniqueProcessId == pid && (HANDLE)handleInfo.HandleValue != INVALID_HANDLE_VALUE) {
            if (!DuplicateHandle(
                hproc,
                (HANDLE)handleInfo.HandleValue,
                GetCurrentProcess(),
                &handleDuplicated,
                DUPLICATE_SAME_ACCESS,
                FALSE,
                0 
            )) {
                continue;
            }
        } else {
            continue;
        }

        ULONG rsz = 0;
        PPUBLIC_OBJECT_TYPE_INFORMATION pHandleTypeInformation = malloc(0);

        do {
            pHandleTypeInformation = realloc(pHandleTypeInformation, rsz);
            status = NtQueryObject(
                handleDuplicated,
                ObjectTypeInformation,
                pHandleTypeInformation,
                rsz,
                &rsz
            );
        } while (status == STATUS_INFO_LENGTH_MISMATCH);
        
        char* handleTypeStr = malloc(pHandleTypeInformation->TypeName.MaximumLength);
        wcstombs(handleTypeStr, pHandleTypeInformation->TypeName.Buffer, pHandleTypeInformation->TypeName.MaximumLength);

        if (argc > 2) {
            if (strcmp(argv[2], handleTypeStr) == 0) {
                printf("HANDLE\t0x%x\nTYPE\t%s (%d)\n\n", handleInfo.HandleValue, handleTypeStr, handleInfo.ObjectTypeIndex);
            } 
        } else {
            printf("HANDLE\t0x%x\nTYPE\t%s (%d)\n\n", handleInfo.HandleValue, handleTypeStr, handleInfo.ObjectTypeIndex);
        }
    }

    return 0;
}
