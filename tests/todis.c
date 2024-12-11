#include <windows.h>

typedef NTSTATUS(WINAPI* protoRtlMoveMemory)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);

int main() {
    PVOID arg1 = (PVOID)0xAA;
    PVOID arg2 = (PVOID)0xAB;
    INT arg3 = 0xAC;
    protoRtlMoveMemory pRtlMoveMemory = (protoRtlMoveMemory) GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlMoveMemory");

    pRtlMoveMemory(arg1, arg2, arg3);
}
