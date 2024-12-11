#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

#define WORKER_FACTORY_HANDLETYPE 30
#define IO_COMPLETION_HANDLETYPE 35

HANDLE DuplicateHandleK(HANDLE hproc, int pPid, int handleType);
int Inject(HANDLE targetProcHandle, HANDLE completionIoHandle, void* ptrShellcode);

#endif
