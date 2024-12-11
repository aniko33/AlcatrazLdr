#include "unwin.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void CALLBACK rPrint(ULONG_PTR param) {
    char* message = (char*)param;
    printf("%s", message);
}

int main() {
    // Allocate and initialize messages
    char* message1 = malloc(1024);
    char* message2 = malloc(1024);

    if (message1 == NULL || message2 == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    // Initialize messages
    snprintf(message1, 1024, "Hello from APC 1\n");
    snprintf(message2, 1024, "Hello from APC 2\n");

    // Queue APCs for the current thread
    HANDLE thread = GetCurrentThread();
    QueueUserAPC(rPrint, thread, (ULONG_PTR)message1);
    QueueUserAPC(rPrint, thread, (ULONG_PTR)message2);

    // Alertable wait to process APCs
    NtTestAlert();

    // Clean up
    free(message1);
    free(message2);

    getchar();
    return 0;
}

