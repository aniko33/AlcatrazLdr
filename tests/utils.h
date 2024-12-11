#include <stdio.h>
#include <windows.h>

void PrintByteArray(unsigned char* array, int array_len) {
    int y = 0;
    for (int i = 0; i < array_len; i++) {
        if (y > 6) {
            printf("\n");
            y = 0;
        }
        printf("0x%x ", array[i]);
        y++;
    }
    printf("\n");
}
