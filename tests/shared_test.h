#include <stdio.h>

extern int GlobalInt;

void PrintInt() {
    printf("FROM FUNCTION: %d\n", GlobalInt);
}
