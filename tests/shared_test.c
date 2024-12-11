#include <stdio.h>
#include "shared_test.h"

extern int GlobalInt;

int main(int argc, char *argv[])
{
    printf("FROM MAIN: %d\n", GlobalInt);
    GlobalInt = 10 * 2;
    PrintInt();

    return 0;
}
