#include <libgen.h>
#include <stdio.h>

int main() {
    char sesso[] = "C:\\test.txt";
    printf("%s\n", basename(sesso));
    return 0;
}
