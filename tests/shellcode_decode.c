#include <stdio.h>
#include <string.h>
#include "../src/shellcode/shellcode.h"
#include "utils.h"

int main() {
    size_t shellcode_size = GetShellcodeSize();
    unsigned char shellcode[shellcode_size];

    ShellcodeDecode(shellcode);
    PrintByteArray(shellcode, shellcode_size);
}
