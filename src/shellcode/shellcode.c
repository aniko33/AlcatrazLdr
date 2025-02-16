/* 
*   Description: Manage the shellcode
*/

#include <string.h>

#include "shellcode.h"
#include "cargo.h"

int GetShellcodeSize() {
    return sizeof(shellcode_encoded) / sizeof(shellcode_encoded[0]);
}

void ShellcodeDecode(unsigned char* shellcode) {
    size_t shellcode_size = GetShellcodeSize();

    for (int i = 0; i < shellcode_size; i++) {
        const char** word = &shellcode_encoded[i];
        for (int y = 0; y < sizeof(shellcode_alphabet) / sizeof(shellcode_alphabet[0]); y++) {
            if (strcmp(*word, shellcode_alphabet[y]) == 0) {
                shellcode[i] = y;
            }
        }
    }
}
