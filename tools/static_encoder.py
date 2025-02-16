"""
    Encode a shellcode using a random word alphabet - a word equals to a HEX value
"""

from os import path
import sys
import random
import json

def list_to_c_array_str(l: list, varname = None) -> str:
    if varname is None:
        out = "{\n\t"
    else:
        out = "char* " + varname + "[] = {\n\t" 

    y = 0
    for i, b in enumerate(l):
        if y > 4:
            out += "\n\t"
            y = 0
        else: y += 1

        if i < len(l) - 1:
            out += f"\"{b}\", " 
        else: out += f"\"{b}\""

    return out + "\n};"

def main(argc: int, argv: list[str]):
    if argc < 2:
        print("Usage: %s <shellcode.bin>" % argv[0])
        return

    english_words = list(json.load(
        open(path.join(path.dirname(__file__), "words_dictionary.json"), "r")
    ).keys())
    
    shellcode_file = argv[1]
    shellcode = open(shellcode_file, "rb").read()

    shellcode_alphabet = list()
    while len(shellcode_alphabet) < 256:
        random_word = random.choice(english_words)

        if not random_word in shellcode_alphabet:
            shellcode_alphabet.append(random_word)

    shellcode_encoded = []

    for b in shellcode:
        shellcode_encoded.append(shellcode_alphabet[b])

    cargo_fd = open("src/shellcode/cargo.h", "w")
    cargo_fd.write(
        "#ifndef CARGO_H\n#define CARGO_H\n"
        +
        "const " + list_to_c_array_str(shellcode_alphabet, "shellcode_alphabet") 
        +
        "\nconst " + list_to_c_array_str(shellcode_encoded, "shellcode_encoded")
        +
        "\n#endif"
    )

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
