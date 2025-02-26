CC = x86_64-w64-mingw32-gcc
CFLAGS = -Iinclude -Iinclude/unwin.h -lntdll -masm=intel

.PHONY: all debug clean
all: output_dir out/main.o out/shellcode.o out/memory.o out/injection.o out/syscalls.o out/ade.o out/alcatrazLdr.exe

debug: CFLAGS += -DDEBUG -g
debug: clean all

clean:
	rm -f out/*

# Ensure the out directory exists
output_dir:
	@mkdir -p out

# 
# { MAIN BUILD }
#

out/main.o: src/main.c | output_dir
	$(CC) src/main.c $(CFLAGS) -o out/main.o -c

out/shellcode.o: src/shellcode/shellcode.c | output_dir
	$(CC) src/shellcode/shellcode.c $(CFLAGS) -o out/shellcode.o -c

out/memory.o: src/memory/memory.c | output_dir
	$(CC) src/memory/memory.c $(CFLAGS) -o out/memory.o -c

out/injection.o: src/injection/injection.c | output_dir
	$(CC) src/injection/injection.c $(CFLAGS) -o out/injection.o -c

out/syscalls.o: src/syscalls/syscalls.c | output_dir
	$(CC) src/syscalls/syscalls.c $(CFLAGS) -o out/syscalls.o -c

out/ade.o: src/syscalls/ade.asm | output_dir
	nasm -f win64 src/syscalls/ade.asm -o out/ade.o

out/alcatrazLdr.exe: out/*.o | output_dir
	$(CC) out/*.o $(CFLAGS) -o out/alcatrazLdr.exe

#
# { EXTRA }
#

out/objector.exe: tools/objector.c | output_dir
	$(CC) tools/objector.c $(CFLAGS) -o out/objector.exe
