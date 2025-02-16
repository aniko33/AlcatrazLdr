CC = x86_64-w64-mingw32-gcc
CFLAGS = -Iinclude -I../lib -lntdll -masm=intel

.PHONY: all debug dev clean
all: out/main.o out/shellcode.o out/memory.o out/injection.o out/syscalls.o out/ade.o out/alcatrazLdr.exe

debug: CFLAGS += -DDEBUG -g
debug: clean all

dev: debug
	cp out/*.exe ~/Documents/shared/

clean:
	rm -f out/*

# 
# { MAIN BUILD }
#

out/main.o: src/main.c
	$(CC) src/main.c $(CFLAGS) -o out/main.o -c

out/shellcode.o: src/shellcode/shellcode.c
	$(CC) src/shellcode/shellcode.c $(CFLAGS) -o out/shellcode.o -c

out/memory.o: src/memory/memory.c
	$(CC) src/memory/memory.c $(CFLAGS) -o out/memory.o -c

out/injection.o: src/injection/injection.c
	$(CC) src/injection/injection.c $(CFLAGS) -o out/injection.o -c

out/syscalls.o: src/syscalls/syscalls.c
	$(CC) src/syscalls/syscalls.c $(CFLAGS) -o out/syscalls.o -c

out/ade.o: src/syscalls/ade.asm
	nasm -f win64 src/syscalls/ade.asm -o out/ade.o

out/alcatrazLdr.exe:
	$(CC) out/*.o $(CFLAGS) -o out/alcatrazLdr.exe

#
# { EXTRA }
#

out/objector.exe: tools/objector.c 
	$(CC) tools/objector.c $(CFLAGS) -o out/objector.exe
