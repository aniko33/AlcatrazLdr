CC = x86_64-w64-mingw32-gcc
CFLAGS = -Iinclude -I../lib -lntdll -masm=intel
files := src/injection/*.c src/shellcode/*.c src/syscalls/*.c src/memory/*.c out/ade.o src/main.c

copy:
	cp out/*.exe ~/Documents/shared/
ade:
	nasm -f win64 src/syscalls/ade.asm -o out/ade.o

main: ade
	$(CC) $(files) $(CFLAGS) -o out/alcatrazLdr.exe

main_dbg: ade
	$(CC) $(files) $(CFLAGS) -o out/alcatrazLdr.exe -DDEBUG -g

objector: 
	$(CC) tools/objector.c $(CFLAGS) -o out/objector.exe

build: main_dbg copy
