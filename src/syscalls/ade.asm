section .data
    SyscallNum db 0h

section .text
    global NewAde
    global ExecuteAde

NewAde: ; FASTCALL
    mov [rel SyscallNum], rcx
    ret

ExecuteAde: ; MS_ABI
    mov r10, rcx
    mov rax, [rel SyscallNum]
    syscall
    ret
