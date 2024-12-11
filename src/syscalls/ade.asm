section .data
    SyscallAddr dq 0x0

section .text
    global NewAde
    global ExecuteAde

NewAde: ; FASTCALL
    mov [rel SyscallAddr], rdx
    ret

ExecuteAde: ; MS_ABI
    mov r10, rcx
    jmp [rel SyscallAddr]
