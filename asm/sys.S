# clang -nostdlib asm.S -o asm
    .global _start

    .text
_start:
    mov     $0x3, %rbx       # store 3 to %rbx

# Run F 3 times
begin:
    call    F                # Run F

    dec     %rbx             # decrement register %rbx
    cmp     $0x0, %rbx       # see if %rbx is 0
    jne     begin            # loop if it's not 0
    xor     %rsi, %rsi       # clear %rsi

# Get input text
input:
    mov     $3, %rax         # sys read
    mov     $0, %rbx         # from stdin
    mov     $buffer, %rcx    # input buffer addr
    mov     $131, %rdx       # max # of bytes
    int     $0x80            # Why $0x80 instead of `syscall`?

# print the text that was inputted
relay:
    mov     $1, %rax         # write
    mov     $1, %rdi         # stdout
    mov     $buffer, %rcx    # address of buffer
    mov     $131, %rdx       # print until null terminator
    syscall

# Print $neat_str
neat:
    mov     $1, %rax         # write
    mov     $1, %rdi         # stdout
    mov     $neat_str, %rsi  # address of neat_str
    mov     $ins_len, %rdx   # length
    syscall

    xor     %rsi, %rsi       # clear, %rsi

end:
    mov     $60, %rax        # envoke exit
    xor     %rdi, %rdi       # return 0
    syscall                  # execute

# (function) Prints $message
F:
    mov     $1, %rax         # call 1 (write)
    mov     $1, %rdi         # stdout
    mov     $message, %rsi   # address of the string to output
    mov     $len, %rdx       # number of bytes
    syscall                  # execute
    ret

    .data
buffer:
    .ascii ""

    .text
message:
    .ascii "Hello, world!\n"
    len = . - message

neat_str:
    .ascii "Neat!\n"
    ins_len = . - neat_str
