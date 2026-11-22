    .text
    .p2align 2
    .global label_address
    .type label_address, %function

// const char *label_address(void)
label_address:
    adr     x0, practice_label
    ret
    .size label_address, .-label_address

    .section .rodata,"a",%progbits
    .type practice_label, %object
practice_label:
    .asciz "Mint practice label"
    .size practice_label, .-practice_label
