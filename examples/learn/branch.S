    .text
    .p2align 2
    .global choose_level
    .type choose_level, %function

// int choose_level(int score)
choose_level:
    cmp     w0, #8
    b.lt    .Llevel_one
    mov     w0, #2
    ret
.Llevel_one:
    mov     w0, #1
    ret
    .size choose_level, .-choose_level
