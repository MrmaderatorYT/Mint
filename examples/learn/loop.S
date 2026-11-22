    .text
    .p2align 2
    .global repeat_add
    .type repeat_add, %function

// unsigned repeat_add(void)
repeat_add:
    mov     w0, #0
    mov     w1, #3
.Lrepeat:
    add     w0, w0, #2
    subs    w1, w1, #1
    b.ne    .Lrepeat
    ret
    .size repeat_add, .-repeat_add
