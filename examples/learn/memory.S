    .text
    .p2align 2
    .global update_pair
    .type update_pair, %function

// unsigned update_pair(unsigned pair[2])
update_pair:
    ldp     w1, w2, [x0]
    add     w1, w1, w2
    str     w1, [x0]
    mov     w0, w1
    ret
    .size update_pair, .-update_pair
