    .text
    .p2align 2
    .global scale_score
    .type scale_score, %function

// unsigned scale_score(unsigned score)
scale_score:
    lsl     w0, w0, #1
    add     w0, w0, #3
    ret
    .size scale_score, .-scale_score
