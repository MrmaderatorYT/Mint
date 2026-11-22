    .text
    .p2align 2
    .global boost_score
    .type boost_score, %function

// unsigned boost_score(unsigned score)
boost_score:
    stp     x29, x30, [sp, #-16]!
    bl      score_bonus
    add     w0, w0, #1
    ldp     x29, x30, [sp], #16
    ret
    .size boost_score, .-boost_score

    .type score_bonus, %function
score_bonus:
    lsl     w0, w0, #1
    ret
    .size score_bonus, .-score_bonus
