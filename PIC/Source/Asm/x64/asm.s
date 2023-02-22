global GetRIP

section .text$F
    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret
