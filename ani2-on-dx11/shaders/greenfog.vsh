;------------------------------------------------------------------------------
; Vertex shader to render green fog
;------------------------------------------------------------------------------
xvs.1.1


mov oPos, v0
mov oT0,  v1


mul r0, v2, c1
mul r1, v2, c3
mul r2, v2, c5
add oT1, r0, c0
add oT2, r1, c2
add oT3, r2, c4

