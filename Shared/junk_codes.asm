

.code

junkAsm1 MACRO ; doesn't work
	mov ebx, eax
	mov eax, [ebp+8]
	jmp eax
ENDM

END