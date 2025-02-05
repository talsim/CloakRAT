

.code

junk_1 MACRO
	push rbp
	mov rbp, rsp
	sub rsp, 16h

	xchg rax, rbx
	cmp rax, 17h
	jne what
	pop rax
	mov [rbp-12], rax
what:
	add rbx, -1
	xchg rbx, rax
	sub rax, -1

	add rsp, 16h
	pop rbp
ENDM

junk_2 MACRO
	push rbp
	mov rbp, rsp
	sub rsp, 16h
	
	cmp rax, 1
	jne a
a:
	test rbx, [rbp-12]
	je b
	push rax
	mov rax, [rbp-12]
	pop rax
b:
	nop
	nop

	add rsp, 16h
	pop rbp
ENDM

small_junk_1 PROC
	test ecx, ebx
	jne yo
	mov eax, eax
yo:
	nop
	mov ebp, ebp
small_junk_1 ENDP


destruction_1 PROC
	junk_2
	mov rax, [rsp+10h]
	junk_1
	jmp rax
destruction_1 ENDP


destruction_2 PROC

	junk_1

	add rsp, 40h

	junk_2

destruction_2 ENDP


END


