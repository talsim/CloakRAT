;;;;;;;;;;;;;; MAKE x32 VERSION
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

	add rsp, 2h
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

	add rsp, 8h
	pop rbp
ENDM


small_junk PROC
	;test ecx, ebx
	;jne yo
	;mov eax, eax
;yo:
	;nop
	;mov ebp, ebp
	ret
small_junk ENDP


jmp_rsp_destruction PROC
	junk_2
	mov rax, [rsp+10h]
	junk_1
	mov rbx, rax
	nop
	jmp rax
jmp_rsp_destruction ENDP


rsp_corrupt_destruction PROC
	junk_1
	add rsp, 16h
	junk_2
	ret
rsp_corrupt_destruction ENDP


END


