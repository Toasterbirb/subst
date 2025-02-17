section .text
	global _start

_start:
	mov r10, 100
	mov r11, 200
	cmp r10, r11
	jge correct

	wrong:
		mov rdi, 0
		jmp exit

	correct:
		mov rdi, 42

	exit:
		mov rax, 60
		syscall
