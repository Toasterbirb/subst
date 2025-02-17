section .text
	global _start

_start:
	mov rax, 60
	mov rdi, 0
	syscall

	mov rax, 60
	mov rdi, 1
	syscall

	mov rax, 60
	mov rdi, 42
	syscall
