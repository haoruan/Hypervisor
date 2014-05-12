EXTERN	HvmSubvertCpu:PROC
EXTERN	HvmResumeGuest:PROC

SAVE_VOLATILE_REGS MACRO
	push	rax
	push	rcx
	push	rdx
	;push	rbx
	;push	rbp
	;push	rsi
	;push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	;push	r12
	;push	r13
	;push	r14
	;push	r15
ENDM

RESTORE_VOLATILE_REGS MACRO
	;pop	r15
	;pop	r14
	;pop	r13
	;pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	;pop	rdi
	;pop	rsi
	;pop	rbp
	;pop	rbx
	pop	rdx
	pop	rcx
	pop	rax
ENDM

.CODE

CmSubvert PROC

	SAVE_VOLATILE_REGS

	sub	rsp, 20h

	mov	rcx, rsp
	call	HvmSubvertCpu

CmSubvert ENDP

CmSlipIntoMatrix PROC

	call	HvmResumeGuest

	add	rsp, 20h

	RESTORE_VOLATILE_REGS

	ret

CmSlipIntoMatrix ENDP

END