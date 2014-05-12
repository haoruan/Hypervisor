EXTERN	 HvmEventCallback:PROC
EXTERN	 VmxDisable:PROC

vmx_read MACRO
	BYTE	0Fh, 078h
ENDM
vmx_call MACRO
	BYTE	0Fh, 01h, 0C1h
ENDM
vmx_resume MACRO
	BYTE	0Fh, 01h, 0C3h
ENDM

MODRM_EAX_ECX MACRO  ;/* [EAX], [ECX] */
	BYTE	0C1h
ENDM

HVM_SAVE_ALL_NOSEGREGS MACRO
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax
ENDM

HVM_RESTORE_ALL_NOSEGREGS MACRO
	pop	rax
	pop	rcx
	pop	rdx
	pop	rbx
	pop	rbp		; rsp
	pop	rbp
	pop	rsi
	pop	rdi
	pop	r8
	pop	r9
	pop	r10
	pop	r11
	pop	r12
	pop	r13
	pop	r14
	pop	r15
ENDM

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

VmxVmCall PROC 
	mov rdx,rcx
	vmx_call
	ret
VmxVmCall ENDP

VmxVmexitHandler PROC   

	HVM_SAVE_ALL_NOSEGREGS
	
	mov     rcx, [rsp + 80h] ;PCPU
	mov 	rdx, rsp		;GuestRegs
	mov 	r8, 0		;TSC
	sub	rsp, 28h		;for 16-byte alignment

	;rdtsc
	
	call	HvmEventCallback
	add	rsp, 28h	

	HVM_RESTORE_ALL_NOSEGREGS	

	vmx_resume
	ret

VmxVmexitHandler ENDP

; Stack layout for VmxByeHyper:
;
; ^                              ^
; |--------------------------|
; |           rip            |
; |--------------------------|
; |           cs             |
; |--------------------------|   
; |         rflags           |
; |--------------------------|
; |			 rsp			 |
; |--------------------------|
; |			  ss			 |
; |--------------------------|
; |			GuestRegs		 |
; |				.			 |
; |				.			 |
; |				.			 |
; |				.			 |
; |				.			 |
; |				.			 |
; |				.			 |
; -----------------------------
VmxByeHyper PROC

	mov rsp, rcx

	mov rax, 00000804h	;GUEST_SS_SELECTOR
	vmx_read
	MODRM_EAX_ECX
	mov rax,rcx
	push rax

	mov rax, 0000681ch	;GUEST_RSP
	vmx_read
	MODRM_EAX_ECX
	mov rax,rcx
	push rax

	mov rax, 00006820h	;GUEST_RFLAGS
	vmx_read
	MODRM_EAX_ECX
	mov rax,rcx
	push rax

	mov rax, 00000802h	;GUEST_CS_SELECTOR
	vmx_read
	MODRM_EAX_ECX
	mov rax,rcx
	push rax

	mov rax, 0000681eh	;GUEST_RIP
	vmx_read
	MODRM_EAX_ECX
	mov rax,rcx
	push rax

	mov	rax, [rsp + 28h + 00h]
	mov	rcx, [rsp + 28h + 08h]
	mov	rdx, [rsp + 28h + 10h]
	mov	rbx, [rsp + 28h + 18h]
	;mov	rbp, [rsp + 28h + 20h] there is rsp
	mov	rbp, [rsp + 28h + 28h]
	mov	rsi, [rsp + 28h + 30h]
	mov	rdi, [rsp + 28h + 38h]
	mov	r8, [rsp + 28h + 40h]
	mov	r9, [rsp + 28h + 48h]
	mov	r10, [rsp + 28h + 50h]
	mov	r11, [rsp + 28h + 58h]
	mov	r12, [rsp + 28h + 60h]
	mov	r13, [rsp + 28h + 68h]
	mov	r14, [rsp + 28h + 70h]
	mov	r15, [rsp + 28h + 78h]

	SAVE_VOLATILE_REGS
	sub rsp, 28h

	call VmxDisable

	add rsp, 28h
	RESTORE_VOLATILE_REGS

	iretq

VmxByeHyper ENDP

END