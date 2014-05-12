.CODE

RegGetCs PROC
	mov		rax, cs
	ret
RegGetCs ENDP

RegGetDs PROC
	mov		rax, ds
	ret
RegGetDs ENDP

RegGetEs PROC
	mov		rax, es
	ret
RegGetEs ENDP

RegGetSs PROC
	mov		rax, ss
	ret
RegGetSs ENDP

RegGetFs PROC
	mov		rax, fs
	ret
RegGetFs ENDP

RegGetGs PROC
	mov		rax, gs
	ret
RegGetGs ENDP

GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP
GetTrSelector PROC
	str	rax
	ret
GetTrSelector ENDP

GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP
GetIdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
GetIdtLimit ENDP

GetGdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
GetGdtBase ENDP
GetIdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
GetIdtBase ENDP

RegGetRflags PROC
	pushfq
	pop		rax
	ret
RegGetRflags ENDP

RegGetTSC PROC
;	rdtscp
	rdtsc
	shl		rdx, 32
	or		rax, rdx
	ret
RegGetTSC ENDP

END