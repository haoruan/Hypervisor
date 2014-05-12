#ifndef _HVM_H
#define _HVM_H

#include "common.h"
#include "../vmx/vmx.h"

#define ARCH_VMX 1

#define	HOST_STACK_SIZE_IN_PAGES	16

// ntamd64_x.h
#define KGDT64_NULL (0 * 16)    // NULL descriptor
#define KGDT64_R0_CODE (1 * 16) // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16) // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16) // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

// this must be synchronized with CmSetBluepillSelectors() (common-asm.asm)
#define	BP_GDT64_CODE		KGDT64_R0_CODE  // cs
#define BP_GDT64_DATA		KGDT64_R0_DATA  // ds, es, ss
#define BP_GDT64_SYS_TSS	KGDT64_SYS_TSS  // tr
#define BP_GDT64_PCR		KGDT64_R0_DATA  // gs

#define BP_GDT_LIMIT	0x6f
#define BP_IDT_LIMIT	0xfff
#define BP_TSS_LIMIT	0x68    // 0x67 min

typedef struct _CPU
{

	PCPU SelfPointer;             // MUST go first in the structure; refer to interrupt handlers for details

	VMX Vmx;
	//union
	//{
	//	//SVM Svm;
	//	VMX Vmx;
	//};

	ULONG ProcessorNumber;
	//ULONG64 TotalTscOffset;

	//LARGE_INTEGER LapicBaseMsr;
	//PHYSICAL_ADDRESS LapicPhysicalBase;
	//PUCHAR LapicVirtualBase;

	LIST_ENTRY GeneralTrapsList;  // list of BP_TRAP structures
	//LIST_ENTRY MsrTrapsList;      //
	//LIST_ENTRY IoTrapsList;       //

	//PVOID SparePage;              // a single page which was allocated just to get an unused PTE.
	//PHYSICAL_ADDRESS SparePagePA; // original PA of the SparePage
	//PULONG64 SparePagePTE;

	//PSEGMENT_DESCRIPTOR GdtArea;
	//PVOID IdtArea;

	PVOID HostStack;              // note that CPU structure reside in this memory region
	//BOOLEAN Nested;

	//ULONG64 ComPrintLastTsc;

} CPU, *PCPU;

typedef BOOLEAN(*ARCH_IS_HVM_IMPLEMENTED)();
typedef NTSTATUS(*ARCH_INITIALIZE)(PCPU Cpu, PVOID GuestRip, PVOID GuestRsp);
typedef NTSTATUS(*ARCH_VIRTUALIZE)(PCPU Cpu);
typedef NTSTATUS(*ARCH_SHUTDOWN)(PCPU Cpu, PGUEST_REGS GuestRegs, BOOLEAN bSetupTimeBomb);
typedef NTSTATUS(*ARCH_REGISTER_TRAPS) (PCPU Cpu);
typedef BOOLEAN(*ARCH_IS_TRAP_VALID) (ULONG TrappedVmExit);
typedef VOID(*ARCH_DISPATCH_EVENT) (PCPU Cpu, PGUEST_REGS GuestRegs);
typedef VOID(*ARCH_ADJUST_RIP) (PCPU Cpu, PGUEST_REGS GuestRegs, ULONG64 Delta);

typedef struct
{
	UCHAR Architecture;

	ARCH_IS_HVM_IMPLEMENTED ArchIsHvmImplemented;
	ARCH_INITIALIZE ArchInitialize;
	ARCH_VIRTUALIZE ArchVirtualize;
	ARCH_SHUTDOWN ArchShutdown;
	ARCH_REGISTER_TRAPS ArchRegisterTraps;
	ARCH_IS_TRAP_VALID ArchIsTrapValid;
	ARCH_DISPATCH_EVENT ArchDispatchEvent;
	ARCH_ADJUST_RIP ArchAdjustRip;

} HVM_DEPENDENT, *PHVM_DEPENDENT;



VOID HvmVmExitCallback(PCPU Cpu,PGUEST_REGS GuestRegs);

NTSTATUS HvmInit();
NTSTATUS HvmSwallowBluepill();
NTSTATUS HvmSpitOutBluepill();
NTSTATUS HvmSubvertCpu(PVOID GuestRsp);
NTSTATUS HvmResumeGuest();

static NTSTATUS HvmSetupGdt(PCPU Cpu);
static NTSTATUS HvmLiberateCpu(PVOID Param);

#endif