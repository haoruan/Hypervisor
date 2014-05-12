#include "traps.h"
#include "memory.h"

extern PHVM_DEPENDENT g_Hvm;

NTSTATUS TrRegisterTrap(PCPU Cpu, PNBP_TRAP Trap)
{
	PLIST_ENTRY TrapList;

	if (!Cpu || !Trap)
		return STATUS_INVALID_PARAMETER;

	switch (Trap->TrapType) {
	case TRAP_GENERAL:
		TrapList = &Cpu->GeneralTrapsList;
		break;
	//case TRAP_MSR:
		//TrapList = &Cpu->MsrTrapsList;
		//break;
	//case TRAP_IO:
		//TrapList = &Cpu->IoTrapsList;
		//break;
	default:
		
		("TrRegisterTrap: Unknown TRAP_TYPE code: %d\n", (char)Trap->TrapType);
		return STATUS_UNSUCCESSFUL;
	}

	InsertTailList(TrapList, &Trap->le);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI TrInitializeGeneralTrap(
	PCPU Cpu,
	ULONG TrappedVmExit,
	UCHAR RipDelta,
	NBP_TRAP_CALLBACK TrapCallback,
	PNBP_TRAP * pInitializedTrap
)
{
	PNBP_TRAP Trap;
	Trace(("TrInitializeGeneralTrap():TrappedVmExit 0x%x\n", TrappedVmExit));

	if (!Cpu || !TrapCallback || !g_Hvm->ArchIsTrapValid(TrappedVmExit) || !pInitializedTrap)
		return STATUS_INVALID_PARAMETER;

	Trap = MmAllocate(sizeof (NBP_TRAP));
	if (!Trap) {
		Trace(("TrInitializeGeneralTrap: MmAllocate() Failed to allocate NBP_TRAP structure (%d bytes)\n", sizeof (NBP_TRAP)));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(Trap, sizeof (NBP_TRAP));

	Trap->TrapType = TRAP_GENERAL;
	Trap->General.TrappedVmExit = TrappedVmExit;
	Trap->General.RipDelta = RipDelta;
	Trap->TrapCallback = TrapCallback;

	*pInitializedTrap = Trap;

	return STATUS_SUCCESS;
}

NTSTATUS TrDeregisterTrap(PNBP_TRAP Trap)
{
	if (!Trap) {
		return STATUS_INVALID_PARAMETER;
	}

	RemoveEntryList(&Trap->le);
	return STATUS_SUCCESS;
}

NTSTATUS TrDeregisterTrapList(PLIST_ENTRY TrapList)
{
	PNBP_TRAP Trap, NextTrap;
	NTSTATUS Status;

	if (!TrapList) {
		return STATUS_INVALID_PARAMETER;
	}

	Trap = (PNBP_TRAP)TrapList->Flink;
	while (Trap != (PNBP_TRAP)TrapList) {
		Trap = CONTAINING_RECORD(Trap, NBP_TRAP, le);
		NextTrap = (PNBP_TRAP)Trap->le.Flink;

		if (!NT_SUCCESS(Status = TrDeregisterTrap(Trap))) {
			Trap = NextTrap;
			continue;
		}

		//CmFreePhysPages(Trap, BYTES_TO_PAGES(sizeof (NBP_TRAP)));
		ExFreePoolWithTag(Trap, ITL_TAG);

		Trap = NextTrap;
	}

	return STATUS_SUCCESS;
}

NTSTATUS TrFindRegisteredTrap(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	ULONG64 exitcode,
	PNBP_TRAP * pTrap
	)
{
	TRAP_TYPE TrapType;
	PLIST_ENTRY TrapList;
	PNBP_TRAP Trap;

	if (!Cpu || !GuestRegs || !pTrap) {
		return STATUS_INVALID_PARAMETER;
	}

	TrapType = TRAP_GENERAL;
	TrapList = &Cpu->GeneralTrapsList;

	Trap = (PNBP_TRAP)TrapList->Flink;
	while (Trap != (PNBP_TRAP)TrapList) {
		Trap = CONTAINING_RECORD(Trap, NBP_TRAP, le);
		if ((Trap->TrapType == TrapType) && Trap->TrapCallback) {
			if ((Trap->TrapType == TRAP_GENERAL) && (Trap->General.TrappedVmExit == exitcode)) {
				*pTrap = Trap;
				return STATUS_SUCCESS;
			}
		}
		Trap = (PNBP_TRAP)Trap->le.Flink;
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS TrExecuteGeneralTrapHandler(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	)
{
	if (!Cpu || !GuestRegs || !Trap || (Trap->TrapType != TRAP_GENERAL))
		return STATUS_INVALID_PARAMETER;

	if (Trap->TrapCallback(Cpu, GuestRegs, Trap, WillBeAlsoHandledByGuestHv)) {
		// trap handler wants us to adjust guest's RIP
		g_Hvm->ArchAdjustRip(Cpu, GuestRegs, Trap->General.RipDelta);
	}

	return STATUS_SUCCESS;
}