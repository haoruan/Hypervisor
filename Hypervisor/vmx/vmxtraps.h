#ifndef _VMX_TRAPS_H
#define _VMX_TRAPS_H

#include "../common/common.h"
#include "../common/traps.h"

NTSTATUS VmxRegisterTraps(PCPU Cpu);

static BOOLEAN VmxDispatchVmxInstrDummy(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	);
static BOOLEAN VmxDispatchCpuid(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	);
static BOOLEAN VmxDispatchStraight(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	);

#endif