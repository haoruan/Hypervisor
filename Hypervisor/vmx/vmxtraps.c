#include "vmxtraps.h"

NTSTATUS VmxRegisterTraps(PCPU Cpu)
{
	NTSTATUS status;
	PNBP_TRAP trap;
	ULONG32 i;
	ULONG32 vmxInstExits[] = {
		EXIT_REASON_VMCALL,
		EXIT_REASON_VMCALL,
		EXIT_REASON_VMLAUNCH,
		EXIT_REASON_VMRESUME,
		EXIT_REASON_VMPTRLD,
		EXIT_REASON_VMPTRST,
		EXIT_REASON_VMREAD,
		EXIT_REASON_VMWRITE,
		EXIT_REASON_VMXON,
		EXIT_REASON_VMXOFF
	}, nonRootInstExits[] = {
		EXIT_REASON_INVD
	};

	// length of the instruction, 0 means length need to be get from vmcs later. 
	status = TrInitializeGeneralTrap(Cpu, EXIT_REASON_CPUID, 0, VmxDispatchCpuid, &trap);
	if (!NT_SUCCESS(status)) {
		Trace(("VmxRegisterTraps: TrInitializeGeneralTrap() Failed to register VmxDispatchCpuid with status 0x%08hX\n", status));
		return status;
	}
	TrRegisterTrap(Cpu, trap);

	// set dummy handler for all VMX intercepts if we compile wihtout nested support
	for (i = 0; i < sizeof (vmxInstExits) / sizeof (ULONG32); i++) {
		// length of the instruction, 0 means length need to be get from vmcs later. 
		status = TrInitializeGeneralTrap(Cpu, vmxInstExits[i], 0, VmxDispatchVmxInstrDummy, &trap);
		if (!NT_SUCCESS(status)) {
			Trace(("VmxRegisterTraps: TrInitializeGeneralTrap() Failed to register VmxDispatchVmon with status 0x%08hX\n", status));
			return STATUS_UNSUCCESSFUL;
		}
		TrRegisterTrap(Cpu, trap);
	}

	// set straight handler for instructions that we ingore
	for (i = 0; i < sizeof (nonRootInstExits) / sizeof (ULONG32); i++) {
		// length of the instruction, 0 means length need to be get from vmcs later. 
		status = TrInitializeGeneralTrap(Cpu, nonRootInstExits[i], 0, VmxDispatchStraight, &trap);
		if (!NT_SUCCESS(status)) {
			Trace(("VmxRegisterTraps: TrInitializeGeneralTrap() Failed to register VmxDispatchVmon with status 0x%08hX\n", status));
			return STATUS_UNSUCCESSFUL;
		}
		TrRegisterTrap(Cpu, trap);
	}

	return STATUS_SUCCESS;
}

static BOOLEAN VmxDispatchCpuid(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	)
{
	ULONG32 fn, cpuinfo[4], ecx;
	ULONG64 inst_len;

	if (!Cpu || !GuestRegs) {
		return TRUE;
	}
	fn = (ULONG32)GuestRegs->rax;

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
	if (Trap->General.RipDelta == 0) {
		Trap->General.RipDelta = inst_len;
	}

	if (fn == BP_KNOCK_EAX) {
		GuestRegs->rax = BP_KNOCK_EAX_ANSWER;
		return TRUE;
	}

	ecx = (ULONG32)GuestRegs->rcx;
	__cpuidex(cpuinfo, fn, ecx);
	GuestRegs->rax = cpuinfo[0];
	GuestRegs->rbx = cpuinfo[1];
	GuestRegs->rcx = cpuinfo[2];
	GuestRegs->rdx = cpuinfo[3];

	return TRUE;
}

static BOOLEAN VmxDispatchVmxInstrDummy(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	)
{
	ULONG64 inst_len, guestRflags;
	if (!Cpu || !GuestRegs) {
		return TRUE;
	}
	//Trace("VmxDispatchVminstructionDummy: Nested virtualization not supported in this build!\n");

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
	Trap->General.RipDelta = inst_len;

	__vmx_vmread(GUEST_RFLAGS, &guestRflags);
	__vmx_vmwrite(GUEST_RFLAGS, guestRflags & (~0x8d5) | 0x1 /* VMFailInvalid */);
	return TRUE;
}

static BOOLEAN VmxDispatchStraight(
	PCPU Cpu,
	PGUEST_REGS GuestRegs,
	PNBP_TRAP Trap,
	BOOLEAN WillBeAlsoHandledByGuestHv
	)
{
	ULONG64 inst_len;

	if (!Cpu || !GuestRegs) {
		return TRUE;
	}

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
	if (Trap->General.RipDelta == 0) {
		Trap->General.RipDelta = inst_len;
	}

	return TRUE;
}