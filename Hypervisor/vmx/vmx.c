#include "vmx.h"
#include "vmxtraps.h"
#include "../common/memory.h"
#include "../common/hypercall.h"

extern PHVM_DEPENDENT g_Hvm;
extern ULONG g_uSubvertedCPUs;

HVM_DEPENDENT g_Vmx = {
	ARCH_VMX,
	VmxIsImplemented,
	VmxInitialize,
	VmxVirtualize,
	VmxShutdown, 
	VmxRegisterTraps,
	VmxIsTrapVaild,
	VmxDispatchEvent,
	VmxAdjustRip
};

static BOOLEAN VmxIsImplemented()
{
	//see intel manual for cpuid
	//you should know how params passed and stack allocated for x64
	BOOLEAN isImp = FALSE;
	LONG32 cpuinfo[4];
	__cpuid(cpuinfo, 0);
	//GetCpuIdInfo(0, &eax, &ebx, &ecx, &edx);
	if (cpuinfo[0] < 1) {
		Trace(("VmxIsImplemented : GetCpuIdInfo() CPUID Not Implemented\n"));
		return FALSE;
	}
	if (!(cpuinfo[1] == 0x756e6547 && cpuinfo[2] == 0x6c65746e && cpuinfo[3] == 0x49656e69)) {
		Trace(("VmxIsImplemented : GetCpuIdInfo() Genu ntel ineI\n"));
		return FALSE;
	}
	//GetCpuIdInfo(0x1, &eax, &ebx, &ecx, &edx);
	__cpuid(cpuinfo, 1);
	isImp = CmIsBitSet(cpuinfo[2], 5);
	return isImp;
}

static NTSTATUS VmxInitialize(PCPU Cpu, PVOID GuestRip, PVOID GuestRsp)
{
	NTSTATUS status;
	Cpu->Vmx.OriginaVmxonR = MmAllocate(VMX_VMXONR_SIZE);
	if (!Cpu->Vmx.OriginaVmxonR) {
		Trace("VmxInitialize: Failed to allocate memory for original Vmxon\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	Trace(("VmxInitialize: OriginaVmxonR VA: 0x%p\n", Cpu->Vmx.OriginaVmxonR));

	Cpu->Vmx.OriginalVmcs = MmAllocate(VMX_VMCS_SIZE);
	if (!Cpu->Vmx.OriginalVmcs) {
		Trace(("VmxInitialize: Failed to allocate memory for original VMCS\n"));
	}
	Cpu->Vmx.OriginalVmcsPA = MmGetPhysicalAddress(Cpu->Vmx.OriginalVmcs);
	Trace(("VmxInitialize: Vmcs VA: 0x%p\n", Cpu->Vmx.OriginalVmcs));
	Trace(("VmxInitialize: Vmcs PA: 0x%p\n", Cpu->Vmx.OriginalVmcsPA));

	Cpu->Vmx.IOBitmapA = MmAllocate(VMX_IOBitmap_SIZE);
	if (!Cpu->Vmx.IOBitmapA) {
		Trace(("VmxInitialize: Failed to allocate memory for original IOBitmapA\n"));
	}
	Cpu->Vmx.IOBitmapAPA = MmGetPhysicalAddress(Cpu->Vmx.IOBitmapA);
	RtlZeroMemory(Cpu->Vmx.IOBitmapA, VMX_IOBitmap_SIZE);
	Trace(("VmxInitialize: IOBitmapA VA: 0x%p\n", Cpu->Vmx.IOBitmapA));

	Cpu->Vmx.IOBitmapB = MmAllocate(VMX_IOBitmap_SIZE);
	if (!Cpu->Vmx.IOBitmapB) {
		Trace(("VmxInitialize: Failed to allocate memory for original IOBitmapB\n"));
	}
	Cpu->Vmx.IOBitmapBPA = MmGetPhysicalAddress(Cpu->Vmx.IOBitmapB);
	RtlZeroMemory(Cpu->Vmx.IOBitmapA, VMX_IOBitmap_SIZE);
	Trace(("VmxInitialize: IOBitmapB VA: 0x%p\n", Cpu->Vmx.IOBitmapB));

	Cpu->Vmx.MSRBitmap = MmAllocate(VMX_MSRBitmap_SIZE);
	if (!Cpu->Vmx.MSRBitmap) {
		Trace(("VmxInitialize: Failed to allocate memory for original MSRBitmap\n"));
	}
	Cpu->Vmx.MSRBitmapPA = MmGetPhysicalAddress(Cpu->Vmx.MSRBitmap);
	RtlZeroMemory(Cpu->Vmx.MSRBitmap, VMX_MSRBitmap_SIZE);
	Trace(("VmxInitialize: MSRBitmap VA: 0x%p\n", Cpu->Vmx.MSRBitmap));

	status = VmxEnable(Cpu->Vmx.OriginaVmxonR);
	if (!NT_SUCCESS(status)) {
		Trace(("VmxInitialize: VmxEnable() failed with status 0x%08hX\n", status));
		return STATUS_UNSUCCESSFUL;
	}
	Trace(("VmxInitialize: Vmx enabled\n"));
	
	status = VmxSetupVMCS(Cpu, GuestRip, GuestRsp);
	if (!NT_SUCCESS(status)) {
		Trace(("VmxInitialize: VmxSetupVMCS() failed with status 0x%08hX\n", status));
		VmxDisable();
		return STATUS_UNSUCCESSFUL;
	}

	Cpu->Vmx.GuestEFER = __readmsr(MSR_EFER);
	Trace(("Guest MSR_EFER Read 0x%llx \n", Cpu->Vmx.GuestEFER));

	Cpu->Vmx.GuestCR0 = __readcr0();
	Cpu->Vmx.GuestCR3 = __readcr3();
	Cpu->Vmx.GuestCR4 = __readcr4();

	return STATUS_SUCCESS;
}

static NTSTATUS VmxVirtualize(PCPU Cpu)
{
	if (!Cpu) {
		return STATUS_INVALID_PARAMETER;
	}

	Trace(("VmxVirtualize(): VmxRead: 0x%X \n", VmxRead(VM_INSTRUCTION_ERROR)));
	Trace(("VmxVirtualize(): RFlags before vmxLaunch: 0x%x \n", RegGetRflags()));
	Trace(("VmxVirtualize(): PCPU: 0x%p \n", Cpu));

	__vmx_vmlaunch();

	// never returns
	ULONG64 error;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &error);

	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS VmxShutdown(PCPU Cpu, PGUEST_REGS GuestRegs, BOOLEAN bSetupTimeBomb)
{
	//UCHAR trampolone[0x600];
	if (!GuestRegs) {
		return STATUS_UNSUCCESSFUL;
	}

	Trace(("VmxShutdown(): CPU#%d", Cpu->ProcessorNumber));
	InterlockedDecrement(&g_uSubvertedCPUs);

	VmxByeHyper(GuestRegs);

	//never return
	return STATUS_SUCCESS;
}
static BOOLEAN VmxIsTrapVaild(ULONG TrappedVmExit)
{
	if (TrappedVmExit > VMX_MAX_GUEST_VMEXIT) {
		return FALSE;
	}
	return TRUE;
}

static VOID VmxDispatchEvent(PCPU Cpu, PGUEST_REGS GuestRegs)
{
	NTSTATUS status;
	ULONG64 exitCode;
	PNBP_TRAP trap;
	ULONG32 hypercallNumber;

	if (!Cpu || !GuestRegs) {
		return;
	}

	__vmx_vmread(VM_EXIT_REASON, &exitCode);
	status = TrFindRegisteredTrap(Cpu, GuestRegs, exitCode, &trap);
	if (!NT_SUCCESS(status)) {
		Trace(("VmxHandleInterception(): TrFindRegisteredTrap() failed for exitcode 0x%llX and status 0x%llx\n", exitCode, status));
		VmxCrash(Cpu, GuestRegs);
	}

	status = TrExecuteGeneralTrapHandler(Cpu, GuestRegs, trap, FALSE);
	if (!NT_SUCCESS(status)) {
		Trace(("VmxHandleInterception: HvmExecuteGeneralTrapHandler() failed with status 0x%08hX\n", status));
	}

	hypercallNumber = (ULONG32)(GuestRegs->rdx & 0xffff);
	switch (hypercallNumber) {
	case NBP_HYPERCALL_UNLOAD:
		Trace(("VmxHandleInterception(): NBP_HYPERCALL_UNLOAD\n"));
		g_Hvm->ArchShutdown(Cpu, GuestRegs, FALSE);
		Trace(("VmxHandleInterception(): ArchShutdown() returned\n"));
		break;
	default:
		break;
	}

}

static VOID VmxAdjustRip(PCPU Cpu,PGUEST_REGS GuestRegs,ULONG64 Delta)
{
	ULONG64 guestRip;
	__vmx_vmread(GUEST_RIP, &guestRip);
	__vmx_vmwrite(GUEST_RIP, guestRip + Delta);
}

static NTSTATUS VmxEnable(PVOID VmxonVA)
{
	ULONG64 cr4;
	ULONG64 vmxmsr;
	ULONG64 flags;
	PHYSICAL_ADDRESS VmxonPA;

	__writecr4(__readcr4() | X86_CR4_VMXE);
	cr4 = __readcr4();
	Trace(("VmxEnable: CR4 after VmxEnable: 0x%llx\n", cr4));
	if (!(cr4 & X86_CR4_VMXE))
		return STATUS_NOT_SUPPORTED;

	//vmxmsr = __readmsr(MSR_IA32_FEATURE_CONTROL);
	//if (!(vmxmsr & 0x04)) {
	//	_KdPrint(("VmxEnable: VMX is not supported: IA32_FEATURE_CONTROL is 0x%llx\n", vmxmsr));
	//	return STATUS_NOT_SUPPORTED;
	//}

	vmxmsr = __readmsr(MSR_IA32_VMX_BASIC);
	*((PULONG64)VmxonVA) = (vmxmsr & 0xffffffff);       //set up vmcs_revision_id
	VmxonPA = MmGetPhysicalAddress(VmxonVA);
	//Trace("VmxEnable: VmxonPA:  0x%llx\n", VmxonPA.QuadPart);
	UCHAR value = __vmx_on((PULONG64)&VmxonPA);
	//VmxTurnOn(MmGetPhysicalAddress(VmxonVA));
	flags = RegGetRflags();
	Trace(("VmxEnable: vmcs_revision_id: 0x%x  Eflags: 0x%x \n", vmxmsr, flags));
	return STATUS_SUCCESS;
}

VOID VmxDisable()
{
	ULONG64 cr4;
	__vmx_off();
	//ULONG64 mask = X86_CR4_VMXE;
	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	cr4 = __readcr4();
	Trace(("VmxDisable(): CR4 after VmxDisable: 0x%llx\n", cr4));
}

static NTSTATUS VmxSetupVMCS(PCPU Cpu, PVOID GuestRip, PVOID GuestRsp)
{
	PVOID gdtBase;
	SEGMENT_SELECTOR segmentSelector;
	ULONG64 pinBaseVmExecControl = 0;

	if (!Cpu || !Cpu->Vmx.OriginalVmcs) {
		return STATUS_INVALID_PARAMETER;
	}
	
	*((ULONG64 *)(Cpu->Vmx.OriginalVmcs)) = __readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff;

	__vmx_vmclear((PULONG64)&Cpu->Vmx.OriginalVmcsPA);
	__vmx_vmptrld((PULONG64)&Cpu->Vmx.OriginalVmcsPA);

	BOOLEAN capability = CmIsBitSet(__readmsr(MSR_IA32_VMX_BASIC), 55);

	//HOST-STATE AREA
		//cr0, cr3, cr4(64)
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
		//RIP, RSP(64)
	__vmx_vmwrite(HOST_RSP, (ULONG64)Cpu);
	__vmx_vmwrite(HOST_RIP, (ULONG64)VmxVmexitHandler);
		//Selector fields(16)
	__vmx_vmwrite(HOST_CS_SELECTOR, RegGetCs() & 0xf8);
	__vmx_vmwrite(HOST_ES_SELECTOR, RegGetEs() & 0xf8);
	__vmx_vmwrite(HOST_DS_SELECTOR, RegGetDs() & 0xf8);
	__vmx_vmwrite(HOST_SS_SELECTOR, RegGetSs() & 0xf8);
	__vmx_vmwrite(HOST_FS_SELECTOR, RegGetFs() & 0xf8);
	__vmx_vmwrite(HOST_GS_SELECTOR, RegGetGs() & 0xf8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTrSelector() & 0xf8);
		//Base-address fields(64)
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
	CmInitializeSegmentSelector(&segmentSelector, GetTrSelector(), (PVOID)GetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, segmentSelector.base);
	__vmx_vmwrite(HOST_GDTR_BASE, (ULONG64)GetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, (ULONG64)GetIdtBase());
	//__vmx_vmwrite(HOST_GDTR_BASE, (ULONG64)Cpu->GdtArea);
	//__vmx_vmwrite(HOST_IDTR_BASE, (ULONG64)Cpu->IdtArea);
		//MSRs
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	//GUEST-STATE AREA
		//cr0, cr3, cr4(64)
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
		//dr7
	//__vmx_vmwrite(GUEST_DR7, 0x400);
		//RIP, RSP, RFLAGS
	__vmx_vmwrite(GUEST_RSP, (ULONG64)GuestRsp);     //setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)GuestRip);     //setup guest ip:CmSlipIntoMatrix
	__vmx_vmwrite(GUEST_RFLAGS, RegGetRflags());
		//CS, SS, DS, ES, FS, GS, LDTR, and TR:
	gdtBase = (PVOID)GetGdtBase();
	VmxFillGuestSelectorData(gdtBase, ES, RegGetEs());
	VmxFillGuestSelectorData(gdtBase, CS, RegGetCs());
	VmxFillGuestSelectorData(gdtBase, SS, RegGetSs());
	VmxFillGuestSelectorData(gdtBase, DS, RegGetDs());
	VmxFillGuestSelectorData(gdtBase, FS, RegGetFs());
	VmxFillGuestSelectorData(gdtBase, GS, RegGetGs());
	VmxFillGuestSelectorData(gdtBase, LDTR, GetLdtr());
	VmxFillGuestSelectorData(gdtBase, TR, GetTrSelector());
	__vmx_vmwrite(GUEST_ES_BASE, 0);
	__vmx_vmwrite(GUEST_CS_BASE, 0);
	__vmx_vmwrite(GUEST_SS_BASE, 0);
	__vmx_vmwrite(GUEST_DS_BASE, 0);
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
		//GDTR, IDTR
	__vmx_vmwrite(GUEST_GDTR_BASE, (ULONG64)gdtBase);
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
		//MSRs
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xffffffff);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
		//Active state
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
		//Interruptibility state
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
		//Pending debug exceptions
	//__vmx_vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
		//Guest Non-Register State - VMCS link pointer(64)
		//Software should set this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry failures
	__vmx_vmwrite(VMCS_LINK_POINTER, 0xffffffff);
	__vmx_vmwrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//VM-EXECUTION CONTROL FIELDS
		//Pin-Based VM-Execution Controls(32) & Processor-Based VM-Execution Controls(32)
	pinBaseVmExecControl |= CPU_BASED_ACTIVATE_MSR_BITMAP;
	if (capability) {
		__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(pinBaseVmExecControl, MSR_IA32_VMX_TRUE_PINBASED_CTLS));
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(pinBaseVmExecControl, MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
	}
	else {
		__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS));
	}
		//Exception Bitmap(32)
	__vmx_vmwrite(EXCEPTION_BITMAP, 0);
		//Page Fault will not cause a VM-Exit
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
		//I/O-Bitmap Addresses(64)
	/*__vmx_vmwrite(IO_BITMAP_A, Cpu->Vmx.IOBitmapAPA.LowPart);
	__vmx_vmwrite(IO_BITMAP_A_HIGH, Cpu->Vmx.IOBitmapBPA.HighPart);
	__vmx_vmwrite(IO_BITMAP_B, Cpu->Vmx.IOBitmapBPA.LowPart);
	__vmx_vmwrite(IO_BITMAP_B_HIGH, Cpu->Vmx.IOBitmapBPA.HighPart);*/
		//Time-Stamp Counter Offset(64)
	//__vmx_vmwrite(TSC_OFFSET, 0);
	//__vmx_vmwrite(TSC_OFFSET_HIGH, 0);
		//Guest/Host Masks and Read Shadows for CR0 and CR4
	__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
	//__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0 | X86_CR0_PG);
	//__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0 | X86_CR4_VMXE);
	//__vmx_vmwrite(CR0_READ_SHADOW, (__readcr4() & X86_CR0_PG) | X86_CR0_PG);
	//__vmx_vmwrite(CR4_READ_SHADOW, 0);
		//CR3-Target Controls
	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
		//MSR-Bitmap Address(64)
	__vmx_vmwrite(MSR_BITMAP, Cpu->Vmx.MSRBitmapPA.LowPart);
	__vmx_vmwrite(MSR_BITMAP_HIGH, Cpu->Vmx.MSRBitmapPA.HighPart);

	//VM-EXIT CONTROL FIELDS
		//VM-Exit Controls
	if (capability) {
		__vmx_vmwrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_TRUE_EXIT_CTLS));
	}
	else {
		__vmx_vmwrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	}
		//VM-Exit Controls for MSRs
	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	//VM-ENTRY CONTROL FIELDS
		//VM-Entry Controls
	if (capability) {
		__vmx_vmwrite(VM_ENTRY_CONTROLS, VmxAdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_TRUE_ENTRY_CTLS));
	}
	else {
		__vmx_vmwrite(VM_ENTRY_CONTROLS, VmxAdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
	}
		//VM-Entry Controls for MSRs
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
		//VM-Entry Controls for Event Injection
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);	

	Trace(("VmxSetupVMCS: Exit\n"));

	return STATUS_SUCCESS;
}

static ULONG32 VmxAdjustControls(ULONG32 Ctl, ULONG32 Msr)
{
	LARGE_INTEGER MsrValue;

	MsrValue.QuadPart = __readmsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

static NTSTATUS VmxFillGuestSelectorData(
	PVOID GdtBase,
	ULONG Segreg,
	USHORT Selector
)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	CmInitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)& SegmentSelector.attributes)[0] + (((PUCHAR)& SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

	if ((Segreg == LDTR) || (Segreg == TR)) {
		// don't setup for FS/GS - their bases are stored in MSR values
		__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);
	}

	return STATUS_SUCCESS;
}

VOID VmxCrash(PCPU Cpu, PGUEST_REGS GuestRegs)
{
	Trace(("!!!VMX CRASH!!!\n"));
	while (1);
}