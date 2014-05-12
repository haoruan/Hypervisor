#include "hvm.h"
#include "memory.h"
#include "hypercall.h"

static KMUTEX g_HvmMutex;

PHVM_DEPENDENT g_Hvm;
ULONG g_uSubvertedCPUs = 0;

extern HVM_DEPENDENT g_Vmx;

NTSTATUS HvmInit(){
	BOOLEAN archIsOk = FALSE;

	g_Hvm = &g_Vmx;
	if (g_Hvm->ArchIsHvmImplemented()) {
		archIsOk = TRUE;
	}
	if (!archIsOk) {
		Trace(("HvmInit : ArchIsHvmImplemented() VMX is not supported\n"));
		return STATUS_NOT_SUPPORTED;
	}

	KeInitializeMutex(&g_HvmMutex, 0);
	return STATUS_SUCCESS;
}

NTSTATUS HvmSwallowBluepill()
{
	ULONG activeProcessors, iProcessor;
	NTSTATUS status, callbackStatus;

	KeWaitForSingleObject(&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

	activeProcessors = KeQueryActiveProcessorCount(NULL);
	for (iProcessor = 0; iProcessor < activeProcessors; iProcessor++) {
		Trace(("HvmSwallowBluepill: Subverting processor #%d\n", iProcessor));
		status = CmDeliverToProcessor(iProcessor, CmSubvert, NULL, &callbackStatus);
		if (!NT_SUCCESS(status)) {
			Trace(("HvmSwallowBluepill : CmDeliverToProcessor() failed with status 0x%08hX\n", status));
			KeReleaseMutex(&g_HvmMutex, FALSE);
			HvmSpitOutBluepill();
			return status;
		}
		if (!NT_SUCCESS(callbackStatus)) {
			Trace(("HvmSwallowBluepill : CmSubvert() failed with status 0x%08hX\n", callbackStatus));
			KeReleaseMutex(&g_HvmMutex, FALSE);
			HvmSpitOutBluepill();
			return callbackStatus;
		}
	}

	KeReleaseMutex(&g_HvmMutex, FALSE);
	if (activeProcessors != g_uSubvertedCPUs) {
		Trace(("HvmSwallowBluepill : ActiveProcessors not equals to SubvertedCPUs\n"));
		HvmSpitOutBluepill();
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HvmSpitOutBluepill()
{
	ULONG activeProcessors, iProcessor;
	NTSTATUS status, callbackStatus;

	KeWaitForSingleObject(&g_HvmMutex, Executive, KernelMode, FALSE, NULL);
	activeProcessors = KeQueryActiveProcessorCount(NULL);
	for (iProcessor = 0; iProcessor < activeProcessors; iProcessor++) {
		Trace(("HvmSpitOutBluepill: Liberating processor #%d\n", iProcessor));
		status = CmDeliverToProcessor(iProcessor, HvmLiberateCpu, NULL, &callbackStatus);
		if (!NT_SUCCESS(status)) {
			Trace(("HvmSpitOutBluepill: CmDeliverToProcessor() failed with status 0x%08hX\n", status));
		}

		if (!NT_SUCCESS(callbackStatus)) {
			Trace(("HvmSpitOutBluepill: HvmLiberateCpu() failed with status 0x%08hX\n", callbackStatus));
		}
	}

	KeReleaseMutex(&g_HvmMutex, FALSE);
	if (0 != g_uSubvertedCPUs) {
		Trace(("HvmSpitOutBluepill : SubvertedCPUs not equals to 0\n"));
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS HvmSubvertCpu(PVOID GuestRsp)
{
	NTSTATUS status;
	PCPU Cpu;
	PVOID hostKernelStackBase;
	Trace(("HvmSubvertCpu : Running on processor #%d\n", KeGetCurrentProcessorNumber()));
	//status = g_Hvm->ArchRegisterTraps(Cpu);
	hostKernelStackBase = MmAllocate(HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE);
	if (!hostKernelStackBase) {
		Trace(("HvmSubvertCpu: Failed to allocate %d pages for the host stack\n", HOST_STACK_SIZE_IN_PAGES));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	Cpu = (PCPU)((PCHAR)hostKernelStackBase + HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE - 8 - ALIGN_UP_BY(sizeof(CPU), 16));
	Cpu->HostStack = hostKernelStackBase;
	// for interrupt handlers which will address CPU through the FS
	Cpu->SelfPointer = Cpu;
	Cpu->ProcessorNumber = KeGetCurrentProcessorNumber();

	InitializeListHead(&Cpu->GeneralTrapsList);
	status = g_Hvm->ArchRegisterTraps(Cpu);
	if (!NT_SUCCESS(status)) {
		Trace(("HvmSubvertCpu: ArchRegisterTraps() failed with status 0x%08hX\n", status));
		return STATUS_UNSUCCESSFUL;
	}

	status = g_Hvm->ArchInitialize(Cpu, CmSlipIntoMatrix, GuestRsp);
	if (!NT_SUCCESS(status)) {
		Trace(("HvmSubvertCpu: ArchInitialize() failed with status 0x%08hX\n", status));
		return STATUS_UNSUCCESSFUL;
	}

	InterlockedIncrement(&g_uSubvertedCPUs);

	g_Hvm->ArchVirtualize(Cpu);


	//never reached
	InterlockedDecrement(&g_uSubvertedCPUs);
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS HvmLiberateCpu(PVOID Param)
{
	NTSTATUS status;
	if (KeGetCurrentIrql() != DISPATCH_LEVEL) {
		return STATUS_UNSUCCESSFUL;
	}

	status = HcMakeHypercall(NBP_HYPERCALL_UNLOAD, 0, NULL);
	if (!NT_SUCCESS(status)) {
		Trace(("HvmLiberateCpu(): HcMakeHypercall() failed on processor #%d, status 0x%08hX\n",
			KeGetCurrentProcessorNumber(), status));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

VOID HvmEventCallback(PCPU Cpu, PGUEST_REGS GuestRegs)
{
	NTSTATUS status;
	if (!Cpu || !GuestRegs) {
		return;
	}

	__vmx_vmread(GUEST_RSP, &GuestRegs->rsp);
	g_Hvm->ArchDispatchEvent(Cpu, GuestRegs);
	__vmx_vmwrite(GUEST_RSP, GuestRegs->rsp);
}

NTSTATUS HvmResumeGuest()
{
	Trace(("HvmResumeGuest(): Processor #%d, irql %d in GUEST\n", KeGetCurrentProcessorNumber(), KeGetCurrentIrql()));

	// irql will be lowered in the CmDeliverToProcessor()
	//CmSti();
	return STATUS_SUCCESS;
}

static NTSTATUS HvmSetupGdt(PCPU Cpu)
{

}