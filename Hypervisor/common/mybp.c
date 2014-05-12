#include "mybp.h"
#include "memory.h"
#include "hvm.h"

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	status = HvmSpitOutBluepill();
	if (!NT_SUCCESS(status)) {
		Trace(("DriverUnload : HvmSplitOutBluepill() failed with status 0x%08hX\n", status));
	}

	MmShutdownManager();

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	status = MmInitManager();
	if (!NT_SUCCESS(status)) {
		Trace(("DriverEntry : MmInitManager() failed with status 0x%08hX\n", status));
		return status;
	}

	status = HvmInit();
	if (!NT_SUCCESS(status)) {
		Trace(("DriverEntry : HvmInit() failed with status 0x%08hX\n", status));
		MmShutdownManager();
		return status;
	}

	status = HvmSwallowBluepill();
	if (!NT_SUCCESS(status)) {
		Trace(("DriverEntry : HvmSwallowBluepill() failed with status 0x%08hX\n", status));
		MmShutdownManager();
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;
	Trace(("DriverEntry: Initialization finished\n"));

	return STATUS_SUCCESS;
}

