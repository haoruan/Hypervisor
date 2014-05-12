#include "hypercall.h"

NTSTATUS NTAPI HcMakeHypercall(
	ULONG32 HypercallNumber,
	ULONG32 HypercallParameter,
	PULONG32 pHypercallResult
	)
{
	VmxVmCall(HypercallNumber);
	return STATUS_SUCCESS;
}