#include "memory.h"

static LIST_ENTRY g_PageTableList;
static KSPIN_LOCK g_PageTableListLock;

NTSTATUS MmInitManager() {
	InitializeListHead(&g_PageTableList);
	KeInitializeSpinLock(&g_PageTableListLock);

	return STATUS_SUCCESS;
}

static NTSTATUS MmSaveInfo(
	//PHYSICAL_ADDRESS PhysicalAddress,
	//PVOID HostAddress,
	PVOID GuestAddress
	//PAGE_ALLOCATION_TYPE AllocationType,
	//ULONG uNumberOfPages,
	//ULONG Flags
	) {
	PALLOCATED_MEM allocatedMem;

	if (!GuestAddress) {
		return STATUS_INVALID_PARAMETER;
	}

	allocatedMem = ExAllocatePoolWithTag(NonPagedPool, sizeof(ALLOCATED_MEM), ITL_TAG);
	if (!allocatedMem) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(allocatedMem, sizeof(ALLOCATED_MEM));
	allocatedMem->GuestAddress = GuestAddress;

	ExInterlockedInsertTailList(&g_PageTableList, &allocatedMem->le, &g_PageTableListLock);

	return STATUS_SUCCESS;
}

PVOID MmAllocate(SIZE_T numberOfBytes) {
	PVOID pBlock;
	NTSTATUS status;

	pBlock = ExAllocatePoolWithTag(NonPagedPool, numberOfBytes, ITL_TAG);
	if (!pBlock) {
		return NULL;
	}
	RtlZeroMemory(pBlock, numberOfBytes);

	status = MmSaveInfo(pBlock);
	if (!NT_SUCCESS(status)) {
		Trace("MmAllocate : MmSaveInfo() failed with status 0x%08X\n", status);
		return NULL;
	}
	
	return pBlock;
}

NTSTATUS MmShutdownManager() {
	PALLOCATED_MEM allocatedMem;
	PLIST_ENTRY pLe;
	while (pLe = ExInterlockedRemoveHeadList(&g_PageTableList, &g_PageTableListLock)) {
		allocatedMem = CONTAINING_RECORD(pLe, ALLOCATED_MEM, le);
		ExFreePoolWithTag(allocatedMem->GuestAddress, ITL_TAG);
		ExFreePoolWithTag(allocatedMem, ITL_TAG);
	}

	return STATUS_SUCCESS;
}