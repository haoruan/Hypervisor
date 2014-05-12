#ifndef _MEMORY_H
#define _MEMORY_H

#include "common.h"

#define ITL_TAG	'LTI'

typedef struct _ALLOCATED_MEM
{

	LIST_ENTRY le;

	//ULONG Flags;

	//PAGE_ALLOCATION_TYPE AllocationType;
	//ULONG uNumberOfPages;         // for PAT_CONTIGUOUS only

	//PHYSICAL_ADDRESS PhysicalAddress;
	//PVOID HostAddress;
	PVOID GuestAddress;

} ALLOCATED_MEM, *PALLOCATED_MEM;

NTSTATUS MmInitManager();

static NTSTATUS MmSaveInfo(
	//PHYSICAL_ADDRESS PhysicalAddress,
	//PVOID HostAddress,
	PVOID GuestAddress
	//PAGE_ALLOCATION_TYPE AllocationType,
	//ULONG uNumberOfPages,
	//ULONG Flags
);
PVOID MmAllocate(SIZE_T numberOfBytes);
NTSTATUS MmShutdownManager();

#endif