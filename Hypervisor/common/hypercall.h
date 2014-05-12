#ifndef _HYPERCALL_H
#define _HYPERCALL_H

#include "common.h"
#include "../vmx/vmx.h"

#define NBP_HYPERCALL_UNLOAD			0x1

NTSTATUS NTAPI HcMakeHypercall(
	ULONG32 HypercallNumber,
	ULONG32 HypercallParameter,
	PULONG32 pHypercallResult
	);

#endif