#include "common.h"

BOOLEAN CmIsBitSet(ULONG64 v, UCHAR bitNo)
{
	//ULONG64 mask = (ULONG64)1 << bitNo;
	return (BOOLEAN)(_bittest64(&v, bitNo) != 0);
}

NTSTATUS CmDeliverToProcessor(
	CCHAR activeProcessors,
	PCALLBACK_PROC CallbackProc,
	PVOID CallbackParam,
	PNTSTATUS pCallbackStatus
)
{
	NTSTATUS CallbackStatus;
	KIRQL OldIrql;

	if (!CallbackProc)
		return STATUS_INVALID_PARAMETER;

	if (pCallbackStatus)
		*pCallbackStatus = STATUS_UNSUCCESSFUL;

	KeSetSystemAffinityThread((KAFFINITY)(1 << activeProcessors));

	OldIrql = KeRaiseIrqlToDpcLevel();
	CallbackStatus = CallbackProc(CallbackParam);
	KeLowerIrql(OldIrql);

	KeRevertToUserAffinityThread();

	// save the status of the callback which has run on the current core
	if (pCallbackStatus)
		*pCallbackStatus = CallbackStatus;

	return STATUS_SUCCESS;
}

NTSTATUS CmInitializeSegmentSelector(
	SEGMENT_SELECTOR * SegmentSelector,
	USHORT Selector,
	PUCHAR GdtBase
)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return STATUS_INVALID_PARAMETER;

	if (Selector & 0x4) {
		Trace(("CmInitializeSegmentSelector: Given selector (0x%X) points to LDT\n", Selector));
		return STATUS_INVALID_PARAMETER;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->sel = Selector;
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	if (!(SegDesc->attr0 & LA_STANDARD)) {
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->attributes.fields.g) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}

NTSTATUS CmSetGdtEntry(
	PSEGMENT_DESCRIPTOR GdtBase,
	ULONG GdtLimit,
	ULONG SelectorNumber,
	PVOID SegmentBase,
	ULONG SegmentLimit,
	UCHAR LowAttributes,
	UCHAR HighAttributes
)
{
	SEGMENT_DESCRIPTOR Descriptor = { 0 };

	if (!GdtBase || SelectorNumber > GdtLimit || (SelectorNumber & 0x07))
		return STATUS_INVALID_PARAMETER;

	Descriptor.limit0 = (USHORT)(SegmentLimit & 0xffff);
	Descriptor.base0 = (USHORT)((ULONG64)SegmentBase & 0xffff);
	Descriptor.base1 = (UCHAR)(((ULONG64)SegmentBase >> 16) & 0xff);
	Descriptor.base2 = (UCHAR)(((ULONG64)SegmentBase >> 24) & 0xff);
	Descriptor.attr0 = LowAttributes;
	Descriptor.limit1attr1 = (UCHAR)((HighAttributes << 4) + (SegmentLimit >> 16));

	GdtBase[SelectorNumber >> 3] = Descriptor;

	if (!(LowAttributes & LA_STANDARD)) {
		// this is a TSS or callgate etc, save the base high part
		*(PULONG64)(((PUCHAR)GdtBase) + SelectorNumber + 8) = ((ULONG64)SegmentBase) >> 32;
	}

	return STATUS_SUCCESS;
}