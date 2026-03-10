/*
 * hypervisor/ept.c
 *
 * EPT (Extended Page Table) management and hook infrastructure.
 * Implements the split-page technique for invisible code hooking:
 *   - Execute permission → shadow page (hooked code)
 *   - Read/Write permission → original page (clean bytes)
 *   - Integrity scans see unmodified code; execution hits our hooks
 */

#include "hv.h"
#include <intrin.h>

extern ULONG64 AsmInvept(ULONG64 type, PVOID descriptor);

/* ─── 4KB page table for split pages ────────────────────────────────── */

EPT_SPLIT_PAGE* g_SplitPages[MAX_SPLIT_PAGES] = { 0 };
ULONG g_SplitPageCount = 0;

/* ─── Invalidate EPT TLB ───────────────────────────────────────────── */

static VOID EptInvalidate(VOID)
{
    struct { ULONG64 Eptp; ULONG64 Reserved; } desc;
    desc.Eptp = g_Hv.Ept->EptPointer;
    desc.Reserved = 0;
    AsmInvept(1, &desc); /* type 1 = single-context */
}

/* ─── Split a 2MB page into 512 × 4KB entries ──────────────────────── */

static NTSTATUS EptSplitLargePage(ULONG pdptIdx, ULONG pdIdx)
{
    if (g_SplitPageCount >= MAX_SPLIT_PAGES)
        return STATUS_INSUFFICIENT_RESOURCES;

    PEPT_PDE pde = &g_Hv.Ept->Pd[pdptIdx][pdIdx];
    if (!pde->LargePage)
        return STATUS_SUCCESS;

    PEPT_SPLIT_PAGE split = (PEPT_SPLIT_PAGE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EPT_SPLIT_PAGE), 'EpSp');
    if (!split) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(split, sizeof(EPT_SPLIT_PAGE));

    split->PdIndex   = pdIdx;
    split->PdptIndex = pdptIdx;

    ULONG64 basePhys = ((ULONG64)pdptIdx * 512 + pdIdx) * (2ULL * 1024 * 1024);

    for (ULONG i = 0; i < 512; i++) {
        split->Pte[i].Read           = 1;
        split->Pte[i].Write          = 1;
        split->Pte[i].Execute        = 1;
        split->Pte[i].MemoryType     = 6;
        split->Pte[i].PageFrameNumber = (basePhys + (ULONG64)i * PAGE_SIZE) >> 12;
    }

    PHYSICAL_ADDRESS ptePa = MmGetPhysicalAddress(&split->Pte[0]);
    pde->Value = 0;
    pde->Read           = 1;
    pde->Write          = 1;
    pde->Execute        = 1;
    pde->LargePage      = 0;
    pde->PageFrameNumber = ptePa.QuadPart >> 12;

    g_SplitPages[g_SplitPageCount++] = split;
    return STATUS_SUCCESS;
}

/* ─── Find the PTE for a given physical address ─────────────────────── */

PEPT_PTE EptFindPte(ULONG64 physAddr)
{
    ULONG pdptIdx = (ULONG)((physAddr >> 30) & 0x1FF);
    ULONG pdIdx   = (ULONG)((physAddr >> 21) & 0x1FF);
    ULONG ptIdx   = (ULONG)((physAddr >> 12) & 0x1FF);

    PEPT_PDE pde = &g_Hv.Ept->Pd[pdptIdx][pdIdx];
    if (pde->LargePage) {
        NTSTATUS st = EptSplitLargePage(pdptIdx, pdIdx);
        if (!NT_SUCCESS(st)) return NULL;
    }

    for (ULONG i = 0; i < g_SplitPageCount; i++) {
        if (g_SplitPages[i]->PdptIndex == pdptIdx &&
            g_SplitPages[i]->PdIndex == pdIdx)
            return &g_SplitPages[i]->Pte[ptIdx];
    }
    return NULL;
}

/* ─── Build an executable trampoline ────────────────────────────────── */

/*
 * Allocates executable non-paged memory containing:
 *   [original first 14 bytes] + [JMP to original+14]
 * This lets the hook handler call through to the original function.
 */
static PVOID BuildTrampoline(PVOID targetFunction, PUCHAR savedBytes)
{
    PUCHAR tramp = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, 32, 'EpTr');
    if (!tramp) return NULL;

    /* Copy saved original bytes (14 bytes) */
    RtlCopyMemory(tramp, savedBytes, 14);

    /* JMP [rip+0] <original + 14>  — 14 bytes */
    tramp[14] = 0xFF;
    tramp[15] = 0x25;
    *(PULONG)(tramp + 16) = 0;
    *(PULONG64)(tramp + 20) = (ULONG64)targetFunction + 14;

    return tramp;
}

/* ─── Install EPT hook (split-page technique) ───────────────────────── */

NTSTATUS HvInstallEptHook(
    _In_ PVOID  TargetFunction,
    _In_ PVOID  HookFunction,
    _Out_ PVOID* OriginalTrampoline)
{
    if (!g_Hv.Active) return STATUS_UNSUCCESSFUL;
    if (g_Hv.HookCount >= MAX_HOOK_COUNT) return STATUS_INSUFFICIENT_RESOURCES;

    PHYSICAL_ADDRESS targetPa = MmGetPhysicalAddress(TargetFunction);
    if (targetPa.QuadPart == 0) return STATUS_INVALID_PARAMETER;

    PVOID shadowPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'EpSh');
    if (!shadowPage) return STATUS_INSUFFICIENT_RESOURCES;

    PVOID pageBase = (PVOID)((ULONG_PTR)TargetFunction & ~0xFFF);
    RtlCopyMemory(shadowPage, pageBase, PAGE_SIZE);

    ULONG offset = (ULONG)((ULONG_PTR)TargetFunction & 0xFFF);
    UCHAR savedBytes[14];
    RtlCopyMemory(savedBytes, (PUCHAR)shadowPage + offset, 14);

    PVOID trampoline = BuildTrampoline(TargetFunction, savedBytes);
    if (!trampoline) {
        ExFreePoolWithTag(shadowPage, 'EpSh');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Patch shadow page: JMP [rip+0] <hookFunction> at target offset */
    PUCHAR hookSite = (PUCHAR)shadowPage + offset;
    hookSite[0] = 0xFF;
    hookSite[1] = 0x25;
    *(PULONG)(hookSite + 2) = 0;
    *(PULONG64)(hookSite + 6) = (ULONG64)HookFunction;

    PHYSICAL_ADDRESS shadowPa = MmGetPhysicalAddress(shadowPage);

    PEPT_PTE pte = EptFindPte(targetPa.QuadPart);
    if (!pte) {
        ExFreePoolWithTag(shadowPage, 'EpSh');
        ExFreePoolWithTag(trampoline, 'EpTr');
        return STATUS_UNSUCCESSFUL;
    }

    /* Record the hook under lock */
    KIRQL irql = ExAcquireSpinLockExclusive(&g_Hv.HookLock);
    EPT_HOOK_ENTRY* entry = &g_Hv.Hooks[g_Hv.HookCount];
    entry->TargetVa     = TargetFunction;
    entry->TargetPa     = targetPa.QuadPart;
    entry->HookFunction = HookFunction;
    entry->ShadowPage   = shadowPage;
    entry->ShadowPa     = shadowPa.QuadPart;
    entry->OriginalBytes = trampoline;
    entry->Active        = TRUE;
    g_Hv.HookCount++;
    ExReleaseSpinLockExclusive(&g_Hv.HookLock, irql);

    /* R/W only — no execute. Exec triggers EPT violation → shadow swap. */
    pte->Execute = 0;

    EptInvalidate();

    *OriginalTrampoline = trampoline;
    return STATUS_SUCCESS;
}

NTSTATUS HvRemoveEptHook(_In_ PVOID TargetFunction)
{
    if (!g_Hv.Active) return STATUS_UNSUCCESSFUL;

    KIRQL irql = ExAcquireSpinLockExclusive(&g_Hv.HookLock);

    for (ULONG i = 0; i < g_Hv.HookCount; i++) {
        if (g_Hv.Hooks[i].TargetVa == TargetFunction && g_Hv.Hooks[i].Active) {
            g_Hv.Hooks[i].Active = FALSE;

            PEPT_PTE pte = EptFindPte(g_Hv.Hooks[i].TargetPa);
            if (pte) {
                pte->Execute = 1;
                pte->Read    = 1;
                pte->Write   = 1;
                pte->PageFrameNumber = (g_Hv.Hooks[i].TargetPa & ~0xFFFULL) >> 12;
            }

            if (g_Hv.Hooks[i].ShadowPage)
                ExFreePoolWithTag(g_Hv.Hooks[i].ShadowPage, 'EpSh');
            if (g_Hv.Hooks[i].OriginalBytes)
                ExFreePoolWithTag(g_Hv.Hooks[i].OriginalBytes, 'EpTr');

            ExReleaseSpinLockExclusive(&g_Hv.HookLock, irql);
            EptInvalidate();
            return STATUS_SUCCESS;
        }
    }

    ExReleaseSpinLockExclusive(&g_Hv.HookLock, irql);
    return STATUS_NOT_FOUND;
}

/* ─── Mark a physical page non-accessible (for MMIO interception) ──── */

NTSTATUS EptMarkPageNoAccess(ULONG64 physAddr)
{
    PEPT_PTE pte = EptFindPte(physAddr);
    if (!pte) return STATUS_UNSUCCESSFUL;
    pte->Read    = 0;
    pte->Write   = 0;
    pte->Execute = 0;
    EptInvalidate();
    return STATUS_SUCCESS;
}

NTSTATUS EptRestorePageAccess(ULONG64 physAddr)
{
    PEPT_PTE pte = EptFindPte(physAddr);
    if (!pte) return STATUS_UNSUCCESSFUL;
    pte->Read    = 1;
    pte->Write   = 1;
    pte->Execute = 1;
    EptInvalidate();
    return STATUS_SUCCESS;
}

/* ─── EPT cleanup ───────────────────────────────────────────────────── */

VOID EptCleanup(VOID)
{
    for (ULONG i = 0; i < g_SplitPageCount; i++) {
        if (g_SplitPages[i])
            ExFreePoolWithTag(g_SplitPages[i], 'EpSp');
    }
    g_SplitPageCount = 0;

    for (ULONG i = 0; i < g_Hv.HookCount; i++) {
        if (g_Hv.Hooks[i].ShadowPage)
            ExFreePoolWithTag(g_Hv.Hooks[i].ShadowPage, 'EpSh');
        if (g_Hv.Hooks[i].OriginalBytes)
            ExFreePoolWithTag(g_Hv.Hooks[i].OriginalBytes, 'EpTr');
    }
}
