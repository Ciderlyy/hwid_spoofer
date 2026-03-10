/*
 * hypervisor/vmexits.c
 *
 * EPT violation sub-handler: dispatches to the appropriate hook
 * when an EPT violation occurs on a hooked page.
 *
 * Implements the execute/read-write split:
 *   - On instruction fetch: swap PTE to shadow page (hooked JMP)
 *   - On data read/write: swap PTE back to original (clean bytes)
 *   - INVEPT after every swap so the TLB doesn't cache stale mappings
 */

#include "hv.h"
#include <intrin.h>

extern ULONG64 AsmInvept(ULONG64 type, PVOID descriptor);
extern EPT_SPLIT_PAGE* g_SplitPages[];
extern ULONG g_SplitPageCount;

static VOID InveptSingleContext(VOID)
{
    struct { ULONG64 Eptp; ULONG64 Reserved; } desc;
    desc.Eptp = g_Hv.Ept->EptPointer;
    desc.Reserved = 0;
    AsmInvept(1, &desc);
}

/* ─── EPT violation sub-handler ─────────────────────────────────────── */

BOOLEAN HandleEptViolation(ULONG64 qualification, ULONG64 guestPhysical)
{
    BOOLEAN isExec  = (qualification & (1ULL << 2)) != 0;

    ULONG64 faultPage = guestPhysical & ~0xFFFULL;

    for (ULONG i = 0; i < g_Hv.HookCount; i++) {
        EPT_HOOK_ENTRY* hook = &g_Hv.Hooks[i];
        if (!hook->Active) continue;

        ULONG64 hookPage = hook->TargetPa & ~0xFFFULL;
        if (faultPage != hookPage) continue;

        ULONG pdptIdx = (ULONG)((guestPhysical >> 30) & 0x1FF);
        ULONG pdIdx   = (ULONG)((guestPhysical >> 21) & 0x1FF);
        ULONG ptIdx   = (ULONG)((guestPhysical >> 12) & 0x1FF);

        PEPT_PTE pte = NULL;
        for (ULONG j = 0; j < g_SplitPageCount; j++) {
            if (g_SplitPages[j]->PdptIndex == pdptIdx &&
                g_SplitPages[j]->PdIndex == pdIdx) {
                pte = &g_SplitPages[j]->Pte[ptIdx];
                break;
            }
        }
        if (!pte) return FALSE;

        if (isExec) {
            /* Instruction fetch: swap to shadow page (execute-only) */
            pte->PageFrameNumber = hook->ShadowPa >> 12;
            pte->Read    = 0;
            pte->Write   = 0;
            pte->Execute = 1;
        } else {
            /* Data access: swap to original page (R/W only) */
            pte->PageFrameNumber = (hook->TargetPa & ~0xFFFULL) >> 12;
            pte->Read    = 1;
            pte->Write   = 1;
            pte->Execute = 0;
        }

        InveptSingleContext();
        return TRUE;
    }

    return FALSE;
}
