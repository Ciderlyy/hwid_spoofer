/*
 * driver/gpu_spoof.c
 *
 * GPU fingerprint spoofing via registry intercepts.
 *
 * ACs read GPU identifiers from registry keys under the display adapter
 * class GUID {4d36e968-e325-11ce-bfc1-08002be10318}.
 * We add these value names to the existing CmCallback intercept list
 * managed by registry_spoof.c.
 *
 * For Phase 3 (pre-hypervisor), this module generates fake GPU strings
 * and stores them in the config. The actual interception is handled by
 * the CmCallback in registry_spoof.c via new INTERCEPT_TYPE entries.
 *
 * Phase 5 will add EPT hooks on dxgkrnl!DxgkQueryAdapterInfo for the
 * D3DKMT API path.
 */

#include "driver.h"

NTSTATUS GpuSpoof_Init(VOID)
{
    if (!g_Driver.Config.SpoofGpu) return STATUS_SUCCESS;

    KIRQL irql = ExAcquireSpinLockExclusive(&g_Driver.ConfigLock);

    if (!g_Driver.Config.FakeGpuSerial[0]) {
        static const CHAR hex[] = "0123456789ABCDEF";
        UCHAR rnd[16];
        ULONG seed;
        Util_RandomBytes((PUCHAR)&seed, sizeof(seed));
        Util_RandomBytes(rnd, sizeof(rnd));
        for (ULONG i = 0; i < 16; i++) {
            g_Driver.Config.FakeGpuSerial[i * 2]     = hex[(rnd[i] >> 4) & 0xF];
            g_Driver.Config.FakeGpuSerial[i * 2 + 1] = hex[rnd[i] & 0xF];
        }
        g_Driver.Config.FakeGpuSerial[32] = '\0';
    }

    if (!g_Driver.Config.FakeGpuDescription[0]) {
        RtlStringCbCopyW(g_Driver.Config.FakeGpuDescription,
                         sizeof(g_Driver.Config.FakeGpuDescription),
                         L"NVIDIA GeForce RTX 4070");
    }

    ExReleaseSpinLockExclusive(&g_Driver.ConfigLock, irql);

    TRACE("[VolFlt] GPU spoof initialized\n");
    return STATUS_SUCCESS;
}

VOID GpuSpoof_Cleanup(VOID)
{
    /* Nothing to clean up — registry intercepts handled by CmCallback */
}
