/*
 * hypervisor/tpm_virt.c
 *
 * TPM 2.0 virtualization via EPT-based MMIO interception.
 *
 * TPM 2.0 communication uses Memory-Mapped I/O (MMIO) at a fixed
 * physical address (typically 0xFED40000, 4KB). The TIS (TPM Interface
 * Specification) protocol involves:
 *   1. Writing a command buffer to the MMIO region
 *   2. Setting the TPM_STS.commandReady bit
 *   3. Polling TPM_STS.dataAvail
 *   4. Reading the response buffer
 *
 * We mark the TPM MMIO page as non-R/W/X in EPT. Every access
 * causes an EPT violation, allowing us to emulate or passthrough
 * TPM register accesses selectively:
 *
 *   - TPM2_CC_GetCapability: return spoofed TPM properties
 *   - TPM2_CC_ReadPublic: return a fake endorsement key (EK)
 *   - TPM2_CC_Certify: returns TPM_RC_FAILURE (cannot forge signatures)
 *   - All other commands: passthrough to real hardware
 *
 * LIMITATIONS (cannot be spoofed):
 *   - TPM2_CC_Certify, TPM2_CC_Quote: require real EK private key
 *   - PCR values: reflect actual boot chain, not spoofed
 *   - EK certificate chain: validation will fail with spoofed EK
 *   - Remote attestation: ACs using TPM attestation will detect spoofing
 */

#include "hv.h"
#include <intrin.h>

/* ─── MMIO passthrough — proxy real hardware when we don't emulate ──── */

static BOOLEAN TpmRealMmioRead(ULONG64 physAddr, ULONG size, PULONG64 outVal)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = physAddr;
    PVOID va = MmMapIoSpace(pa, size, MmNonCached);
    if (!va) return FALSE;
    if (size == 4)
        *outVal = *(volatile ULONG*)va;
    else
        *outVal = *(volatile ULONG64*)va;
    MmUnmapIoSpace(va, size);
    return TRUE;
}

static BOOLEAN TpmRealMmioWrite(ULONG64 physAddr, ULONG size, ULONG64 val)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = physAddr;
    PVOID va = MmMapIoSpace(pa, size, MmNonCached);
    if (!va) return FALSE;
    if (size == 4)
        *(volatile ULONG*)va = (ULONG)val;
    else
        *(volatile ULONG64*)va = val;
    MmUnmapIoSpace(va, size);
    return TRUE;
}

/* ─── TPM TIS register offsets ──────────────────────────────────────── */

#define TPM_BASE_ADDRESS     0xFED40000ULL
#define TPM_REGION_SIZE      0x5000

/* TIS register offsets (locality 0) */
#define TPM_ACCESS            0x0000
#define TPM_INT_ENABLE        0x0008
#define TPM_INT_VECTOR        0x000C
#define TPM_INT_STATUS        0x0010
#define TPM_INTF_CAP          0x0014
#define TPM_STS               0x0018
#define TPM_DATA_FIFO         0x0024
#define TPM_INTERFACE_ID      0x0030
#define TPM_XDATA_FIFO        0x0080
#define TPM_DID_VID           0x0F00
#define TPM_RID                0x0F04

/* TPM_STS bits */
#define TPM_STS_VALID          (1 << 7)
#define TPM_STS_COMMAND_READY  (1 << 6)
#define TPM_STS_GO             (1 << 5)
#define TPM_STS_DATA_AVAIL     (1 << 4)
#define TPM_STS_EXPECT         (1 << 3)
#define TPM_STS_SELFTEST_DONE  (1 << 2)
#define TPM_STS_RESPONSE_RETRY (1 << 1)

/* TPM2 command codes we intercept */
#define TPM2_CC_GET_CAPABILITY  0x0000017A
#define TPM2_CC_READ_PUBLIC     0x00000173
#define TPM2_CC_CERTIFY         0x00000148

/* TPM2 capabilities */
#define TPM_CAP_TPM_PROPERTIES  0x00000006
#define TPM_PT_MANUFACTURER     0x00000105
#define TPM_PT_VENDOR_STRING_1  0x00000106
#define TPM_PT_FIRMWARE_VERSION_1 0x00000111

/* ─── TPM virtualization state ──────────────────────────────────────── */

typedef enum _TPM_VIRT_STATE {
    TPM_STATE_IDLE,
    TPM_STATE_RECEPTION,
    TPM_STATE_EXECUTION,
    TPM_STATE_COMPLETION,
    TPM_STATE_PASSTHROUGH,  /* forwarding to real TPM hardware */
} TPM_VIRT_STATE;

typedef struct _TPM_VIRT {
    BOOLEAN         Active;
    TPM_VIRT_STATE  State;
    UCHAR           CommandBuffer[4096];
    ULONG           CommandLength;
    UCHAR           ResponseBuffer[4096];
    ULONG           ResponseLength;
    ULONG           ResponseOffset;
    BOOLEAN         Intercepted;

    /* Spoofed values */
    ULONG           FakeManufacturer;
    ULONG           FakeVendorString;
    ULONG           FakeFirmwareVer;
    UCHAR           FakeEkPublic[256];
    ULONG           FakeEkPublicLen;
} TPM_VIRT, *PTPM_VIRT;

static TPM_VIRT g_TpmVirt = { 0 };

/* ─── TPM command/response builders ─────────────────────────────────── */

static USHORT ReadBe16(PUCHAR p) { return (USHORT)((p[0] << 8) | p[1]); }
static ULONG  ReadBe32(PUCHAR p) { return (p[0] << 24)|(p[1] << 16)|(p[2] << 8)|p[3]; }

static VOID WriteBe16(PUCHAR p, USHORT v) { p[0]=(UCHAR)(v>>8); p[1]=(UCHAR)v; }
static VOID WriteBe32(PUCHAR p, ULONG v) {
    p[0]=(UCHAR)(v>>24); p[1]=(UCHAR)(v>>16); p[2]=(UCHAR)(v>>8); p[3]=(UCHAR)v;
}

/*
 * Build a spoofed GetCapability response.
 * TPM2 response header: tag(2) + size(4) + responseCode(4)
 * GetCapability response: moreData(1) + capability(4) + data...
 */
static VOID BuildFakeGetCapabilityResponse(
    ULONG capability, ULONG property, ULONG propertyCount)
{
    PUCHAR resp = g_TpmVirt.ResponseBuffer;
    ULONG offset = 0;

    WriteBe16(resp + offset, 0x8001); offset += 2;   /* TPM_ST_NO_SESSIONS */
    offset += 4; /* size placeholder */
    WriteBe32(resp + offset, 0); offset += 4;         /* TPM_RC_SUCCESS */
    resp[offset++] = 0;                                /* moreData = NO */
    WriteBe32(resp + offset, capability); offset += 4;

    if (capability == TPM_CAP_TPM_PROPERTIES) {
        ULONG count = 0;
        ULONG countOffset = offset;
        offset += 4; /* property count placeholder */

        if (property <= TPM_PT_MANUFACTURER && propertyCount > 0) {
            WriteBe32(resp + offset, TPM_PT_MANUFACTURER); offset += 4;
            WriteBe32(resp + offset, g_TpmVirt.FakeManufacturer); offset += 4;
            count++;
        }
        if (property <= TPM_PT_VENDOR_STRING_1 &&
            (property + propertyCount) > TPM_PT_VENDOR_STRING_1) {
            WriteBe32(resp + offset, TPM_PT_VENDOR_STRING_1); offset += 4;
            WriteBe32(resp + offset, g_TpmVirt.FakeVendorString); offset += 4;
            count++;
        }
        if (property <= TPM_PT_FIRMWARE_VERSION_1 &&
            (property + propertyCount) > TPM_PT_FIRMWARE_VERSION_1) {
            WriteBe32(resp + offset, TPM_PT_FIRMWARE_VERSION_1); offset += 4;
            WriteBe32(resp + offset, g_TpmVirt.FakeFirmwareVer); offset += 4;
            count++;
        }

        WriteBe32(resp + countOffset, count);
    }

    WriteBe32(resp + 2, offset); /* fill in total size */
    g_TpmVirt.ResponseLength = offset;
    g_TpmVirt.ResponseOffset = 0;
    g_TpmVirt.Intercepted = TRUE;
}

/*
 * Build a failure response for TPM2_CC_CERTIFY (attestation).
 * We cannot forge signatures — return error so real TPM is not used.
 */
static VOID BuildFakeCertifyFailure(VOID)
{
    PUCHAR resp = g_TpmVirt.ResponseBuffer;
    WriteBe16(resp + 0, 0x8001);
    WriteBe32(resp + 2, 10);       /* size */
    WriteBe32(resp + 6, 0x00000101); /* TPM_RC_FAILURE */
    g_TpmVirt.ResponseLength = 10;
    g_TpmVirt.ResponseOffset = 0;
    g_TpmVirt.Intercepted = TRUE;
}

/*
 * Build a spoofed ReadPublic response for the fake EK.
 */
static VOID BuildFakeReadPublicResponse(VOID)
{
    PUCHAR resp = g_TpmVirt.ResponseBuffer;
    ULONG offset = 0;

    WriteBe16(resp + offset, 0x8001); offset += 2;
    offset += 4; /* size placeholder */
    WriteBe32(resp + offset, 0); offset += 4; /* TPM_RC_SUCCESS */

    /* TPMT_PUBLIC: simplified — just output our fake EK bytes */
    WriteBe16(resp + offset, (USHORT)g_TpmVirt.FakeEkPublicLen); offset += 2;
    if (g_TpmVirt.FakeEkPublicLen > 0 && g_TpmVirt.FakeEkPublicLen <= 256) {
        RtlCopyMemory(resp + offset, g_TpmVirt.FakeEkPublic,
                       g_TpmVirt.FakeEkPublicLen);
        offset += g_TpmVirt.FakeEkPublicLen;
    }

    WriteBe32(resp + 2, offset);
    g_TpmVirt.ResponseLength = offset;
    g_TpmVirt.ResponseOffset = 0;
    g_TpmVirt.Intercepted = TRUE;
}

/* ─── Analyze submitted command and decide: intercept or passthrough ── */

static VOID TpmAnalyzeCommand(VOID)
{
    if (g_TpmVirt.CommandLength < 10) {
        g_TpmVirt.Intercepted = FALSE;
        return;
    }

    ULONG commandCode = ReadBe32(g_TpmVirt.CommandBuffer + 6);

    switch (commandCode) {
    case TPM2_CC_GET_CAPABILITY: {
        if (g_TpmVirt.CommandLength >= 22) {
            ULONG cap   = ReadBe32(g_TpmVirt.CommandBuffer + 10);
            ULONG prop  = ReadBe32(g_TpmVirt.CommandBuffer + 14);
            ULONG count = ReadBe32(g_TpmVirt.CommandBuffer + 18);
            if (cap == TPM_CAP_TPM_PROPERTIES) {
                BuildFakeGetCapabilityResponse(cap, prop, count);
                return;
            }
        }
        g_TpmVirt.Intercepted = FALSE;
        break;
    }
    case TPM2_CC_READ_PUBLIC:
        BuildFakeReadPublicResponse();
        break;

    case TPM2_CC_CERTIFY:
        /* Cannot forge attestation — return failure so real TPM identity
           is not exposed via attestation. */
        BuildFakeCertifyFailure();
        return;

    default:
        g_TpmVirt.Intercepted = FALSE;
        break;
    }
}

/* ─── EPT violation handler for TPM MMIO accesses ───────────────────── */

/*
 * Called from the EPT violation handler when the faulting physical
 * address falls within the TPM MMIO region.
 *
 * Returns TRUE if we handled it (emulated the access).
 * Returns FALSE if the access should be passed through to real hardware.
 */
BOOLEAN TpmVirt_HandleMmioAccess(
    ULONG64 physAddr,
    BOOLEAN isWrite,
    ULONG   accessSize,
    PULONG64 value)
{
    if (!g_TpmVirt.Active) return FALSE;

    ULONG offset = (ULONG)(physAddr - TPM_BASE_ADDRESS);

    /* Passthrough mode: proxy every access to real TPM hardware */
    if (g_TpmVirt.State == TPM_STATE_PASSTHROUGH) {
        if (isWrite) {
            if (*value & TPM_STS_COMMAND_READY && offset == TPM_STS)
                g_TpmVirt.State = TPM_STATE_RECEPTION;
            return TpmRealMmioWrite(physAddr, accessSize, *value);
        } else {
            if (!TpmRealMmioRead(physAddr, accessSize, value))
                *value = 0;
            return TRUE;
        }
    }

    if (isWrite) {
        switch (offset) {
        case TPM_STS:
            if (*value & TPM_STS_COMMAND_READY) {
                g_TpmVirt.State = TPM_STATE_RECEPTION;
                g_TpmVirt.CommandLength = 0;
                g_TpmVirt.Intercepted = FALSE;
            }
            if (*value & TPM_STS_GO) {
                g_TpmVirt.State = TPM_STATE_EXECUTION;
                TpmAnalyzeCommand();
                if (g_TpmVirt.Intercepted) {
                    g_TpmVirt.State = TPM_STATE_COMPLETION;
                } else {
                    /* Forward command to real TPM, then enter passthrough */
                    for (ULONG i = 0; i < g_TpmVirt.CommandLength; i++) {
                        ULONG64 b = g_TpmVirt.CommandBuffer[i];
                        TpmRealMmioWrite(TPM_BASE_ADDRESS + TPM_DATA_FIFO, 4, b);
                    }
                    TpmRealMmioWrite(physAddr, 4, *value);
                    g_TpmVirt.State = TPM_STATE_PASSTHROUGH;
                }
            }
            return TRUE;

        case TPM_DATA_FIFO:
            if (g_TpmVirt.State == TPM_STATE_RECEPTION &&
                g_TpmVirt.CommandLength < sizeof(g_TpmVirt.CommandBuffer)) {
                g_TpmVirt.CommandBuffer[g_TpmVirt.CommandLength++] =
                    (UCHAR)(*value & 0xFF);
            }
            return TRUE;

        default:
            return TpmRealMmioWrite(physAddr, accessSize, *value);
        }
    } else {
        /* Read access */
        switch (offset) {
        case TPM_STS:
            *value = TPM_STS_VALID;
            if (g_TpmVirt.State == TPM_STATE_RECEPTION)
                *value |= TPM_STS_COMMAND_READY | TPM_STS_EXPECT;
            else if (g_TpmVirt.State == TPM_STATE_COMPLETION &&
                     g_TpmVirt.Intercepted)
                *value |= TPM_STS_VALID | TPM_STS_DATA_AVAIL;
            return TRUE;

        case TPM_DATA_FIFO:
            if (g_TpmVirt.State == TPM_STATE_COMPLETION &&
                g_TpmVirt.Intercepted &&
                g_TpmVirt.ResponseOffset < g_TpmVirt.ResponseLength) {
                /* Simulate TPM response latency (~2–5 us) to match real hardware */
                if (g_TpmVirt.ResponseOffset == 0) {
                    ULONG64 t0 = __rdtsc();
                    while (__rdtsc() - t0 < 8000) { }
                }
                *value = g_TpmVirt.ResponseBuffer[g_TpmVirt.ResponseOffset++];
                if (g_TpmVirt.ResponseOffset >= g_TpmVirt.ResponseLength)
                    g_TpmVirt.State = TPM_STATE_IDLE;
            } else {
                *value = 0xFF;
            }
            return TRUE;

        case TPM_ACCESS:
            *value = 0xA1; /* tpmEstablishment + activeLocality + valid */
            return TRUE;

        case TPM_INTF_CAP:
            *value = 0x30; /* TIS 1.3, data transfer = FIFO */
            return TRUE;

        case TPM_DID_VID:
            *value = ((ULONG64)g_TpmVirt.FakeManufacturer << 16) | 0x0001;
            return TRUE;

        case TPM_INTERFACE_ID:
            *value = 0x00; /* FIFO interface */
            return TRUE;

        default:
            return TpmRealMmioRead(physAddr, accessSize, value);
        }
    }
}

/* ─── Initialize TPM virtualization ─────────────────────────────────── */

NTSTATUS TpmVirt_Init(VOID)
{
    RtlZeroMemory(&g_TpmVirt, sizeof(g_TpmVirt));

    /* Generate fake TPM identity */
    g_TpmVirt.FakeManufacturer = 0x494E5443; /* 'INTC' — Intel */
    g_TpmVirt.FakeVendorString = 0x494E5443;
    g_TpmVirt.FakeFirmwareVer  = 0x00070055; /* 7.85 */

    /* Generate random fake EK public key (256 bytes, RSA-2048) */
    extern VOID Util_RandomBytes(PUCHAR buf, ULONG len);
    Util_RandomBytes(g_TpmVirt.FakeEkPublic, 256);
    g_TpmVirt.FakeEkPublicLen = 256;
    /* Make it look like a valid RSA public exponent */
    g_TpmVirt.FakeEkPublic[0] = 0x00;
    g_TpmVirt.FakeEkPublic[1] = 0x01;

    if (!HvIsActive()) {
        /* Without hypervisor, we can't do MMIO interception.
           TPM virtualization requires EPT. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Mark TPM MMIO pages as non-accessible in EPT.
       Every access causes an EPT violation VM-exit → our handler. */
    ULONG64 tpmPhysBase = TPM_BASE_ADDRESS;
    BOOLEAN anyMarked = FALSE;
    for (ULONG pageOff = 0; pageOff < TPM_REGION_SIZE; pageOff += PAGE_SIZE) {
        NTSTATUS markSt = EptMarkPageNoAccess(tpmPhysBase + pageOff);
        if (NT_SUCCESS(markSt)) anyMarked = TRUE;
    }

    if (!anyMarked) return STATUS_UNSUCCESSFUL;

    g_TpmVirt.Active = TRUE;
    g_TpmVirt.State  = TPM_STATE_IDLE;

    return STATUS_SUCCESS;
}

VOID TpmVirt_Cleanup(VOID)
{
    if (!g_TpmVirt.Active) return;

    ULONG64 tpmPhysBase = TPM_BASE_ADDRESS;
    for (ULONG pageOff = 0; pageOff < TPM_REGION_SIZE; pageOff += PAGE_SIZE)
        EptRestorePageAccess(tpmPhysBase + pageOff);

    g_TpmVirt.Active = FALSE;
}

VOID TpmVirt_Regenerate(VOID)
{
    if (!g_TpmVirt.Active) return;

    /* Regenerate fake TPM identity for REGENERATE ioctl */
    extern VOID Util_RandomBytes(PUCHAR buf, ULONG len);
    UCHAR rnd[4];
    Util_RandomBytes(rnd, sizeof(rnd));
    g_TpmVirt.FakeManufacturer = 0x494E5443; /* 'INTC' — keep vendor, vary version */
    g_TpmVirt.FakeVendorString = 0x494E5443;
    g_TpmVirt.FakeFirmwareVer  = 0x00070000u | (rnd[0] << 8) | rnd[1];

    Util_RandomBytes(g_TpmVirt.FakeEkPublic, 256);
    g_TpmVirt.FakeEkPublicLen = 256;
    g_TpmVirt.FakeEkPublic[0] = 0x00;
    g_TpmVirt.FakeEkPublic[1] = 0x01;
}
