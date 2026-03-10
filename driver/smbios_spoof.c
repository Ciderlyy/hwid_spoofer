/*
 * driver/smbios_spoof.c
 *
 * SMBIOS firmware table in-memory patching.
 *
 * Strategy: at boot-start DriverEntry time, call ZwQuerySystemInformation
 * with SystemFirmwareTableInformation to get the raw SMBIOS data, then
 * locate the kernel's cached copy by scanning ntoskrnl's data sections
 * for the same byte pattern, and patch the serial / UUID strings in-place.
 *
 * This runs before any AC driver can snapshot the real values.
 */

#include "driver.h"
#include "smbios_spoof.h"

/* ─── SMBIOS structure definitions ──────────────────────────────────── */

#define SMBIOS_TYPE_BIOS       0
#define SMBIOS_TYPE_SYSTEM     1
#define SMBIOS_TYPE_BASEBOARD  2
#define SMBIOS_TYPE_CHASSIS    3
#define SMBIOS_TYPE_END_OF_TABLE 127

#pragma pack(push, 1)
typedef struct _SMBIOS_HEADER {
    UCHAR  Type;
    UCHAR  Length;
    USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _RAW_SMBIOS_DATA {
    UCHAR  Used20CallingMethod;
    UCHAR  SMBIOSMajorVersion;
    UCHAR  SMBIOSMinorVersion;
    UCHAR  DmiRevision;
    ULONG  Length;
    UCHAR  SMBIOSTableData[1];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

/* SystemFirmwareTableInformation for ZwQuerySystemInformation */
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG  ProviderSignature;
    ULONG  Action;
    ULONG  TableID;
    ULONG  TableBufferLength;
    UCHAR  TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

#define SYSTEM_FIRMWARE_TABLE_GET 1
#define SystemFirmwareTableInformation 76
#pragma pack(pop)

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      ULONG  SystemInformationClass,
    _Inout_   PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

/* ─── SMBIOS string helpers ─────────────────────────────────────────── */

/*
 * SMBIOS strings are stored as a double-NUL-terminated list after the
 * formatted portion of each structure.  String index 1 = first string.
 */
static PUCHAR SmbiosGetStringPtr(PSMBIOS_HEADER hdr, UCHAR stringIndex)
{
    if (stringIndex == 0) return NULL;
    PUCHAR p = (PUCHAR)hdr + hdr->Length;
    for (UCHAR cur = 1; cur < stringIndex; cur++) {
        while (*p) p++;
        p++;
        if (*p == 0) return NULL;
    }
    return p;
}

static PUCHAR SmbiosNextStructure(PSMBIOS_HEADER hdr)
{
    PUCHAR p = (PUCHAR)hdr + hdr->Length;
    while (!(p[0] == 0 && p[1] == 0)) p++;
    return p + 2;
}

static VOID SmbiosPatchString(PUCHAR strPtr, const CHAR* fake, ULONG maxLen)
{
    if (!strPtr || !fake || !fake[0]) return;
    ULONG origLen = 0;
    while (strPtr[origLen]) origLen++;
    ULONG fakeLen = (ULONG)strlen(fake);
    ULONG copyLen = (fakeLen < origLen) ? fakeLen : origLen;
    if (copyLen > maxLen) copyLen = maxLen;
    RtlCopyMemory(strPtr, fake, copyLen);
    if (copyLen < origLen)
        RtlFillMemory(strPtr + copyLen, origLen - copyLen, ' ');
}

/* ─── Patch UUID in Type 1 (System Information) ─────────────────────── */

static VOID SmbiosPatchUuid(PUCHAR uuidField, const CHAR* fakeUuidStr)
{
    if (!uuidField || !fakeUuidStr || !fakeUuidStr[0]) return;
    UCHAR uuid[16] = { 0 };
    ULONG idx = 0;
    const CHAR* s = fakeUuidStr;
    while (*s && idx < 16) {
        if (*s == '-') { s++; continue; }
        UCHAR hi = 0, lo = 0;
        if (s[0] >= '0' && s[0] <= '9') hi = (UCHAR)(s[0] - '0');
        else if (s[0] >= 'a' && s[0] <= 'f') hi = (UCHAR)(s[0] - 'a' + 10);
        else if (s[0] >= 'A' && s[0] <= 'F') hi = (UCHAR)(s[0] - 'A' + 10);
        if (s[1] >= '0' && s[1] <= '9') lo = (UCHAR)(s[1] - '0');
        else if (s[1] >= 'a' && s[1] <= 'f') lo = (UCHAR)(s[1] - 'a' + 10);
        else if (s[1] >= 'A' && s[1] <= 'F') lo = (UCHAR)(s[1] - 'A' + 10);
        uuid[idx++] = (UCHAR)((hi << 4) | lo);
        s += 2;
    }
    RtlCopyMemory(uuidField, uuid, 16);
}

/* ─── Main table patching ───────────────────────────────────────────── */

VOID PatchSmbiosTable(PUCHAR tableData, ULONG tableLen)
{
    PUCHAR end = tableData + tableLen;
    PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)tableData;

    while ((PUCHAR)hdr + sizeof(SMBIOS_HEADER) <= end &&
           hdr->Type != SMBIOS_TYPE_END_OF_TABLE) {

        switch (hdr->Type) {
        case SMBIOS_TYPE_BIOS: {
            /* Type 0: string index 4 = BIOS serial (if Length >= 0x18) */
            if (hdr->Length >= 0x18 && g_Driver.Config.FakeBiosSerial[0]) {
                PUCHAR data = (PUCHAR)hdr;
                UCHAR serialIdx = data[0x17];
                if (serialIdx)
                    SmbiosPatchString(SmbiosGetStringPtr(hdr, serialIdx),
                                      g_Driver.Config.FakeBiosSerial, 63);
            }
            break;
        }
        case SMBIOS_TYPE_SYSTEM: {
            /* Type 1: offset 0x04 = Manufacturer(1), 0x05 = Product(2),
               0x06 = Version(3), 0x07 = SerialNumber(4), 0x08 = UUID(16 bytes) */
            if (hdr->Length >= 0x19) {
                PUCHAR data = (PUCHAR)hdr;
                UCHAR serialIdx = data[0x07];
                const CHAR* sysSerial = g_Driver.Config.FakeSystemSerial[0]
                    ? g_Driver.Config.FakeSystemSerial
                    : g_Driver.Config.FakeBoardSerial;
                if (serialIdx && sysSerial[0])
                    SmbiosPatchString(SmbiosGetStringPtr(hdr, serialIdx),
                                      sysSerial, 63);
                if (g_Driver.Config.FakeSystemUuid[0])
                    SmbiosPatchUuid(data + 0x08, g_Driver.Config.FakeSystemUuid);
            }
            break;
        }
        case SMBIOS_TYPE_BASEBOARD: {
            /* Type 2: offset 0x07 = SerialNumber(string index) */
            if (hdr->Length >= 0x08) {
                PUCHAR data = (PUCHAR)hdr;
                UCHAR serialIdx = data[0x07];
                if (serialIdx && g_Driver.Config.FakeBoardSerial[0])
                    SmbiosPatchString(SmbiosGetStringPtr(hdr, serialIdx),
                                      g_Driver.Config.FakeBoardSerial, 63);
            }
            break;
        }
        case SMBIOS_TYPE_CHASSIS: {
            /* Type 3: offset 0x07 = SerialNumber(string index) */
            if (hdr->Length >= 0x08) {
                PUCHAR data = (PUCHAR)hdr;
                UCHAR serialIdx = data[0x07];
                if (serialIdx && g_Driver.Config.FakeChassisSerial[0])
                    SmbiosPatchString(SmbiosGetStringPtr(hdr, serialIdx),
                                      g_Driver.Config.FakeChassisSerial, 63);
            }
            break;
        }
        }

        PUCHAR next = SmbiosNextStructure(hdr);
        if (next >= end) break;
        hdr = (PSMBIOS_HEADER)next;
    }
}

/* ─── ACPI table patching (FACS HardwareSignature, etc.) ─────────────── */

#define ACPI_TABLE_FACS 0x53434146  /* 'SCAF' little-endian */
#define FACS_HARDWARE_SIGNATURE_OFFSET 32

VOID PatchAcpiTable(ULONG tableId, PUCHAR tableData, ULONG tableLen)
{
    if (!tableData || tableLen < 36) return;

    if (tableId == ACPI_TABLE_FACS && tableLen >= FACS_HARDWARE_SIGNATURE_OFFSET + 8) {
        /* FACS HardwareSignature: 64-bit value at offset 32 */
        if (g_Driver.Config.SpoofSmbios && g_Driver.Config.FakeBoardSerial[0]) {
            ULONG64 sig = 0;
            for (ULONG i = 0; i < 8 && g_Driver.Config.FakeBoardSerial[i]; i++)
                sig = (sig << 8) | (UCHAR)g_Driver.Config.FakeBoardSerial[i];
            *(PULONG64)(tableData + FACS_HARDWARE_SIGNATURE_OFFSET) = sig;
        }
    }
}

/* ─── Kernel SMBIOS cache discovery and patching ────────────────────── */

/*
 * Find the SMBIOS table cached by the kernel by calling
 * ZwQuerySystemInformation(SystemFirmwareTableInformation) and then
 * searching ntoskrnl data pages for the raw table signature.
 */

static PVOID  g_PatchedAddress = NULL;
static ULONG  g_PatchedLength  = 0;

NTSTATUS SmbiosSpoof_Init(VOID)
{
    if (!g_Driver.Config.SpoofSmbios) return STATUS_SUCCESS;

    /* Step 1: Query raw SMBIOS data size */
    SYSTEM_FIRMWARE_TABLE_INFORMATION query = { 0 };
    query.ProviderSignature = 'RSMB';
    query.Action = SYSTEM_FIRMWARE_TABLE_GET;
    query.TableID = 0;

    ULONG needed = 0;
    NTSTATUS st = ZwQuerySystemInformation(SystemFirmwareTableInformation,
                                           &query, sizeof(query), &needed);
    if (st != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(st))
        return st;

    ULONG allocSize = needed + 256;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION buf =
        (PSYSTEM_FIRMWARE_TABLE_INFORMATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, allocSize, POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    buf->ProviderSignature = 'RSMB';
    buf->Action = SYSTEM_FIRMWARE_TABLE_GET;
    buf->TableID = 0;
    buf->TableBufferLength = allocSize - FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    st = ZwQuerySystemInformation(SystemFirmwareTableInformation,
                                  buf, allocSize, &needed);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(buf, POOL_TAG);
        return st;
    }

    /* Step 2: Get the raw SMBIOS data from the returned buffer.
       The TableBuffer contains a RAW_SMBIOS_DATA header followed by the
       actual SMBIOS structures. */
    PRAW_SMBIOS_DATA raw = (PRAW_SMBIOS_DATA)buf->TableBuffer;
    if (raw->Length == 0 || raw->Length > 0x10000) {
        ExFreePoolWithTag(buf, POOL_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    /* Step 3: Patch the raw table data in our buffer copy first.
       Then search kernel memory for the original and patch it too. */
    PatchSmbiosTable(raw->SMBIOSTableData, raw->Length);

    /*
     * Step 4: The kernel caches SMBIOS data in a pool allocation.
     * We can't reliably find it by scanning all of kernel memory.
     * Instead, we use the fact that ZwQuerySystemInformation copies
     * from the kernel's internal buffer — if we call it again, it
     * returns the same data. By patching our copy and then finding
     * the original via signature matching in the kernel modules,
     * we can patch it.
     *
     * For boot-start timing, our patched copy in the output buffer
     * IS the data the system returns. The simplest safe approach:
     * call ZwQuerySystemInformation repeatedly — the kernel's buffer
     * is the same physical allocation each time.
     *
     * Alternative: scan MmSystemRangeStart..MmHighestUserAddress
     * for the raw SMBIOS anchor bytes.
     *
     * For the research tool, we'll scan non-paged pool for the
     * SMBIOS signature pattern and patch it in place.
     */

    /* Search for the kernel's cached raw SMBIOS table.
       The table starts with the SMBIOS header bytes (version, length)
       which are unlikely to appear elsewhere in pool memory. */
    PUCHAR signature = (PUCHAR)raw;
    ULONG  sigLen    = 8; /* first 8 bytes of RAW_SMBIOS_DATA header */

    PHYSICAL_ADDRESS lowAddr  = { 0 };
    PHYSICAL_ADDRESS highAddr = { 0 };
    highAddr.QuadPart = -1;
    PHYSICAL_ADDRESS skipBytes = { 0 };

    /* Scan the system address range for the SMBIOS signature */
    PVOID startAddr = MmGetSystemRoutineAddress(NULL);
    UNREFERENCED_PARAMETER(startAddr);
    UNREFERENCED_PARAMETER(lowAddr);
    UNREFERENCED_PARAMETER(highAddr);
    UNREFERENCED_PARAMETER(skipBytes);

    /*
     * Practical approach: Since we can't safely scan all kernel memory,
     * patch the returned buffer (which is our copy) and rely on the
     * hypervisor (Phase 5) to intercept future queries via EPT.
     *
     * For now, this function patches the data that the current
     * ZwQuerySystemInformation call returned — validating our parsing.
     * The real interception happens via EPT in Phase 5.
     */

    TRACE("[VolFlt] SMBIOS tables parsed: ver %u.%u, %lu bytes\n",
          raw->SMBIOSMajorVersion, raw->SMBIOSMinorVersion, raw->Length);

    ExFreePoolWithTag(buf, POOL_TAG);
    return STATUS_SUCCESS;
}

VOID SmbiosSpoof_Cleanup(VOID)
{
    g_PatchedAddress = NULL;
    g_PatchedLength  = 0;
}
