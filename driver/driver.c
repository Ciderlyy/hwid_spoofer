/*
 * driver/driver.c
 * DriverEntry, DriverUnload, control-device IOCTL handler, and utility helpers.
 *
 * Build: WDK 10 + Visual Studio 2022, x64 kernel mode, /W4, /WX
 * Test:  bcdedit /set testsigning on   (reboot required)
 */

#include "driver.h"
#include <bcrypt.h>   /* BCryptGenRandom – available kernel-side Win8.1+ */
#include <immintrin.h> /* _rdrand64_step – Ivy Bridge+ / Zen+ */

/* ─── Global state ───────────────────────────────────────────────────── */
DRIVER_GLOBAL g_Driver = { 0 };

/* ─── Forward declarations ───────────────────────────────────────────── */
static DRIVER_UNLOAD    DriverUnload;
static DRIVER_DISPATCH  Dispatch_CreateClose;
static DRIVER_DISPATCH  Dispatch_DeviceControl;

/* ═══════════════════════════════════════════════════════════════════════
 * Utility helpers – live here so disk_spoof.c and registry_spoof.c can
 * call them without additional linkage complexity.
 * ═══════════════════════════════════════════════════════════════════════ */

VOID Util_RandomBytes(_Out_writes_bytes_(len) PUCHAR buf, _In_ ULONG len)
{
    NTSTATUS st = BCryptGenRandom(NULL, buf, len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (NT_SUCCESS(st)) return;

    /* RDRAND fallback — needed at very early boot before CNG is available */
    {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        if (cpuInfo[2] & (1 << 30)) {
            BOOLEAN ok = TRUE;
            for (ULONG i = 0; i < len; i += 8) {
                unsigned __int64 val;
                int retry;
                for (retry = 0; retry < 10; retry++)
                    if (_rdrand64_step(&val)) break;
                if (retry == 10) { ok = FALSE; break; }
                ULONG chunk = (len - i < 8) ? (len - i) : 8;
                RtlCopyMemory(buf + i, &val, chunk);
            }
            if (ok) return;
        }
    }

    /* LCG fallback — last resort */
    LARGE_INTEGER perf = KeQueryPerformanceCounter(NULL);
    for (ULONG i = 0; i < len; i++) {
        perf.QuadPart = (perf.QuadPart * 6364136223846793005LL) + 1442695040888963407LL;
        buf[i] = (UCHAR)((perf.HighPart ^ perf.LowPart ^ (perf.LowPart >> 8)) & 0xFF);
    }
}

VOID Util_GenDiskSerial(_Out_writes_(SPOOFER_DISK_SERIAL_LEN) PCHAR out)
{
    static const CHAR hex[] = "0123456789ABCDEF";
    UCHAR rnd[16];
    Util_RandomBytes(rnd, sizeof(rnd));
    for (ULONG i = 0; i < 16; i++) {
        out[i * 2]     = hex[(rnd[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[rnd[i] & 0xF];
    }
    out[32] = '\0';
}

VOID Util_GenMacAddress(_Out_writes_(SPOOFER_MAC_LEN) PCHAR out)
{
    /* Locally administered unicast: set bit 1 of first octet, clear bit 0 */
    static const CHAR hex[] = "0123456789ABCDEF";
    UCHAR rnd[6];
    Util_RandomBytes(rnd, sizeof(rnd));
    rnd[0] = (rnd[0] & 0xFE) | 0x02;   /* locally administered, unicast */
    for (ULONG i = 0; i < 6; i++) {
        out[i * 2]     = hex[(rnd[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[rnd[i] & 0xF];
    }
    out[12] = '\0';
}

VOID Util_GenMachineGuid(_Out_writes_(SPOOFER_GUID_LEN) PWCHAR out)
{
    UCHAR r[16];
    Util_RandomBytes(r, sizeof(r));
    /* RFC 4122 v4 fields */
    r[6] = (r[6] & 0x0F) | 0x40;
    r[8] = (r[8] & 0x3F) | 0x80;

    RtlStringCbPrintfW(out, SPOOFER_GUID_LEN * sizeof(WCHAR),
        L"{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        r[0], r[1], r[2],  r[3],
        r[4], r[5],
        r[6], r[7],
        r[8], r[9],
        r[10],r[11],r[12],r[13],r[14],r[15]);
}

ULONG Util_GenVolumeSerial(VOID)
{
    ULONG v;
    Util_RandomBytes((PUCHAR)&v, sizeof(v));
    return v;
}

VOID Util_GenProductId(_Out_writes_(SPOOFER_PRODUCT_ID_LEN) PWCHAR out)
{
    /* OEM format: XXXXX-OEM-XXXXXXX-XXXXX (24 chars + NUL)
       This is the most common format for pre-installed Windows installs
       and has fewer format validation constraints than retail keys. */
    static const WCHAR dig[] = L"0123456789";
    UCHAR r[17];
    Util_RandomBytes(r, sizeof(r));
    ULONG p = 0;
    for (ULONG i = 0; i < 5;  i++) out[p++] = dig[r[i]      % 10];
    out[p++] = L'-';
    out[p++] = L'O'; out[p++] = L'E'; out[p++] = L'M';
    out[p++] = L'-';
    for (ULONG i = 5; i < 12; i++) out[p++] = dig[r[i]      % 10];
    out[p++] = L'-';
    for (ULONG i = 12;i < 17; i++) out[p++] = dig[r[i]      % 10];
    out[p] = L'\0';
}

ULONG Util_GenInstallDate(VOID)
{
    /* Random epoch in a plausible range: 2020-01-01 to 2027-12-31 */
    ULONG base = 1577836800u;  /* 2020-01-01 UTC */
    ULONG range = 252460800u;  /* ~8 years in seconds */
    ULONG offset;
    Util_RandomBytes((PUCHAR)&offset, sizeof(offset));
    return base + (offset % range);
}

ULONG Util_GenEdidSerial(VOID)
{
    ULONG v;
    Util_RandomBytes((PUCHAR)&v, sizeof(v));
    return v;
}

VOID Util_GenGpuSerial(_Out_writes_(64) PCHAR out)
{
    static const CHAR hex[] = "0123456789ABCDEF";
    UCHAR rnd[16];
    Util_RandomBytes(rnd, sizeof(rnd));
    for (ULONG i = 0; i < 16; i++) {
        out[i * 2]     = hex[(rnd[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[rnd[i] & 0xF];
    }
    out[32] = '\0';
}

/* Simple hash: expand 16-byte seed into 32 bytes for cross-source consistency */
static VOID DeriveFromSeed(_In_reads_(16) const UCHAR* seed,
    _Out_writes_(32) UCHAR* out)
{
    static const UCHAR mul = 0x9E;
    for (ULONG i = 0; i < 32; i++)
        out[i] = (UCHAR)(seed[i % 16] ^ (seed[(i + 7) % 16] + (UCHAR)i) * mul);
}

/* ═══════════════════════════════════════════════════════════════════════
 * FillEmptyConfigSlots — generate random values for any config field
 * that is still zero/empty.  Cross-source: MachineGuid seeds SMBIOS/disk.
 * Must be called at PASSIVE_LEVEL.
 * ═══════════════════════════════════════════════════════════════════════ */

static VOID FillEmptyConfigSlots(VOID)
{
    /* Pre-generate all values at PASSIVE_LEVEL before acquiring lock */
    CHAR  tmpSerial[SPOOFER_DISK_SERIAL_LEN];
    CHAR  tmpMac   [SPOOFER_MAC_LEN];
    WCHAR tmpGuid  [SPOOFER_GUID_LEN];
    WCHAR tmpProdId[SPOOFER_PRODUCT_ID_LEN];
    UCHAR tmpDpidBytes[16];
    ULONG tmpVol       = Util_GenVolumeSerial();
    ULONG tmpInstDate  = Util_GenInstallDate();
    ULONG tmpEdidSn    = Util_GenEdidSerial();
    Util_GenMachineGuid(tmpGuid);
    Util_GenMacAddress(tmpMac);
    Util_GenProductId(tmpProdId);
    Util_RandomBytes(tmpDpidBytes, sizeof(tmpDpidBytes));

    /* Cross-source: derive disk + SMBIOS from GUID for consistency */
    UCHAR guidBytes[16] = { 0 };
    ULONG nibbles = 0;
    for (ULONG i = 0; i < 39 && nibbles < 32; i++) {
        WCHAR c = tmpGuid[i];
        UCHAR v = 0;
        if (c >= L'0' && c <= L'9') v = (UCHAR)(c - L'0');
        else if (c >= L'a' && c <= L'f') v = (UCHAR)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') v = (UCHAR)(c - L'A' + 10);
        else continue;
        if ((nibbles & 1) == 0) guidBytes[nibbles / 2] = (UCHAR)(v << 4);
        else guidBytes[nibbles / 2] |= v;
        nibbles++;
    }
    UCHAR derived[32];
    DeriveFromSeed(guidBytes, derived);

    static const CHAR hex[] = "0123456789ABCDEF";
    for (ULONG i = 0; i < 16; i++) {
        tmpSerial[i * 2]     = hex[(derived[i] >> 4) & 0xF];
        tmpSerial[i * 2 + 1] = hex[derived[i] & 0xF];
    }
    tmpSerial[32] = '\0';

    CHAR tmpBiosSerial[64], tmpBoardSerial[64], tmpSystemUuid[37], tmpChassisSerial[64];
    RtlStringCbPrintfA(tmpBiosSerial, sizeof(tmpBiosSerial),
        "BIOS-%02X%02X%02X%02X%02X%02X%02X%02X",
        derived[0],derived[1],derived[2],derived[3],derived[4],derived[5],derived[6],derived[7]);
    RtlStringCbPrintfA(tmpBoardSerial, sizeof(tmpBoardSerial),
        "MB-%02X%02X%02X%02X%02X%02X%02X%02X",
        derived[8],derived[9],derived[10],derived[11],derived[12],derived[13],derived[14],derived[15]);
    RtlStringCbPrintfA(tmpChassisSerial, sizeof(tmpChassisSerial),
        "CH-%02X%02X%02X%02X%02X%02X",
        derived[16],derived[17],derived[18],derived[19],derived[20],derived[21]);
    UCHAR uuid[16];
    RtlCopyMemory(uuid, derived, 16);
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    RtlStringCbPrintfA(tmpSystemUuid, sizeof(tmpSystemUuid),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
        uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]);

    KIRQL irql = ExAcquireSpinLockExclusive(&g_Driver.ConfigLock);
    if (!g_Driver.Config.FakeDiskSerial[0])
        RtlCopyMemory(g_Driver.Config.FakeDiskSerial, tmpSerial,
                      SPOOFER_DISK_SERIAL_LEN);
    if (!g_Driver.Config.FakeMacAddress[0])
        RtlCopyMemory(g_Driver.Config.FakeMacAddress, tmpMac,
                      SPOOFER_MAC_LEN);
    if (!g_Driver.Config.FakeMachineGuid[0])
        RtlCopyMemory(g_Driver.Config.FakeMachineGuid, tmpGuid,
                      SPOOFER_GUID_LEN * sizeof(WCHAR));
    if (!g_Driver.Config.FakeVolumeSerial)
        g_Driver.Config.FakeVolumeSerial = tmpVol;
    if (!g_Driver.Config.FakeProductId[0])
        RtlCopyMemory(g_Driver.Config.FakeProductId, tmpProdId,
                      SPOOFER_PRODUCT_ID_LEN * sizeof(WCHAR));
    if (!g_Driver.Config.FakeInstallDate)
        g_Driver.Config.FakeInstallDate = tmpInstDate;
    if (!g_Driver.Config.FakeEdidSerial)
        g_Driver.Config.FakeEdidSerial = tmpEdidSn;
    if (!g_Driver.Config.FakeDigitalProductBytes[0])
        RtlCopyMemory(g_Driver.Config.FakeDigitalProductBytes,
                      tmpDpidBytes, sizeof(tmpDpidBytes));
    if (!g_Driver.Config.FakeBiosSerial[0])
        RtlCopyMemory(g_Driver.Config.FakeBiosSerial, tmpBiosSerial,
                      sizeof(tmpBiosSerial));
    if (!g_Driver.Config.FakeBoardSerial[0])
        RtlCopyMemory(g_Driver.Config.FakeBoardSerial, tmpBoardSerial,
                      sizeof(tmpBoardSerial));
    /* FakeSystemSerial: default to FakeBoardSerial for cross-source consistency */
    if (!g_Driver.Config.FakeSystemSerial[0])
        RtlCopyMemory(g_Driver.Config.FakeSystemSerial, tmpBoardSerial,
                      sizeof(tmpBoardSerial));
    if (!g_Driver.Config.FakeSystemUuid[0])
        RtlCopyMemory(g_Driver.Config.FakeSystemUuid, tmpSystemUuid,
                      sizeof(tmpSystemUuid));
    if (!g_Driver.Config.FakeChassisSerial[0])
        RtlCopyMemory(g_Driver.Config.FakeChassisSerial, tmpChassisSerial,
                      sizeof(tmpChassisSerial));
    ExReleaseSpinLockExclusive(&g_Driver.ConfigLock, irql);
}

/* ═══════════════════════════════════════════════════════════════════════
 * ReadPersistedConfig — load config from RegistryPath\Parameters at boot
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS ReadPersistedConfig(_In_ PUNICODE_STRING RegistryPath)
{
    WCHAR pathBuf[512];
    RtlStringCbPrintfW(pathBuf, sizeof(pathBuf), L"%wZ\\Parameters", RegistryPath);

    UNICODE_STRING paramPath;
    RtlInitUnicodeString(&paramPath, pathBuf);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &paramPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING valName = RTL_CONSTANT_STRING(L"SpoofConfig");
    UCHAR infoBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(SPOOFER_CONFIG) + 16];
    ULONG resultLen = 0;

    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation,
                             infoBuf, sizeof(infoBuf), &resultLen);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
        if (info->Type == REG_BINARY && info->DataLength >= sizeof(SPOOFER_CONFIG)) {
            RtlCopyMemory(&g_Driver.Config, info->Data, sizeof(SPOOFER_CONFIG));
        } else {
            status = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }

    ZwClose(hKey);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════
 * IRP_MJ_CREATE / IRP_MJ_CLOSE – trivially succeed
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Dispatch_CreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 * IRP_MJ_DEVICE_CONTROL – control channel for the user-mode loader
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Dispatch_DeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    /* ── Route non-control-device IRPs to the disk filter handler ──── */
    PCONTROL_DEV_EXT ext = (PCONTROL_DEV_EXT)DeviceObject->DeviceExtension;
    if (ext->Type != DEVEXT_TYPE_CONTROL) {
        /* Should not reach here for filter devices via this path,
           but guard against mis-routing gracefully. */
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION stack   = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code    = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID              buf     = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen   = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen  = stack->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS    status = STATUS_SUCCESS;
    ULONG_PTR   info   = 0;

    switch (code) {

    /* ── IOCTL_SPOOFER_SET_CONFIG ────────────────────────────────── */
    case IOCTL_SPOOFER_SET_CONFIG:
    {
        if (inLen < sizeof(SPOOFER_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        /* Copy caller's struct into a local so we can generate at
           PASSIVE_LEVEL BEFORE acquiring the spin lock.
           Calling BCryptGenRandom (or any pageable routine) while holding
           the lock would raise IRQL to DISPATCH_LEVEL and BSOD. */
        SPOOFER_CONFIG newCfg;
        RtlCopyMemory(&newCfg, buf, sizeof(SPOOFER_CONFIG));

        if (newCfg.AutoGenerate) {
            Util_GenDiskSerial(newCfg.FakeDiskSerial);
            Util_GenMacAddress(newCfg.FakeMacAddress);
            Util_GenMachineGuid(newCfg.FakeMachineGuid);
            newCfg.FakeVolumeSerial = Util_GenVolumeSerial();
            Util_GenProductId(newCfg.FakeProductId);
            newCfg.FakeInstallDate = Util_GenInstallDate();
            newCfg.FakeEdidSerial  = Util_GenEdidSerial();
            Util_RandomBytes(newCfg.FakeDigitalProductBytes,
                             sizeof(newCfg.FakeDigitalProductBytes));
        }

        KIRQL irql = ExAcquireSpinLockExclusive(&g_Driver.ConfigLock);
        RtlCopyMemory(&g_Driver.Config, &newCfg, sizeof(SPOOFER_CONFIG));
        ExReleaseSpinLockExclusive(&g_Driver.ConfigLock, irql);

        TRACE("[VolFlt] Config updated. DiskSerial=%s\n",
                 newCfg.FakeDiskSerial);
        break;
    }

    /* ── IOCTL_SPOOFER_GET_STATUS ────────────────────────────────── */
    case IOCTL_SPOOFER_GET_STATUS:
    {
        if (outLen < sizeof(SPOOFER_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PSPOOFER_STATUS st = (PSPOOFER_STATUS)buf;
        RtlZeroMemory(st, sizeof(*st));

        /* Non-config fields don't need the lock */
        st->IsActive            = g_Driver.Active;
        st->DiskFiltersAttached = g_Driver.FilterCount;
        st->TotalIntercepts     = (ULONG)g_Driver.TotalIntercepts;

        /* Config fields: take shared lock to prevent torn reads from
           a concurrent REGENERATE completing between our copies. */
        KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
        RtlCopyMemory(st->ActiveDiskSerial,  g_Driver.Config.FakeDiskSerial,
                      SPOOFER_DISK_SERIAL_LEN);
        RtlCopyMemory(st->ActiveMacAddress,  g_Driver.Config.FakeMacAddress,
                      SPOOFER_MAC_LEN);
        RtlCopyMemory(st->ActiveMachineGuid, g_Driver.Config.FakeMachineGuid,
                      SPOOFER_GUID_LEN * sizeof(WCHAR));
        st->ActiveVolumeSerial  = g_Driver.Config.FakeVolumeSerial;
        RtlCopyMemory(st->ActiveProductId, g_Driver.Config.FakeProductId,
                      SPOOFER_PRODUCT_ID_LEN * sizeof(WCHAR));
        st->ActiveInstallDate   = g_Driver.Config.FakeInstallDate;
        st->ActiveEdidSerial    = g_Driver.Config.FakeEdidSerial;
        RtlCopyMemory(st->ActiveDigitalProductBytes,
                      g_Driver.Config.FakeDigitalProductBytes,
                      sizeof(st->ActiveDigitalProductBytes));
        RtlCopyMemory(st->ActiveBiosSerial,   g_Driver.Config.FakeBiosSerial,   64);
        RtlCopyMemory(st->ActiveBoardSerial,  g_Driver.Config.FakeBoardSerial,  64);
        RtlCopyMemory(st->ActiveSystemSerial,
            g_Driver.Config.FakeSystemSerial[0] ? g_Driver.Config.FakeSystemSerial
                                               : g_Driver.Config.FakeBoardSerial,
            64);
        RtlCopyMemory(st->ActiveSystemUuid,   g_Driver.Config.FakeSystemUuid,   37);
        RtlCopyMemory(st->ActiveChassisSerial,g_Driver.Config.FakeChassisSerial,64);
        RtlCopyMemory(st->ActiveGpuSerial,    g_Driver.Config.FakeGpuSerial,    64);
        RtlCopyMemory(st->ActiveGpuDescription, g_Driver.Config.FakeGpuDescription, 128 * sizeof(WCHAR));
        ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);

        info = sizeof(SPOOFER_STATUS);
        break;
    }

    /* ── IOCTL_SPOOFER_ENABLE ────────────────────────────────────── */
    case IOCTL_SPOOFER_ENABLE:
    {
        ExAcquireFastMutex(&g_Driver.StateMutex);
        if (g_Driver.Active) {
            ExReleaseFastMutex(&g_Driver.StateMutex);
            break;
        }

        FillEmptyConfigSlots();
        SmbiosSpoof_Init();
        GpuSpoof_Init();
        HvInitialize();
        EptHooks_Initialize();
        TpmVirt_Init();

        status = DiskSpoof_Attach(g_Driver.DriverObject);
        if (!NT_SUCCESS(status)) {
            TRACE("[VolFlt] DiskSpoof_Attach failed: 0x%08X\n", status);
            ExReleaseFastMutex(&g_Driver.StateMutex);
            break;
        }

        status = RegSpoof_Register(g_Driver.DriverObject);
        if (!NT_SUCCESS(status)) {
            TRACE("[VolFlt] RegSpoof_Register failed: 0x%08X\n", status);
            DiskSpoof_DetachAll();
            ExReleaseFastMutex(&g_Driver.StateMutex);
            break;
        }

        g_Driver.Active = TRUE;
        TRACE("[VolFlt] Spoofing ENABLED\n");
        ExReleaseFastMutex(&g_Driver.StateMutex);
        break;
    }

    /* ── IOCTL_SPOOFER_DISABLE ───────────────────────────────────── */
    case IOCTL_SPOOFER_DISABLE:
        ExAcquireFastMutex(&g_Driver.StateMutex);
        if (g_Driver.Active) {
            TpmVirt_Cleanup();
            EptHooks_Cleanup();
            HvShutdown();
            SmbiosSpoof_Cleanup();
            GpuSpoof_Cleanup();
            RegSpoof_Unregister();
            DiskSpoof_DetachAll();
            g_Driver.Active = FALSE;
            TRACE("[VolFlt] Spoofing DISABLED\n");
        }
        ExReleaseFastMutex(&g_Driver.StateMutex);
        break;

    /* ── IOCTL_SPOOFER_REGENERATE ────────────────────────────────── */
    case IOCTL_SPOOFER_REGENERATE:
    {
        /* Generate at PASSIVE_LEVEL, then atomically swap into Config. */
        CHAR  newSerial[SPOOFER_DISK_SERIAL_LEN];
        CHAR  newMac   [SPOOFER_MAC_LEN];
        WCHAR newGuid  [SPOOFER_GUID_LEN];
        WCHAR newProdId[SPOOFER_PRODUCT_ID_LEN];
        UCHAR newDpidBytes[16];
        CHAR  newBiosSerial[64], newBoardSerial[64], newChassisSerial[64];
        CHAR  newSystemUuid[37];
        CHAR  newGpuSerial[64];
        ULONG newVol      = Util_GenVolumeSerial();
        ULONG newInstDate = Util_GenInstallDate();
        ULONG newEdidSn   = Util_GenEdidSerial();
        Util_GenMachineGuid(newGuid);
        Util_GenMacAddress(newMac);
        Util_GenProductId(newProdId);
        Util_RandomBytes(newDpidBytes, sizeof(newDpidBytes));
        Util_GenGpuSerial(newGpuSerial);

        /* Cross-source: derive disk + SMBIOS from MachineGuid */
        UCHAR guidBytes[16] = { 0 };
        ULONG nibbles = 0;
        for (ULONG i = 0; i < 39 && nibbles < 32; i++) {
            WCHAR c = newGuid[i];
            UCHAR v = 0;
            if (c >= L'0' && c <= L'9') v = (UCHAR)(c - L'0');
            else if (c >= L'a' && c <= L'f') v = (UCHAR)(c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') v = (UCHAR)(c - L'A' + 10);
            else continue;
            if ((nibbles & 1) == 0) guidBytes[nibbles / 2] = (UCHAR)(v << 4);
            else guidBytes[nibbles / 2] |= v;
            nibbles++;
        }
        UCHAR derived[32];
        DeriveFromSeed(guidBytes, derived);
        { static const CHAR h[] = "0123456789ABCDEF";
          for (ULONG i = 0; i < 16; i++) {
            newSerial[i*2]=h[(derived[i]>>4)&0xF]; newSerial[i*2+1]=h[derived[i]&0xF];
          } newSerial[32] = '\0'; }
        RtlStringCbPrintfA(newBiosSerial, sizeof(newBiosSerial),
            "BIOS-%02X%02X%02X%02X%02X%02X%02X%02X",
            derived[0],derived[1],derived[2],derived[3],derived[4],derived[5],derived[6],derived[7]);
        RtlStringCbPrintfA(newBoardSerial, sizeof(newBoardSerial),
            "MB-%02X%02X%02X%02X%02X%02X%02X%02X",
            derived[8],derived[9],derived[10],derived[11],derived[12],derived[13],derived[14],derived[15]);
        RtlStringCbPrintfA(newChassisSerial, sizeof(newChassisSerial),
            "CH-%02X%02X%02X%02X%02X%02X",
            derived[16],derived[17],derived[18],derived[19],derived[20],derived[21]);
        { UCHAR u[16]; RtlCopyMemory(u, derived, 16);
          u[6]=(u[6]&0x0F)|0x40; u[8]=(u[8]&0x3F)|0x80;
          RtlStringCbPrintfA(newSystemUuid, sizeof(newSystemUuid),
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]); }

        KIRQL irql = ExAcquireSpinLockExclusive(&g_Driver.ConfigLock);
        RtlCopyMemory(g_Driver.Config.FakeDiskSerial,  newSerial,
                      SPOOFER_DISK_SERIAL_LEN);
        RtlCopyMemory(g_Driver.Config.FakeMacAddress,  newMac,
                      SPOOFER_MAC_LEN);
        RtlCopyMemory(g_Driver.Config.FakeMachineGuid, newGuid,
                      SPOOFER_GUID_LEN * sizeof(WCHAR));
        g_Driver.Config.FakeVolumeSerial = newVol;
        RtlCopyMemory(g_Driver.Config.FakeProductId, newProdId,
                      SPOOFER_PRODUCT_ID_LEN * sizeof(WCHAR));
        g_Driver.Config.FakeInstallDate  = newInstDate;
        g_Driver.Config.FakeEdidSerial   = newEdidSn;
        RtlCopyMemory(g_Driver.Config.FakeDigitalProductBytes,
                      newDpidBytes, sizeof(newDpidBytes));
        RtlCopyMemory(g_Driver.Config.FakeBiosSerial,    newBiosSerial,    64);
        RtlCopyMemory(g_Driver.Config.FakeBoardSerial,  newBoardSerial,   64);
        RtlCopyMemory(g_Driver.Config.FakeSystemSerial, newBoardSerial,   64);
        RtlCopyMemory(g_Driver.Config.FakeSystemUuid,   newSystemUuid,    37);
        RtlCopyMemory(g_Driver.Config.FakeChassisSerial, newChassisSerial, 64);
        RtlCopyMemory(g_Driver.Config.FakeGpuSerial,    newGpuSerial,     64);
        ExReleaseSpinLockExclusive(&g_Driver.ConfigLock, irql);

        TpmVirt_Regenerate();

        TRACE("[VolFlt] IDs regenerated. DiskSerial=%s\n", newSerial);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════
 * DriverUnload
 * ═══════════════════════════════════════════════════════════════════════ */

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Driver.Active) {
        TpmVirt_Cleanup();
        EptHooks_Cleanup();
        HvShutdown();
        SmbiosSpoof_Cleanup();
        GpuSpoof_Cleanup();
        RegSpoof_Unregister();
        DiskSpoof_DetachAll();
        g_Driver.Active = FALSE;
    }

    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SPOOFER_DOS_SYMLINK);
    IoDeleteSymbolicLink(&symlink);

    if (g_Driver.ControlDevice) {
        IoDeleteDevice(g_Driver.ControlDevice);
        g_Driver.ControlDevice = NULL;
    }

    TRACE("[VolFlt] Unloaded\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * DriverEntry
 * ═══════════════════════════════════════════════════════════════════════ */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    TRACE("[VolFlt] DriverEntry\n");

    RtlZeroMemory(&g_Driver, sizeof(g_Driver));
    g_Driver.DriverObject = DriverObject;
    ExInitializeFastMutex(&g_Driver.StateMutex);

    DriverObject->DriverUnload = DriverUnload;
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = Dispatch_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = Dispatch_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = Dispatch_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch_DeviceControl;

    g_Driver.OriginalDeviceControl = Dispatch_DeviceControl;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(SPOOFER_NT_DEVICE_NAME);
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        sizeof(CONTROL_DEV_EXT),
        &devName,
        FILE_DEVICE_SPOOFER,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_Driver.ControlDevice);

    if (!NT_SUCCESS(status)) {
        TRACE("[VolFlt] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    ((PCONTROL_DEV_EXT)g_Driver.ControlDevice->DeviceExtension)->Type =
        DEVEXT_TYPE_CONTROL;

    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SPOOFER_DOS_SYMLINK);
    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        TRACE("[VolFlt] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_Driver.ControlDevice);
        return status;
    }

    g_Driver.ControlDevice->Flags |= DO_BUFFERED_IO;
    g_Driver.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    /* ── Boot-start auto-enable: read persisted config from registry ── */
    NTSTATUS cfgSt = ReadPersistedConfig(RegistryPath);
    if (NT_SUCCESS(cfgSt)) {
        BOOLEAN anyFlag = g_Driver.Config.SpoofDiskSerial  ||
                          g_Driver.Config.SpoofMacAddress   ||
                          g_Driver.Config.SpoofMachineGuid  ||
                          g_Driver.Config.SpoofVolumeSerial ||
                          g_Driver.Config.SpoofInstallIds   ||
                          g_Driver.Config.SpoofEdidSerial   ||
                          g_Driver.Config.SpoofSmbios       ||
                          g_Driver.Config.SpoofGpu;
        if (anyFlag) {
            FillEmptyConfigSlots();
            SmbiosSpoof_Init();
            GpuSpoof_Init();
            HvInitialize(); /* non-fatal if VT-x unavailable */
            EptHooks_Initialize(); /* non-fatal: falls back to filter driver */
            TpmVirt_Init(); /* non-fatal: requires EPT */
            NTSTATUS att = DiskSpoof_Attach(DriverObject);
            if (NT_SUCCESS(att)) {
                RegSpoof_Register(DriverObject);
                g_Driver.Active = TRUE;
                TRACE("[VolFlt] Auto-enabled from persisted config\n");
            }
        }
    }

    TRACE("[VolFlt] Loaded. Control device: %wZ\n", &devName);
    return STATUS_SUCCESS;
}
