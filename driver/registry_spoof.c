/*
 * driver/registry_spoof.c
 *
 * Registry-based HWID spoofing via CmRegisterCallbackEx.
 *
 * Values intercepted
 * ──────────────────
 *  • MachineGuid     HKLM\SOFTWARE\Microsoft\Cryptography             (REG_SZ)
 *  • NetworkAddress  HKLM\SYSTEM\CCS\Control\Class\{4D36E972...}\*    (REG_SZ)
 *  • ProductId       HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (REG_SZ)
 *  • DigitalProductId HKLM\...\CurrentVersion                         (REG_BINARY)
 *  • InstallDate     HKLM\...\CurrentVersion                          (REG_DWORD)
 *  • EDID            HKLM\SYSTEM\CCS\Enum\DISPLAY\*\*\Device Parameters (REG_BINARY)
 *
 * PatchGuard note: CmRegisterCallbackEx is a documented kernel API and
 * is fully PatchGuard-safe.
 */

#include "driver.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Well-known registry paths and value names
 * ═══════════════════════════════════════════════════════════════════════ */

/* -- MachineGuid ---------------------------------------------------- */
static UNICODE_STRING g_ValMachineGuid =
    RTL_CONSTANT_STRING(L"MachineGuid");

static UNICODE_STRING g_KeyCryptography =
    RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography");

/* -- NetworkAddress -------------------------------------------------- */
static UNICODE_STRING g_ValNetworkAddress =
    RTL_CONSTANT_STRING(L"NetworkAddress");

static UNICODE_STRING g_KeyNicClassPrefix =
    RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS"
        L"\\{4D36E972-E325-11CE-BFC1-08002BE10318}");

/* -- Windows install identifiers ------------------------------------- */
static UNICODE_STRING g_ValProductId =
    RTL_CONSTANT_STRING(L"ProductId");

static UNICODE_STRING g_ValDigitalProductId =
    RTL_CONSTANT_STRING(L"DigitalProductId");

static UNICODE_STRING g_ValInstallDate =
    RTL_CONSTANT_STRING(L"InstallDate");

static UNICODE_STRING g_KeyCurrentVersion =
    RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

/* -- Monitor EDID ---------------------------------------------------- */
static UNICODE_STRING g_ValEdid =
    RTL_CONSTANT_STRING(L"EDID");

static UNICODE_STRING g_KeyDisplayPrefix =
    RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\DISPLAY");

static UNICODE_STRING g_SubDeviceParameters =
    RTL_CONSTANT_STRING(L"\\Device Parameters");

/* -- GPU adapter (display class GUID) -------------------------------- */
static UNICODE_STRING g_ValDriverDesc =
    RTL_CONSTANT_STRING(L"DriverDesc");

static UNICODE_STRING g_ValAdapterString =
    RTL_CONSTANT_STRING(L"HardwareInformation.AdapterString");

static UNICODE_STRING g_ValBiosString =
    RTL_CONSTANT_STRING(L"HardwareInformation.BiosString");

static UNICODE_STRING g_ValGpuSerial =
    RTL_CONSTANT_STRING(L"HardwareInformation.SerialNumber");
static UNICODE_STRING g_ValGpuSerialAlt =
    RTL_CONSTANT_STRING(L"SerialNumber");

static UNICODE_STRING g_KeyGpuClassPrefix =
    RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS"
        L"\\{4D36E968-E325-11CE-BFC1-08002BE10318}");

/* ─── Forward declaration ────────────────────────────────────────────── */
static EX_CALLBACK_FUNCTION RegNotifyCallback;

/* ─── Helper: case-insensitive prefix test ───────────────────────────── */
static BOOLEAN StartsWith(
    _In_ PCUNICODE_STRING full,
    _In_ PCUNICODE_STRING prefix)
{
    if (full->Length < prefix->Length) return FALSE;
    UNICODE_STRING head = *full;
    head.Length = prefix->Length;
    return RtlEqualUnicodeString(&head, prefix, TRUE);
}

/* Suffix test: does keyName end with the given suffix (case-insensitive)? */
static BOOLEAN EndsWith(
    _In_ PCUNICODE_STRING full,
    _In_ PCUNICODE_STRING suffix)
{
    if (full->Length < suffix->Length) return FALSE;
    UNICODE_STRING tail;
    tail.Buffer        = (PWCH)((PUCHAR)full->Buffer + (full->Length - suffix->Length));
    tail.Length         = suffix->Length;
    tail.MaximumLength = suffix->Length;
    return RtlEqualUnicodeString(&tail, suffix, TRUE);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Patch helpers
 * ═══════════════════════════════════════════════════════════════════════ */

static VOID PatchStringValue(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION info,
    _In_ PCWSTR                         fakeWide,
    _In_ ULONG                          totalBufLen)
{
    if (!info || info->Type != REG_SZ) return;

    ULONG hdrSize  = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
    if (totalBufLen <= hdrSize) return;
    ULONG maxData  = totalBufLen - hdrSize;
    ULONG srcBytes = (ULONG)(wcslen(fakeWide) + 1) * sizeof(WCHAR);
    if (srcBytes > maxData) return;

    RtlCopyMemory(info->Data, fakeWide, srcBytes);
    if (maxData > srcBytes) {
        ULONG padLen = (info->DataLength > srcBytes)
                     ? (info->DataLength - srcBytes) : 0;
        if (padLen > 0)
            RtlZeroMemory(info->Data + srcBytes, padLen);
    }
    info->DataLength = srcBytes;
}

static VOID PatchFullStringValue(
    _In_ PKEY_VALUE_FULL_INFORMATION info,
    _In_ ULONG                       totalBufLen,
    _In_ PCWSTR                      fakeWide)
{
    if (!info || info->Type != REG_SZ) return;
    if (info->DataOffset == 0 || info->DataOffset >= totalBufLen) return;

    ULONG  available = totalBufLen - info->DataOffset;
    ULONG  srcBytes  = (ULONG)(wcslen(fakeWide) + 1) * sizeof(WCHAR);
    if (srcBytes > available) return;

    PUCHAR dataPtr = (PUCHAR)info + info->DataOffset;
    RtlCopyMemory(dataPtr, fakeWide, srcBytes);
    if (info->DataLength > srcBytes) {
        RtlZeroMemory(dataPtr + srcBytes, info->DataLength - srcBytes);
    }
    info->DataLength = srcBytes;
}

/* Patch a REG_DWORD value in KeyValuePartialInformation */
static VOID PatchDwordValue(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION info,
    _In_ ULONG                          fakeValue)
{
    if (!info || info->Type != REG_DWORD) return;
    if (info->DataLength < sizeof(ULONG))  return;
    *(PULONG)info->Data = fakeValue;
}

/* Patch a REG_DWORD in KeyValueFullInformation */
static VOID PatchFullDwordValue(
    _In_ PKEY_VALUE_FULL_INFORMATION info,
    _In_ ULONG                       totalBufLen,
    _In_ ULONG                       fakeValue)
{
    if (!info || info->Type != REG_DWORD) return;
    if (info->DataOffset == 0 || info->DataOffset >= totalBufLen) return;
    if (info->DataLength < sizeof(ULONG)) return;
    if (info->DataOffset + sizeof(ULONG) > totalBufLen) return;
    *(PULONG)((PUCHAR)info + info->DataOffset) = fakeValue;
}

/* Patch EDID binary blob — overwrite the 4-byte serial at offset 0x0C.
   EDID structure: bytes 12-15 = serial number (DWORD, little-endian). */
#define EDID_SERIAL_OFFSET  12u
#define EDID_MIN_LENGTH     128u

static VOID PatchEdidBinary(
    _Inout_updates_bytes_(dataLen) PUCHAR data,
    _In_ ULONG  dataLen,
    _In_ ULONG  fakeSerial)
{
    if (dataLen < EDID_MIN_LENGTH) return;
    *(PULONG)(data + EDID_SERIAL_OFFSET) = fakeSerial;

    /* Recompute the EDID checksum (byte 127 = 256 - (sum of bytes 0..126) % 256) */
    ULONG sum = 0;
    for (ULONG i = 0; i < 127; i++) sum += data[i];
    data[127] = (UCHAR)(256u - (sum % 256u));
}

static VOID PatchEdidPartial(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION info,
    _In_ ULONG  fakeSerial)
{
    if (!info || info->Type != REG_BINARY) return;
    PatchEdidBinary(info->Data, info->DataLength, fakeSerial);
}

static VOID PatchEdidFull(
    _In_ PKEY_VALUE_FULL_INFORMATION info,
    _In_ ULONG totalBufLen,
    _In_ ULONG fakeSerial)
{
    if (!info || info->Type != REG_BINARY) return;
    if (info->DataOffset == 0 || info->DataOffset >= totalBufLen) return;
    ULONG available = totalBufLen - info->DataOffset;
    PUCHAR dataPtr  = (PUCHAR)info + info->DataOffset;
    ULONG  dataLen  = (info->DataLength < available) ? info->DataLength : available;
    PatchEdidBinary(dataPtr, dataLen, fakeSerial);
}

/* Patch DigitalProductId — a 164-byte opaque blob. Bytes 8-23 contain
   the decoded product key. We overwrite them with the pre-generated
   FakeDigitalProductBytes blob from config (16 bytes, BCryptGenRandom
   quality, generated at PASSIVE_LEVEL during SET_CONFIG/ENABLE/REGEN). */
static VOID PatchDigitalProductIdPartial(
    _In_ PKEY_VALUE_PARTIAL_INFORMATION info,
    _In_reads_(16) const UCHAR *fakeBytes)
{
    if (!info || info->Type != REG_BINARY) return;
    if (info->DataLength < 24) return;
    ULONG copyLen = 16;
    if (info->DataLength - 8 < copyLen) copyLen = info->DataLength - 8;
    RtlCopyMemory(info->Data + 8, fakeBytes, copyLen);
}

static VOID PatchDigitalProductIdFull(
    _In_ PKEY_VALUE_FULL_INFORMATION info,
    _In_ ULONG totalBufLen,
    _In_reads_(16) const UCHAR *fakeBytes)
{
    if (!info || info->Type != REG_BINARY) return;
    if (info->DataOffset == 0 || info->DataOffset >= totalBufLen) return;
    ULONG available = totalBufLen - info->DataOffset;
    PUCHAR dataPtr  = (PUCHAR)info + info->DataOffset;
    ULONG  dataLen  = (info->DataLength < available) ? info->DataLength : available;
    if (dataLen < 24) return;
    ULONG copyLen = 16;
    if (dataLen - 8 < copyLen) copyLen = dataLen - 8;
    RtlCopyMemory(dataPtr + 8, fakeBytes, copyLen);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Intercept classification
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum _INTERCEPT_TYPE {
    INTERCEPT_NONE = 0,
    INTERCEPT_MACHINE_GUID,
    INTERCEPT_NETWORK_ADDRESS,
    INTERCEPT_PRODUCT_ID,
    INTERCEPT_DIGITAL_PRODUCT_ID,
    INTERCEPT_INSTALL_DATE,
    INTERCEPT_EDID,
    INTERCEPT_GPU_DESCRIPTION,
    INTERCEPT_GPU_SERIAL,
} INTERCEPT_TYPE;

/* ═══════════════════════════════════════════════════════════════════════
 * Registry callback
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS RegNotifyCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_Driver.Active) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    if (notifyClass != RegNtPostQueryValueKey) return STATUS_SUCCESS;

    PREG_POST_OPERATION_INFORMATION postInfo =
        (PREG_POST_OPERATION_INFORMATION)Argument2;
    if (!postInfo || !NT_SUCCESS(postInfo->Status)) return STATUS_SUCCESS;

    PREG_QUERY_VALUE_KEY_INFORMATION preInfo =
        (PREG_QUERY_VALUE_KEY_INFORMATION)postInfo->PreInformation;
    if (!preInfo || !preInfo->ValueName) return STATUS_SUCCESS;

    /* ── Snapshot feature flags under shared lock ──────────────────── */
    BOOLEAN cfgSpoofMachineGuid, cfgSpoofMacAddress,
            cfgSpoofInstallIds, cfgSpoofEdidSerial, cfgSpoofGpu;
    {
        KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
        cfgSpoofMachineGuid = g_Driver.Config.SpoofMachineGuid;
        cfgSpoofMacAddress  = g_Driver.Config.SpoofMacAddress;
        cfgSpoofInstallIds  = g_Driver.Config.SpoofInstallIds;
        cfgSpoofEdidSerial  = g_Driver.Config.SpoofEdidSerial;
        cfgSpoofGpu         = g_Driver.Config.SpoofGpu;
        ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);
    }

    /* ── Classify the value name ───────────────────────────────────── */
    INTERCEPT_TYPE type = INTERCEPT_NONE;

    if (cfgSpoofMachineGuid &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValMachineGuid, TRUE)) {
        type = INTERCEPT_MACHINE_GUID;
    } else if (cfgSpoofMacAddress &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValNetworkAddress, TRUE)) {
        type = INTERCEPT_NETWORK_ADDRESS;
    } else if (cfgSpoofInstallIds &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValProductId, TRUE)) {
        type = INTERCEPT_PRODUCT_ID;
    } else if (cfgSpoofInstallIds &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValDigitalProductId, TRUE)) {
        type = INTERCEPT_DIGITAL_PRODUCT_ID;
    } else if (cfgSpoofInstallIds &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValInstallDate, TRUE)) {
        type = INTERCEPT_INSTALL_DATE;
    } else if (cfgSpoofEdidSerial &&
        RtlEqualUnicodeString(preInfo->ValueName, &g_ValEdid, TRUE)) {
        type = INTERCEPT_EDID;
    } else if (cfgSpoofGpu &&
        (RtlEqualUnicodeString(preInfo->ValueName, &g_ValDriverDesc, TRUE) ||
         RtlEqualUnicodeString(preInfo->ValueName, &g_ValAdapterString, TRUE) ||
         RtlEqualUnicodeString(preInfo->ValueName, &g_ValBiosString, TRUE))) {
        type = INTERCEPT_GPU_DESCRIPTION;
    } else if (cfgSpoofGpu &&
        (RtlEqualUnicodeString(preInfo->ValueName, &g_ValGpuSerial, TRUE) ||
         RtlEqualUnicodeString(preInfo->ValueName, &g_ValGpuSerialAlt, TRUE))) {
        type = INTERCEPT_GPU_SERIAL;
    }

    if (type == INTERCEPT_NONE) return STATUS_SUCCESS;

    /* ── Verify the key path matches the expected location ─────────── */
    PUNICODE_STRING keyName = NULL;
    NTSTATUS st = CmCallbackGetKeyObjectIDEx(
                      &g_Driver.RegCookie, preInfo->Object,
                      NULL, &keyName, 0);
    if (!NT_SUCCESS(st) || !keyName) return STATUS_SUCCESS;

    BOOLEAN keyOk = FALSE;

    switch (type) {
    case INTERCEPT_MACHINE_GUID:
        keyOk = RtlEqualUnicodeString(keyName, &g_KeyCryptography, TRUE);
        break;
    case INTERCEPT_NETWORK_ADDRESS:
        keyOk = StartsWith(keyName, &g_KeyNicClassPrefix);
        break;
    case INTERCEPT_PRODUCT_ID:
    case INTERCEPT_DIGITAL_PRODUCT_ID:
    case INTERCEPT_INSTALL_DATE:
        keyOk = RtlEqualUnicodeString(keyName, &g_KeyCurrentVersion, TRUE);
        break;
    case INTERCEPT_EDID:
        keyOk = StartsWith(keyName, &g_KeyDisplayPrefix) &&
                EndsWith(keyName, &g_SubDeviceParameters);
        break;
    case INTERCEPT_GPU_DESCRIPTION:
    case INTERCEPT_GPU_SERIAL:
        keyOk = StartsWith(keyName, &g_KeyGpuClassPrefix);
        break;
    default:
        break;
    }

    CmCallbackReleaseKeyObjectIDEx(keyName);
    if (!keyOk) return STATUS_SUCCESS;

    /* ── Snapshot config values under lock ──────────────────────────── */
    WCHAR  localGuid  [SPOOFER_GUID_LEN]       = { 0 };
    CHAR   localMac   [SPOOFER_MAC_LEN]         = { 0 };
    WCHAR  localProdId[SPOOFER_PRODUCT_ID_LEN]  = { 0 };
    ULONG  localInstDate = 0;
    ULONG  localEdidSn   = 0;
    UCHAR  localDpidBytes[16] = { 0 };
    WCHAR  localGpuDesc[128] = { 0 };
    CHAR   localGpuSerial[64] = { 0 };

    {
        KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
        RtlCopyMemory(localGuid,   g_Driver.Config.FakeMachineGuid,
                      SPOOFER_GUID_LEN * sizeof(WCHAR));
        RtlCopyMemory(localMac,    g_Driver.Config.FakeMacAddress,
                      SPOOFER_MAC_LEN);
        RtlCopyMemory(localProdId, g_Driver.Config.FakeProductId,
                      SPOOFER_PRODUCT_ID_LEN * sizeof(WCHAR));
        localInstDate = g_Driver.Config.FakeInstallDate;
        localEdidSn   = g_Driver.Config.FakeEdidSerial;
        RtlCopyMemory(localDpidBytes, g_Driver.Config.FakeDigitalProductBytes,
                      sizeof(localDpidBytes));
        RtlCopyMemory(localGpuDesc, g_Driver.Config.FakeGpuDescription,
                      sizeof(localGpuDesc));
        RtlCopyMemory(localGpuSerial, g_Driver.Config.FakeGpuSerial, 64);
        ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);
    }

    /* ── Dispatch to the appropriate patch logic ───────────────────── */
    PVOID kvInfo = preInfo->KeyValueInformation;
    ULONG bufLen = preInfo->Length;

    switch (type) {

    case INTERCEPT_MACHINE_GUID:
    {
        PCWSTR fake = localGuid;
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchStringValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo, fake, bufLen);
            break;
        case KeyValueFullInformation:
            PatchFullStringValue((PKEY_VALUE_FULL_INFORMATION)kvInfo, bufLen, fake);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_NETWORK_ADDRESS:
    {
        WCHAR macWide[SPOOFER_MAC_LEN * 2] = { 0 };
        for (ULONG i = 0; i < SPOOFER_MAC_LEN && localMac[i]; i++) {
            macWide[i] = (WCHAR)(UCHAR)localMac[i];
        }
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchStringValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo, macWide, bufLen);
            break;
        case KeyValueFullInformation:
            PatchFullStringValue((PKEY_VALUE_FULL_INFORMATION)kvInfo, bufLen, macWide);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_PRODUCT_ID:
    {
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchStringValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo,
                             localProdId, bufLen);
            break;
        case KeyValueFullInformation:
            PatchFullStringValue((PKEY_VALUE_FULL_INFORMATION)kvInfo,
                                 bufLen, localProdId);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_DIGITAL_PRODUCT_ID:
    {
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchDigitalProductIdPartial(
                (PKEY_VALUE_PARTIAL_INFORMATION)kvInfo, localDpidBytes);
            break;
        case KeyValueFullInformation:
            PatchDigitalProductIdFull(
                (PKEY_VALUE_FULL_INFORMATION)kvInfo, bufLen, localDpidBytes);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_INSTALL_DATE:
    {
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchDwordValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo, localInstDate);
            break;
        case KeyValueFullInformation:
            PatchFullDwordValue((PKEY_VALUE_FULL_INFORMATION)kvInfo,
                                bufLen, localInstDate);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_EDID:
    {
        switch (preInfo->KeyValueInformationClass) {
        case KeyValuePartialInformation:
            PatchEdidPartial((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo, localEdidSn);
            break;
        case KeyValueFullInformation:
            PatchEdidFull((PKEY_VALUE_FULL_INFORMATION)kvInfo, bufLen, localEdidSn);
            break;
        default: break;
        }
        break;
    }

    case INTERCEPT_GPU_DESCRIPTION:
    {
        if (localGpuDesc[0]) {
            switch (preInfo->KeyValueInformationClass) {
            case KeyValuePartialInformation:
                PatchStringValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo,
                                 localGpuDesc, bufLen);
                break;
            case KeyValueFullInformation:
                PatchFullStringValue((PKEY_VALUE_FULL_INFORMATION)kvInfo,
                                     bufLen, localGpuDesc);
                break;
            default: break;
            }
        }
        break;
    }

    case INTERCEPT_GPU_SERIAL:
    {
        if (localGpuSerial[0]) {
            WCHAR gpuSerialWide[64] = { 0 };
            for (ULONG i = 0; i < 63 && localGpuSerial[i]; i++)
                gpuSerialWide[i] = (WCHAR)(UCHAR)localGpuSerial[i];
            switch (preInfo->KeyValueInformationClass) {
            case KeyValuePartialInformation:
                PatchStringValue((PKEY_VALUE_PARTIAL_INFORMATION)kvInfo,
                                 gpuSerialWide, bufLen);
                break;
            case KeyValueFullInformation:
                PatchFullStringValue((PKEY_VALUE_FULL_INFORMATION)kvInfo,
                                     bufLen, gpuSerialWide);
                break;
            default: break;
            }
        }
        break;
    }

    default:
        break;
    }

    InterlockedIncrement(&g_Driver.TotalIntercepts);
    TRACE("[VolFlt] Registry intercept [%d]: %wZ -> (spoofed)\n",
             (int)type, preInfo->ValueName);

    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════ */

NTSTATUS RegSpoof_Register(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370000");

    NTSTATUS st = CmRegisterCallbackEx(
                      RegNotifyCallback,
                      &altitude,
                      DriverObject,
                      NULL,
                      &g_Driver.RegCookie,
                      NULL);

    if (!NT_SUCCESS(st)) {
        TRACE("[VolFlt] CmRegisterCallbackEx failed: 0x%08X\n", st);
    } else {
        TRACE("[VolFlt] Registry callback registered\n");
    }
    return st;
}

VOID RegSpoof_Unregister(VOID)
{
    if (g_Driver.RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_Driver.RegCookie);
        g_Driver.RegCookie.QuadPart = 0;
        TRACE("[VolFlt] Registry callback unregistered\n");
    }
}
