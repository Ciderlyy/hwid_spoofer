/*
 * hypervisor/ept_hook.c
 *
 * EPT-based invisible hook dispatch for spoofing subsystems.
 *
 *  5b. Disk spoofing via EPT — completion routine approach
 *  5c. Module hiding via NtQuerySystemInformation hook
 *  5e. SMBIOS interception via same NtQuerySystemInformation hook
 */

#include "hv.h"
#include <intrin.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <ntifs.h>

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object);

extern POBJECT_TYPE IoDriverObjectType;
extern DRIVER_GLOBAL g_Driver;

/* Forward declarations from smbios_spoof.c */
extern VOID PatchSmbiosTable(PUCHAR tableData, ULONG tableLen);
extern VOID PatchAcpiTable(ULONG tableId, PUCHAR tableData, ULONG tableLen);

/* ═══════════════════════════════════════════════════════════════════════
 * 5b. Disk serial spoofing via EPT + completion routine
 *
 * The hook replaces disk.sys!DiskDeviceControl. It sets a completion
 * routine on the IRP BEFORE forwarding to the original handler.
 * The completion routine fires when the IRP completes (sync or async)
 * and patches the output buffer safely.
 * ═══════════════════════════════════════════════════════════════════════ */

static PVOID g_OrigDiskDispatch = NULL;

typedef NTSTATUS (*PFN_DISPATCH)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

typedef struct _DISK_HOOK_CTX {
    ULONG IoControlCode;
    PIO_COMPLETION_ROUTINE OriginalCompletion;
    PVOID OriginalContext;
    BOOLEAN InvokeOnSuccess;
    BOOLEAN InvokeOnError;
    BOOLEAN InvokeOnCancel;
} DISK_HOOK_CTX, *PDISK_HOOK_CTX;

static VOID PatchStorageSerial(PVOID Buffer, ULONG BufferLength)
{
    if (!Buffer || BufferLength < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        return;

    PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)Buffer;
    if (desc->SerialNumberOffset == 0 ||
        desc->SerialNumberOffset >= BufferLength)
        return;

    PCHAR serial = (PCHAR)((PUCHAR)Buffer + desc->SerialNumberOffset);
    ULONG maxLen = BufferLength - desc->SerialNumberOffset;

    KIRQL irql;
    irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
    CHAR localSerial[SPOOFER_DISK_SERIAL_LEN];
    RtlCopyMemory(localSerial, g_Driver.Config.FakeDiskSerial,
                  SPOOFER_DISK_SERIAL_LEN);
    ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);

    if (!localSerial[0]) return;

    ULONG copyLen = (ULONG)strlen(localSerial);
    if (copyLen >= maxLen) copyLen = maxLen - 1;
    RtlCopyMemory(serial, localSerial, copyLen);
    serial[copyLen] = '\0';
}

static NTSTATUS DiskHookCompletion(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context)
{
    PDISK_HOOK_CTX ctx = (PDISK_HOOK_CTX)Context;
    if (!ctx) goto done;

    if (NT_SUCCESS(Irp->IoStatus.Status) &&
        ctx->IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
        PatchStorageSerial(
            Irp->AssociatedIrp.SystemBuffer,
            (ULONG)Irp->IoStatus.Information);
        InterlockedIncrement(&g_Driver.TotalIntercepts);
    }

    /* Chain to the original completion routine if one was set */
    if (ctx->OriginalCompletion) {
        BOOLEAN invoke = FALSE;
        if (NT_SUCCESS(Irp->IoStatus.Status) && ctx->InvokeOnSuccess) invoke = TRUE;
        if (!NT_SUCCESS(Irp->IoStatus.Status) && ctx->InvokeOnError) invoke = TRUE;
        if (Irp->Cancel && ctx->InvokeOnCancel) invoke = TRUE;
        if (invoke) {
            PIO_COMPLETION_ROUTINE savedCompletion = ctx->OriginalCompletion;
            PVOID savedContext = ctx->OriginalContext;
            ExFreePoolWithTag(ctx, 'EpSh');
            return savedCompletion(DeviceObject, Irp, savedContext);
        }
    }

done:
    if (ctx) ExFreePoolWithTag(ctx, 'EpSh');

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS HookedDiskDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

    /* Only intercept storage query property; pass everything else through */
    if (ioctl != IOCTL_STORAGE_QUERY_PROPERTY) {
        PFN_DISPATCH orig = (PFN_DISPATCH)g_OrigDiskDispatch;
        return orig(DeviceObject, Irp);
    }

    /* Allocate completion context — non-paged, safe at any IRQL */
    PDISK_HOOK_CTX ctx = (PDISK_HOOK_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DISK_HOOK_CTX), 'EpSh');
    if (!ctx) {
        PFN_DISPATCH orig = (PFN_DISPATCH)g_OrigDiskDispatch;
        return orig(DeviceObject, Irp);
    }

    ctx->IoControlCode = ioctl;

    /* Save and replace any existing completion routine */
    ctx->OriginalCompletion = stack->CompletionRoutine;
    ctx->OriginalContext    = stack->Context;
    ctx->InvokeOnSuccess    = (stack->Control & SL_INVOKE_ON_SUCCESS) != 0;
    ctx->InvokeOnError      = (stack->Control & SL_INVOKE_ON_ERROR) != 0;
    ctx->InvokeOnCancel     = (stack->Control & SL_INVOKE_ON_CANCEL) != 0;

    stack->CompletionRoutine = DiskHookCompletion;
    stack->Context           = ctx;
    stack->Control           = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;

    PFN_DISPATCH orig = (PFN_DISPATCH)g_OrigDiskDispatch;
    return orig(DeviceObject, Irp);
}

NTSTATUS EptHook_InstallDiskHook(VOID)
{
    if (!HvIsActive()) return STATUS_NOT_SUPPORTED;

    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    PDRIVER_OBJECT diskDriver = NULL;
    NTSTATUS st = ObReferenceObjectByName(
        &driverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
        0, IoDriverObjectType, KernelMode, NULL,
        (PVOID*)&diskDriver);
    if (!NT_SUCCESS(st)) return st;

    PVOID target = diskDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    ObDereferenceObject(diskDriver);

    if (!target) return STATUS_UNSUCCESSFUL;

    PVOID trampoline = NULL;
    st = HvInstallEptHook(target, (PVOID)HookedDiskDeviceControl, &trampoline);
    if (NT_SUCCESS(st)) g_OrigDiskDispatch = trampoline;
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════
 * 5c + 5e. Module hiding + SMBIOS interception
 *
 * Both piggyback on NtQuerySystemInformation. The hook checks:
 *   - SystemModuleInformation (11): strip our driver from the list
 *   - SystemFirmwareTableInformation (76): patch SMBIOS table data
 * ═══════════════════════════════════════════════════════════════════════ */

static PVOID g_OrigNtQuerySystemInfo = NULL;

typedef NTSTATUS (NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#define SystemModuleInformation_Class 11
#define SystemFirmwareTableInformation_Class 76

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#pragma pack(push, 1)
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG  ProviderSignature;
    ULONG  Action;
    ULONG  TableID;
    ULONG  TableBufferLength;
    UCHAR  TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef struct _RAW_SMBIOS_DATA_HDR {
    UCHAR  Used20CallingMethod;
    UCHAR  SMBIOSMajorVersion;
    UCHAR  SMBIOSMinorVersion;
    UCHAR  DmiRevision;
    ULONG  Length;
    UCHAR  SMBIOSTableData[1];
} RAW_SMBIOS_DATA_HDR;
#pragma pack(pop)


static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength)
{
    PFN_NTQUERYSYSTEMINFORMATION orig =
        (PFN_NTQUERYSYSTEMINFORMATION)g_OrigNtQuerySystemInfo;

    NTSTATUS st = orig(SystemInformationClass, SystemInformation,
                       SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(st)) return st;

    /* ── Module hiding ──────────────────────────────────────────────── */
    if (SystemInformationClass == SystemModuleInformation_Class &&
        SystemInformation) {
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)SystemInformation;
        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
            PCHAR name = (PCHAR)mods->Modules[i].FullPathName +
                         mods->Modules[i].OffsetToFileName;
            ANSI_STRING ansiName, target;
            RtlInitAnsiString(&ansiName, name);
            RtlInitAnsiString(&target, "volflt.sys");
            if (RtlEqualString(&ansiName, &target, TRUE)) {
                ULONG remaining = mods->NumberOfModules - i - 1;
                if (remaining > 0) {
                    RtlMoveMemory(&mods->Modules[i],
                                  &mods->Modules[i + 1],
                                  remaining * sizeof(RTL_PROCESS_MODULE_INFORMATION));
                }
                mods->NumberOfModules--;
                if (ReturnLength && *ReturnLength >= sizeof(RTL_PROCESS_MODULE_INFORMATION))
                    *ReturnLength -= sizeof(RTL_PROCESS_MODULE_INFORMATION);
                break;
            }
        }
    }

    /* ── SMBIOS firmware table patching ─────────────────────────────── */
    BOOLEAN spoofSmbios = FALSE;
    {
        KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
        spoofSmbios = g_Driver.Config.SpoofSmbios;
        ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);
    }
    if (SystemInformationClass == SystemFirmwareTableInformation_Class &&
        SystemInformation && spoofSmbios) {
        PSYSTEM_FIRMWARE_TABLE_INFORMATION fwInfo =
            (PSYSTEM_FIRMWARE_TABLE_INFORMATION)SystemInformation;
        ULONG hdrSize = FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
        if (fwInfo->ProviderSignature == 'RSMB' && fwInfo->Action == 1) {
            RAW_SMBIOS_DATA_HDR* raw = (RAW_SMBIOS_DATA_HDR*)fwInfo->TableBuffer;
            if (SystemInformationLength > hdrSize + sizeof(RAW_SMBIOS_DATA_HDR) &&
                raw->Length > 0 && raw->Length <= 0x10000) {
                PatchSmbiosTable(raw->SMBIOSTableData, raw->Length);
            }
        } else if (fwInfo->ProviderSignature == 'ACPI' && fwInfo->Action == 1 &&
                   SystemInformationLength > hdrSize + fwInfo->TableBufferLength) {
            PatchAcpiTable(fwInfo->TableID, fwInfo->TableBuffer, fwInfo->TableBufferLength);
        }
    }

    return st;
}

NTSTATUS EptHook_InstallModuleHide(VOID)
{
    if (!HvIsActive()) return STATUS_NOT_SUPPORTED;

    UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
    PVOID target = MmGetSystemRoutineAddress(&funcName);
    if (!target) return STATUS_NOT_FOUND;

    PVOID trampoline = NULL;
    NTSTATUS st = HvInstallEptHook(target,
                                    (PVOID)HookedNtQuerySystemInformation,
                                    &trampoline);
    if (NT_SUCCESS(st)) g_OrigNtQuerySystemInfo = trampoline;
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════
 * 5f. Volume serial spoofing via NtQueryVolumeInformationFile
 *
 * GetVolumeInformation uses this. Patch FILE_FS_VOLUME_INFORMATION.
 * ═══════════════════════════════════════════════════════════════════════ */

#define FileFsVolumeInformation 1

#pragma pack(push, 1)
typedef struct _FILE_FS_VOLUME_INFO {
    LARGE_INTEGER VolumeCreationTime;
    ULONG         VolumeSerialNumber;
    ULONG         VolumeLabelLength;
    BOOLEAN       SupportsObjects;
    WCHAR         VolumeLabel[1];
} FILE_FS_VOLUME_INFO, *PFILE_FS_VOLUME_INFO;
#pragma pack(pop)

static PVOID g_OrigNtQueryVolumeInfo = NULL;

typedef NTSTATUS (NTAPI *PFN_NTQUERYVOLUMEINFORMATIONFILE)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    ULONG FsInformationClass);

static NTSTATUS NTAPI HookedNtQueryVolumeInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    ULONG FsInformationClass)
{
    PFN_NTQUERYVOLUMEINFORMATIONFILE orig =
        (PFN_NTQUERYVOLUMEINFORMATIONFILE)g_OrigNtQueryVolumeInfo;

    NTSTATUS st = orig(FileHandle, IoStatusBlock, FsInformation,
                       Length, FsInformationClass);
    if (!NT_SUCCESS(st)) return st;

    if (FsInformationClass == FileFsVolumeInformation &&
        FsInformation && Length >= sizeof(FILE_FS_VOLUME_INFO)) {
        KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
        ULONG fakeSerial = g_Driver.Config.FakeVolumeSerial;
        BOOLEAN spoof = g_Driver.Config.SpoofVolumeSerial;
        ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);
        if (spoof && fakeSerial != 0) {
            PFILE_FS_VOLUME_INFO vol = (PFILE_FS_VOLUME_INFO)FsInformation;
            vol->VolumeSerialNumber = fakeSerial;
        }
    }
    return st;
}

NTSTATUS EptHook_InstallVolumeHook(VOID)
{
    if (!HvIsActive()) return STATUS_NOT_SUPPORTED;

    UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"NtQueryVolumeInformationFile");
    PVOID target = MmGetSystemRoutineAddress(&funcName);
    if (!target) return STATUS_NOT_FOUND;

    PVOID trampoline = NULL;
    NTSTATUS st = HvInstallEptHook(target,
                                    (PVOID)HookedNtQueryVolumeInformationFile,
                                    &trampoline);
    if (NT_SUCCESS(st)) g_OrigNtQueryVolumeInfo = trampoline;
    return st;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Phase 5 entry point
 * ═══════════════════════════════════════════════════════════════════════ */

NTSTATUS EptHooks_Initialize(VOID)
{
    /* Module hiding + SMBIOS interception share the same hook */
    EptHook_InstallModuleHide();

    /* Disk serial spoofing */
    EptHook_InstallDiskHook();

    /* Volume serial spoofing (GetVolumeInformation path) */
    EptHook_InstallVolumeHook();

    return STATUS_SUCCESS;
}

VOID EptHooks_Cleanup(VOID)
{
    if (g_OrigDiskDispatch) {
        UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
        PDRIVER_OBJECT diskDriver = NULL;
        NTSTATUS st = ObReferenceObjectByName(
            &driverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
            0, IoDriverObjectType, KernelMode, NULL,
            (PVOID*)&diskDriver);
        if (NT_SUCCESS(st)) {
            HvRemoveEptHook(diskDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
            ObDereferenceObject(diskDriver);
        }
        g_OrigDiskDispatch = NULL;
    }

    if (g_OrigNtQuerySystemInfo) {
        UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
        PVOID target = MmGetSystemRoutineAddress(&funcName);
        if (target) HvRemoveEptHook(target);
        g_OrigNtQuerySystemInfo = NULL;
    }

    if (g_OrigNtQueryVolumeInfo) {
        UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"NtQueryVolumeInformationFile");
        PVOID target = MmGetSystemRoutineAddress(&funcName);
        if (target) HvRemoveEptHook(target);
        g_OrigNtQueryVolumeInfo = NULL;
    }
}
