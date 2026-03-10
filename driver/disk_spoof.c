/*
 * driver/disk_spoof.c
 *
 * Disk serial number spoofing via a storage stack filter device.
 *
 * Interception paths
 * ──────────────────
 *  a) IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty
 *     Standard Win32/WMI path.  Patches STORAGE_DEVICE_DESCRIPTOR.SerialNumber.
 *
 *  b) IOCTL_SCSI_PASS_THROUGH (METHOD_BUFFERED)
 *     Raw SCSI INQUIRY VPD page 0x80 (Unit Serial Number).
 *     Data buffer is appended to SystemBuffer at DataBufferOffset.
 *
 *  c) IOCTL_SCSI_PASS_THROUGH_DIRECT (METHOD_BUFFERED, user-mode data ptr)
 *     Same SCSI path but DataBuffer is a raw user-mode address.
 *     Requires manual MDL probe+lock in dispatch, cleanup in completion.
 *
 *  d) IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe Identify Controller)
 *     Admin opcode 0x06, CNS=0x01.  Patches the 20-byte SN field at
 *     offset 4 of the Identify Controller Data Structure.
 */

#include "driver.h"

/* ─── NVMe constants (NVM Express Base Spec) ─────────────────────────── */
#define NVME_ADMIN_OPCODE_IDENTIFY      0x06u
#define NVME_IDENTIFY_CNS_CONTROLLER    0x01u
#define NVME_IDENTIFY_SN_OFFSET         4u
#define NVME_IDENTIFY_SN_LENGTH         20u
#define NVME_PASSTHRU_CMD_MIN_LEN       44u  /* minimum STORAGE_PROTOCOL_COMMAND.CommandLength for NVMe */

/* ─── SCSI INQUIRY constants ─────────────────────────────────────────── */
#define SCSI_OPCODE_INQUIRY             0x12u
#define SCSI_INQUIRY_EVPD_BIT           0x01u
#define SCSI_VPD_UNIT_SERIAL_NUMBER     0x80u
#define SCSI_VPD_SERIAL_DATA_OFFSET     4u

/* ─── Forward declarations ───────────────────────────────────────────── */
static NTSTATUS Filter_DeviceControl           (_In_ PDEVICE_OBJECT, _Inout_ PIRP);
static NTSTATUS Filter_Pnp                     (_In_ PDEVICE_OBJECT, _Inout_ PIRP);
static NTSTATUS Filter_Power                   (_In_ PDEVICE_OBJECT, _Inout_ PIRP);
static NTSTATUS Filter_PassThrough             (_In_ PDEVICE_OBJECT, _Inout_ PIRP);
static NTSTATUS StorageCompletion              (_In_ PDEVICE_OBJECT, _In_ PIRP,
                                                _In_opt_ PVOID);
static NTSTATUS ScsiPassThroughCompletion      (_In_ PDEVICE_OBJECT, _In_ PIRP,
                                                _In_opt_ PVOID);
static NTSTATUS ScsiPassThroughDirectCompletion(_In_ PDEVICE_OBJECT, _In_ PIRP,
                                                _In_opt_ PVOID);
static NTSTATUS NvmeProtocolCompletion         (_In_ PDEVICE_OBJECT, _In_ PIRP,
                                                _In_opt_ PVOID);

/* ═══════════════════════════════════════════════════════════════════════
 * SnapshotFakeSerial — lock-safe read of FakeDiskSerial into a local buf
 * ═══════════════════════════════════════════════════════════════════════ */

static ULONG SnapshotFakeSerial(_Out_writes_(SPOOFER_DISK_SERIAL_LEN) PCHAR out)
{
    KIRQL irql = ExAcquireSpinLockShared(&g_Driver.ConfigLock);
    RtlCopyMemory(out, g_Driver.Config.FakeDiskSerial, SPOOFER_DISK_SERIAL_LEN);
    ExReleaseSpinLockShared(&g_Driver.ConfigLock, irql);
    return (ULONG)strnlen(out, SPOOFER_DISK_SERIAL_LEN - 1);
}

/* ═══════════════════════════════════════════════════════════════════════
 * AttachToDisk
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS AttachToDisk(
    _In_ PDEVICE_OBJECT  TargetDevice,
    _In_ PDRIVER_OBJECT  DriverObject)
{
    ULONG slot = MAX_DISK_FILTERS;
    for (ULONG i = 0; i < g_Driver.FilterCount; i++) {
        if (g_Driver.FilterDevices[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == MAX_DISK_FILTERS) {
        if (g_Driver.FilterCount >= MAX_DISK_FILTERS) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        slot = g_Driver.FilterCount;
    }

    PDEVICE_OBJECT filterDev = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        sizeof(DISK_FILTER_EXT),
        NULL,
        TargetDevice->DeviceType,
        TargetDevice->Characteristics,
        FALSE,
        &filterDev);

    if (!NT_SUCCESS(status)) return status;

    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)filterDev->DeviceExtension;
    ext->Type = DEVEXT_TYPE_DISK_FILTER;

    filterDev->Flags |= (TargetDevice->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO));
    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;

    ext->LowerDevice = IoAttachDeviceToDeviceStack(filterDev, TargetDevice);
    if (!ext->LowerDevice) {
        IoDeleteDevice(filterDev);
        return STATUS_UNSUCCESSFUL;
    }

    if (g_Driver.FilterCount == 0) {
        DriverObject->MajorFunction[IRP_MJ_PNP]   = Filter_Pnp;
        DriverObject->MajorFunction[IRP_MJ_POWER]  = Filter_Power;
        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            if (i != IRP_MJ_DEVICE_CONTROL &&
                i != IRP_MJ_PNP            &&
                i != IRP_MJ_POWER) {
                DriverObject->MajorFunction[i] = Filter_PassThrough;
            }
        }
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Filter_DeviceControl;

    g_Driver.FilterDevices[slot] = filterDev;
    if (slot == g_Driver.FilterCount) g_Driver.FilterCount++;
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 * DiskSpoof_Attach
 * ═══════════════════════════════════════════════════════════════════════ */

NTSTATUS DiskSpoof_Attach(_In_ PDRIVER_OBJECT DriverObject)
{
    ULONG attached = 0;

    for (ULONG idx = 0; idx < 16; idx++) {
        WCHAR           nameBuf[64] = { 0 };
        UNICODE_STRING  diskName;
        PFILE_OBJECT    fileObj = NULL;
        PDEVICE_OBJECT  diskDev = NULL;

        /* DR index usually matches Harddisk index but may diverge on
           hot-swap or multi-path setups; Partition0 fallback covers those. */
        RtlStringCbPrintfW(nameBuf, sizeof(nameBuf),
                           L"\\Device\\Harddisk%lu\\DR%lu", idx, idx);
        RtlInitUnicodeString(&diskName, nameBuf);

        NTSTATUS st = IoGetDeviceObjectPointer(
                          &diskName, FILE_READ_ATTRIBUTES, &fileObj, &diskDev);
        if (!NT_SUCCESS(st)) {
            RtlStringCbPrintfW(nameBuf, sizeof(nameBuf),
                               L"\\Device\\Harddisk%lu\\Partition0", idx);
            RtlInitUnicodeString(&diskName, nameBuf);
            st = IoGetDeviceObjectPointer(&diskName, FILE_READ_ATTRIBUTES,
                                          &fileObj, &diskDev);
            if (!NT_SUCCESS(st)) continue;
        }

        st = AttachToDisk(diskDev, DriverObject);
        ObDereferenceObject(fileObj);

        if (NT_SUCCESS(st)) {
            attached++;
            TRACE("[VolFlt] Attached filter to %wZ\n", &diskName);
        } else {
            TRACE("[VolFlt] AttachToDisk[%lu] failed: 0x%08X\n", idx, st);
        }
    }

    TRACE("[VolFlt] DiskSpoof_Attach: %lu filter(s) installed\n", attached);
    return (attached > 0) ? STATUS_SUCCESS : STATUS_DEVICE_NOT_CONNECTED;
}

/* ═══════════════════════════════════════════════════════════════════════
 * DiskSpoof_DetachAll
 * ═══════════════════════════════════════════════════════════════════════ */

VOID DiskSpoof_DetachAll(VOID)
{
    for (ULONG i = 0; i < g_Driver.FilterCount; i++) {
        PDEVICE_OBJECT filterDev = g_Driver.FilterDevices[i];
        if (!filterDev) continue;

        PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)filterDev->DeviceExtension;
        if (ext->LowerDevice) {
            IoDetachDevice(ext->LowerDevice);
            ext->LowerDevice = NULL;
        }
        IoDeleteDevice(filterDev);
        g_Driver.FilterDevices[i] = NULL;
    }
    g_Driver.FilterCount = 0;
    TRACE("[VolFlt] All disk filters removed\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * Completion 1: IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty
 * ═══════════════════════════════════════════════════════════════════════ */

#define DISK_COMPLETION_DELAY_US  20   /* Mask hook overhead; 15–25 us typical for bare metal */

static NTSTATUS StorageCompletion(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_     PIRP           Irp,
    _In_opt_ PVOID          Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    KeStallExecutionProcessor(DISK_COMPLETION_DELAY_US);
    if (!NT_SUCCESS(Irp->IoStatus.Status)) goto done;

    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG bufLen = (ULONG)Irp->IoStatus.Information;

    if (!sysBuf || bufLen < sizeof(STORAGE_DEVICE_DESCRIPTOR)) goto done;

    PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)sysBuf;
    if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= bufLen) goto done;

    PCHAR serial = (PCHAR)sysBuf + desc->SerialNumberOffset;
    ULONG maxLen = bufLen - desc->SerialNumberOffset - 1;

    CHAR  localSerial[SPOOFER_DISK_SERIAL_LEN];
    ULONG fakeLen = SnapshotFakeSerial(localSerial);
    if (fakeLen == 0 || fakeLen > maxLen) goto done;

    RtlZeroMemory(serial, maxLen + 1);
    RtlCopyMemory(serial, localSerial, fakeLen);

    InterlockedIncrement(&g_Driver.TotalIntercepts);
    TRACE("[VolFlt] [STORAGE_QUERY] disk serial spoofed\n");

done:
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Completion 2a: IOCTL_SCSI_PASS_THROUGH (METHOD_BUFFERED)
 *
 * Data buffer is in SystemBuffer at spt->DataBufferOffset.
 * VPD 0x80 response: byte 0=devtype, 1=0x80, 2=0, 3=len, 4+=serial.
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS ScsiPassThroughCompletion(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_     PIRP           Irp,
    _In_opt_ PVOID          Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    KeStallExecutionProcessor(DISK_COMPLETION_DELAY_US);
    if (!NT_SUCCESS(Irp->IoStatus.Status)) goto done;

    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG bufLen = (ULONG)Irp->IoStatus.Information;
    if (!sysBuf || bufLen < sizeof(SCSI_PASS_THROUGH)) goto done;

    PSCSI_PASS_THROUGH spt = (PSCSI_PASS_THROUGH)sysBuf;

    if (spt->CdbLength < 6)                         goto done;
    if (spt->Cdb[0] != SCSI_OPCODE_INQUIRY)         goto done;
    if (!(spt->Cdb[1] & SCSI_INQUIRY_EVPD_BIT))     goto done;
    if (spt->Cdb[2] != SCSI_VPD_UNIT_SERIAL_NUMBER) goto done;

    if (spt->DataBufferOffset < sizeof(SCSI_PASS_THROUGH)) goto done;
    if (spt->DataBufferOffset >= bufLen)                    goto done;

    PUCHAR vpdBuf    = (PUCHAR)sysBuf + spt->DataBufferOffset;
    ULONG  vpdRemain = bufLen - (ULONG)spt->DataBufferOffset;

    if (vpdRemain <= SCSI_VPD_SERIAL_DATA_OFFSET) goto done;
    if (vpdBuf[1] != SCSI_VPD_UNIT_SERIAL_NUMBER) goto done;

    PUCHAR serialField  = vpdBuf + SCSI_VPD_SERIAL_DATA_OFFSET;
    ULONG  serialBufLen = vpdRemain - SCSI_VPD_SERIAL_DATA_OFFSET;

    CHAR  localSerial[SPOOFER_DISK_SERIAL_LEN];
    ULONG fakeLen = SnapshotFakeSerial(localSerial);
    if (fakeLen == 0) goto done;

    ULONG copyLen = (fakeLen < serialBufLen) ? fakeLen : serialBufLen;
    RtlFillMemory(serialField, serialBufLen, ' ');
    RtlCopyMemory(serialField, localSerial, copyLen);
    vpdBuf[3] = (UCHAR)(copyLen & 0xFF);

    InterlockedIncrement(&g_Driver.TotalIntercepts);
    TRACE("[VolFlt] [SCSI_PASS_THROUGH] VPD 0x80 serial spoofed\n");

done:
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Completion 2b: IOCTL_SCSI_PASS_THROUGH_DIRECT
 *
 * SPTD is also METHOD_BUFFERED, so Irp->MdlAddress is NULL.
 * The data buffer lives at a raw user-mode address (sptd->DataBuffer).
 * The dispatch routine locked the user pages into an MDL and passed
 * the system address + MDL through an SPTD_COMPLETION_CTX allocation.
 * We patch via that system address, then clean up the MDL + pool.
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS ScsiPassThroughDirectCompletion(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_     PIRP           Irp,
    _In_opt_ PVOID          Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KeStallExecutionProcessor(DISK_COMPLETION_DELAY_US);
    PSPTD_COMPLETION_CTX ctx = (PSPTD_COMPLETION_CTX)Context;

    if (!NT_SUCCESS(Irp->IoStatus.Status) || !ctx || !ctx->SystemAddress) {
        goto cleanup;
    }

    /* Verify CDB again from the SPT header in SystemBuffer, which is
       still valid at completion time for METHOD_BUFFERED IOCTLs. */
    PSCSI_PASS_THROUGH_DIRECT sptd =
        (PSCSI_PASS_THROUGH_DIRECT)Irp->AssociatedIrp.SystemBuffer;
    if (!sptd)                                        goto cleanup;
    if (sptd->CdbLength < 6)                          goto cleanup;
    if (sptd->Cdb[0] != SCSI_OPCODE_INQUIRY)          goto cleanup;
    if (!(sptd->Cdb[1] & SCSI_INQUIRY_EVPD_BIT))      goto cleanup;
    if (sptd->Cdb[2] != SCSI_VPD_UNIT_SERIAL_NUMBER)  goto cleanup;

    PUCHAR vpdBuf    = (PUCHAR)ctx->SystemAddress;
    ULONG  vpdRemain = ctx->BufferLength;

    if (vpdRemain <= SCSI_VPD_SERIAL_DATA_OFFSET) goto cleanup;
    if (vpdBuf[1] != SCSI_VPD_UNIT_SERIAL_NUMBER) goto cleanup;

    PUCHAR serialField  = vpdBuf + SCSI_VPD_SERIAL_DATA_OFFSET;
    ULONG  serialBufLen = vpdRemain - SCSI_VPD_SERIAL_DATA_OFFSET;

    CHAR  localSerial[SPOOFER_DISK_SERIAL_LEN];
    ULONG fakeLen = SnapshotFakeSerial(localSerial);
    if (fakeLen == 0) goto cleanup;

    ULONG copyLen = (fakeLen < serialBufLen) ? fakeLen : serialBufLen;
    RtlFillMemory(serialField, serialBufLen, ' ');
    RtlCopyMemory(serialField, localSerial, copyLen);
    vpdBuf[3] = (UCHAR)(copyLen & 0xFF);

    InterlockedIncrement(&g_Driver.TotalIntercepts);
    TRACE("[VolFlt] [SCSI_PASS_THROUGH_DIRECT] VPD 0x80 serial spoofed\n");

cleanup:
    if (ctx) {
        if (ctx->LockedMdl) {
            MmUnlockPages(ctx->LockedMdl);
            IoFreeMdl(ctx->LockedMdl);
        }
        ExFreePoolWithTag(ctx, POOL_TAG);
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Completion 3: IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe Identify Controller)
 *
 * METHOD_BUFFERED — everything is in SystemBuffer.
 * DataFromDeviceBufferOffset is relative to the STORAGE_PROTOCOL_COMMAND.
 * NVMe Identify Controller Data: SN at offset 4, 20 bytes, space-padded.
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS NvmeProtocolCompletion(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_     PIRP           Irp,
    _In_opt_ PVOID          Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    KeStallExecutionProcessor(DISK_COMPLETION_DELAY_US);
    if (!NT_SUCCESS(Irp->IoStatus.Status)) goto done;

    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG bufLen = (ULONG)Irp->IoStatus.Information;
    if (!sysBuf || bufLen < sizeof(STORAGE_PROTOCOL_COMMAND)) goto done;

    PSTORAGE_PROTOCOL_COMMAND proto = (PSTORAGE_PROTOCOL_COMMAND)sysBuf;
    if (proto->ProtocolType != ProtocolTypeNvme)  goto done;
    if (proto->CommandLength < NVME_PASSTHRU_CMD_MIN_LEN) goto done;
    if (proto->Command[0] != NVME_ADMIN_OPCODE_IDENTIFY) goto done;
    if ((proto->Command[40] & 0xFF) != NVME_IDENTIFY_CNS_CONTROLLER) goto done;

    if (proto->DataFromDeviceBufferOffset == 0) goto done;
    if (proto->DataFromDeviceTransferLength <
            NVME_IDENTIFY_SN_OFFSET + NVME_IDENTIFY_SN_LENGTH) goto done;

    ULONG dataOff = proto->DataFromDeviceBufferOffset;
    if (dataOff + proto->DataFromDeviceTransferLength > bufLen) goto done;

    PUCHAR snField = (PUCHAR)sysBuf + dataOff + NVME_IDENTIFY_SN_OFFSET;

    CHAR  localSerial[SPOOFER_DISK_SERIAL_LEN];
    ULONG fakeLen = SnapshotFakeSerial(localSerial);
    if (fakeLen == 0) goto done;

    ULONG copyLen = (fakeLen < NVME_IDENTIFY_SN_LENGTH)
                    ? fakeLen : NVME_IDENTIFY_SN_LENGTH;
    RtlFillMemory(snField, NVME_IDENTIFY_SN_LENGTH, ' ');
    RtlCopyMemory(snField, localSerial, copyLen);

    InterlockedIncrement(&g_Driver.TotalIntercepts);
    TRACE("[VolFlt] [NVME_PROTOCOL_CMD] Identify Controller SN spoofed\n");

done:
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

/* ═══════════════════════════════════════════════════════════════════════
 * IRP_MJ_DEVICE_CONTROL
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Filter_DeviceControl(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp)
{
    PCONTROL_DEV_EXT baseExt = (PCONTROL_DEV_EXT)DeviceObject->DeviceExtension;

    if (baseExt->Type == DEVEXT_TYPE_CONTROL) {
        return g_Driver.OriginalDeviceControl(DeviceObject, Irp);
    }

    PDISK_FILTER_EXT   ext   = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code  = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG              inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID              buf   = Irp->AssociatedIrp.SystemBuffer;

    if (!g_Driver.Active || !g_Driver.Config.SpoofDiskSerial) {
        goto passthrough;
    }

    /* ── Path 1: IOCTL_STORAGE_QUERY_PROPERTY ──────────────────────── */
    if (code == IOCTL_STORAGE_QUERY_PROPERTY) {
        if (buf && inLen >= sizeof(STORAGE_PROPERTY_QUERY)) {
            PSTORAGE_PROPERTY_QUERY q = (PSTORAGE_PROPERTY_QUERY)buf;
            if (q->PropertyId == StorageDeviceProperty &&
                q->QueryType  == PropertyStandardQuery) {
                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, StorageCompletion,
                                       NULL, TRUE, TRUE, TRUE);
                return IoCallDriver(ext->LowerDevice, Irp);
            }
        }
        goto passthrough;
    }

    /* ── Path 2a: IOCTL_SCSI_PASS_THROUGH (buffered) ───────────────── */
    if (code == IOCTL_SCSI_PASS_THROUGH) {
        if (buf && inLen >= sizeof(SCSI_PASS_THROUGH)) {
            PSCSI_PASS_THROUGH spt = (PSCSI_PASS_THROUGH)buf;
            if (spt->CdbLength >= 6                          &&
                spt->Cdb[0]  == SCSI_OPCODE_INQUIRY          &&
                (spt->Cdb[1] &  SCSI_INQUIRY_EVPD_BIT)       &&
                spt->Cdb[2]  == SCSI_VPD_UNIT_SERIAL_NUMBER) {
                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, ScsiPassThroughCompletion,
                                       NULL, TRUE, TRUE, TRUE);
                return IoCallDriver(ext->LowerDevice, Irp);
            }
        }
        goto passthrough;
    }

    /* ── Path 2b: IOCTL_SCSI_PASS_THROUGH_DIRECT ───────────────────── *
     * SPTD is METHOD_BUFFERED — Irp->MdlAddress is NULL.               *
     * sptd->DataBuffer is a raw user-mode pointer.  We MUST probe+lock  *
     * it here (PASSIVE_LEVEL, correct process context) and hand the     *
     * system address to the completion routine via a pool-allocated ctx. */
    if (code == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
        if (buf && inLen >= sizeof(SCSI_PASS_THROUGH_DIRECT)) {
            PSCSI_PASS_THROUGH_DIRECT sptd = (PSCSI_PASS_THROUGH_DIRECT)buf;
            if (sptd->CdbLength >= 6                          &&
                sptd->Cdb[0]  == SCSI_OPCODE_INQUIRY          &&
                (sptd->Cdb[1] &  SCSI_INQUIRY_EVPD_BIT)       &&
                sptd->Cdb[2]  == SCSI_VPD_UNIT_SERIAL_NUMBER  &&
                sptd->DataBuffer != NULL                       &&
                sptd->DataTransferLength > 0) {

                /* Allocate an MDL describing the user-mode data buffer */
                PMDL mdl = IoAllocateMdl(
                               sptd->DataBuffer,
                               sptd->DataTransferLength,
                               FALSE, FALSE, NULL);
                if (!mdl) goto passthrough;

                __try {
                    MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    IoFreeMdl(mdl);
                    goto passthrough;
                }

                PVOID sysAddr = MmGetSystemAddressForMdlSafe(
                                    mdl, NormalPagePriority);
                if (!sysAddr) {
                    MmUnlockPages(mdl);
                    IoFreeMdl(mdl);
                    goto passthrough;
                }

                PSPTD_COMPLETION_CTX ctx =
                    (PSPTD_COMPLETION_CTX)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sizeof(SPTD_COMPLETION_CTX), POOL_TAG);
                if (!ctx) {
                    MmUnlockPages(mdl);
                    IoFreeMdl(mdl);
                    goto passthrough;
                }
                ctx->LockedMdl     = mdl;
                ctx->SystemAddress = sysAddr;
                ctx->BufferLength  = sptd->DataTransferLength;

                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, ScsiPassThroughDirectCompletion,
                                       ctx, TRUE, TRUE, TRUE);
                return IoCallDriver(ext->LowerDevice, Irp);
            }
        }
        goto passthrough;
    }

    /* ── Path 3: IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe Identify) ────── */
    if (code == IOCTL_STORAGE_PROTOCOL_COMMAND) {
        if (buf && inLen >= sizeof(STORAGE_PROTOCOL_COMMAND)) {
            PSTORAGE_PROTOCOL_COMMAND proto = (PSTORAGE_PROTOCOL_COMMAND)buf;
            if (proto->ProtocolType  == ProtocolTypeNvme   &&
                proto->CommandLength >= 44                  &&
                proto->Command[0]    == NVME_ADMIN_OPCODE_IDENTIFY &&
                (proto->Command[40] & 0xFF) == NVME_IDENTIFY_CNS_CONTROLLER) {
                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, NvmeProtocolCompletion,
                                       NULL, TRUE, TRUE, TRUE);
                return IoCallDriver(ext->LowerDevice, Irp);
            }
        }
        goto passthrough;
    }

passthrough:
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ═══════════════════════════════════════════════════════════════════════
 * IRP_MJ_PNP
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Filter_Pnp(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp)
{
    PCONTROL_DEV_EXT baseExt = (PCONTROL_DEV_EXT)DeviceObject->DeviceExtension;
    if (baseExt->Type == DEVEXT_TYPE_CONTROL) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PDISK_FILTER_EXT   ext   = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        IoSkipCurrentIrpStackLocation(Irp);
        NTSTATUS st = IoCallDriver(ext->LowerDevice, Irp);

        IoDetachDevice(ext->LowerDevice);
        IoDeleteDevice(DeviceObject);

        for (ULONG i = 0; i < g_Driver.FilterCount; i++) {
            if (g_Driver.FilterDevices[i] == DeviceObject) {
                g_Driver.FilterDevices[i] = NULL;
                break;
            }
        }
        while (g_Driver.FilterCount > 0 &&
               g_Driver.FilterDevices[g_Driver.FilterCount - 1] == NULL) {
            g_Driver.FilterCount--;
        }
        return st;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ═══════════════════════════════════════════════════════════════════════
 * IRP_MJ_POWER
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Filter_Power(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp)
{
    PCONTROL_DEV_EXT baseExt = (PCONTROL_DEV_EXT)DeviceObject->DeviceExtension;
    if (baseExt->Type == DEVEXT_TYPE_CONTROL) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ext->LowerDevice, Irp);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Generic pass-through
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS Filter_PassThrough(
    _In_    PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP           Irp)
{
    PCONTROL_DEV_EXT baseExt = (PCONTROL_DEV_EXT)DeviceObject->DeviceExtension;
    if (baseExt->Type == DEVEXT_TYPE_CONTROL) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}
