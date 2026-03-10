/*
 * driver/driver.h
 * Kernel-mode internal declarations shared across all driver translation units.
 */

#pragma once

#define _KERNEL_MODE 1

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntddstor.h>   /* IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR */
#include <ntddscsi.h>

#include "../shared/protocol.h"

/* ─── Debug tracing — compiles to nothing in free (release) builds ──── */
#if DBG
#define TRACE(fmt, ...) DbgPrint(fmt, ##__VA_ARGS__)
#else
#define TRACE(fmt, ...) ((void)0)
#endif

/* ─── Pool tag (generic Windows-style) ───────────────────────────────── */
#define POOL_TAG        'fltV'   /* volume filter */
#define POOL_TAG_BUF    'fltB'   /* scratch buffers */

/* ─── Device extension types ─────────────────────────────────────────── */
#define DEVEXT_TYPE_CONTROL     0x1u   /* our named control device  */
#define DEVEXT_TYPE_DISK_FILTER 0x2u   /* disk stack filter device  */

/* Extension for the control device (DEVEXT_TYPE_CONTROL) */
typedef struct _CONTROL_DEV_EXT {
    ULONG Type;   /* must be first */
} CONTROL_DEV_EXT, *PCONTROL_DEV_EXT;

/* Extension for each disk filter device (DEVEXT_TYPE_DISK_FILTER) */
typedef struct _DISK_FILTER_EXT {
    ULONG           Type;            /* must be first */
    PDEVICE_OBJECT  LowerDevice;     /* device we're attached above */
} DISK_FILTER_EXT, *PDISK_FILTER_EXT;

/* ─── Driver global state ─────────────────────────────────────────────── */
#define MAX_DISK_FILTERS  16u

typedef struct _DRIVER_GLOBAL {
    /* Control device */
    PDEVICE_OBJECT   ControlDevice;

    /* Active config & flags — guarded by ConfigLock */
    SPOOFER_CONFIG   Config;
    EX_SPIN_LOCK     ConfigLock;    /* IRQL-safe: works at DISPATCH_LEVEL   */
    BOOLEAN          Active;
    LONG volatile    TotalIntercepts;
    FAST_MUTEX       StateMutex;    /* serializes ENABLE/DISABLE state transitions */

    /* Disk filter tracking */
    PDEVICE_OBJECT   FilterDevices[MAX_DISK_FILTERS];
    ULONG            FilterCount;

    /*
     * Saved pointer to the original Dispatch_DeviceControl from driver.c.
     * DiskSpoof_Attach overwrites MajorFunction[IRP_MJ_DEVICE_CONTROL] with
     * Filter_DeviceControl; Filter_DeviceControl calls this for the control
     * device path so we avoid infinite recursion.
     */
    PDRIVER_DISPATCH OriginalDeviceControl;

    /* Registry callback cookie */
    LARGE_INTEGER    RegCookie;

    /* Back-pointer to our DRIVER_OBJECT (needed in sub-modules) */
    PDRIVER_OBJECT   DriverObject;
} DRIVER_GLOBAL, *PDRIVER_GLOBAL;

extern DRIVER_GLOBAL g_Driver;

/* ─── Completion context for SCSI_PASS_THROUGH_DIRECT ────────────────── *
 * SPTD uses METHOD_BUFFERED but the data buffer is a raw user-mode       *
 * pointer (sptd->DataBuffer), NOT in SystemBuffer.  We must probe+lock   *
 * it ourselves in the dispatch routine (PASSIVE_LEVEL, correct process   *
 * context) and pass the system address through to the completion routine  *
 * which may run at DISPATCH_LEVEL in an arbitrary thread context.         */
typedef struct _SPTD_COMPLETION_CTX {
    PMDL    LockedMdl;
    PVOID   SystemAddress;
    ULONG   BufferLength;
} SPTD_COMPLETION_CTX, *PSPTD_COMPLETION_CTX;

/* ─── Sub-module exports: disk spoofing ──────────────────────────────── */
NTSTATUS DiskSpoof_Attach(_In_ PDRIVER_OBJECT DriverObject);
VOID     DiskSpoof_DetachAll(VOID);

/* ─── Sub-module exports: registry spoofing ─────────────────────────── */
NTSTATUS RegSpoof_Register(_In_ PDRIVER_OBJECT DriverObject);
VOID     RegSpoof_Unregister(VOID);

/* ─── Sub-module exports: SMBIOS spoofing ───────────────────────────── */
NTSTATUS SmbiosSpoof_Init(VOID);
VOID     SmbiosSpoof_Cleanup(VOID);

/* ─── Sub-module exports: GPU spoofing ──────────────────────────────── */
NTSTATUS GpuSpoof_Init(VOID);
VOID     GpuSpoof_Cleanup(VOID);

/* ─── Sub-module exports: Hypervisor ────────────────────────────────── */
NTSTATUS HvInitialize(VOID);
VOID     HvShutdown(VOID);
BOOLEAN  HvIsActive(VOID);

/* ─── Sub-module exports: EPT hooks ─────────────────────────────────── */
NTSTATUS EptHooks_Initialize(VOID);
VOID     EptHooks_Cleanup(VOID);

/* ─── Sub-module exports: TPM virtualization ─────────────────────────── */
NTSTATUS TpmVirt_Init(VOID);
VOID     TpmVirt_Cleanup(VOID);
VOID     TpmVirt_Regenerate(VOID);
BOOLEAN  TpmVirt_HandleMmioAccess(ULONG64 physAddr, BOOLEAN isWrite,
                                   ULONG accessSize, PULONG64 value);

/* ─── Helpers ────────────────────────────────────────────────────────── */
VOID     Util_RandomBytes(_Out_writes_bytes_(len) PUCHAR buf, _In_ ULONG len);
VOID     Util_GenDiskSerial(_Out_writes_(SPOOFER_DISK_SERIAL_LEN) PCHAR out);
VOID     Util_GenMacAddress(_Out_writes_(SPOOFER_MAC_LEN) PCHAR out);
VOID     Util_GenMachineGuid(_Out_writes_(SPOOFER_GUID_LEN) PWCHAR out);
ULONG    Util_GenVolumeSerial(VOID);
VOID     Util_GenProductId(_Out_writes_(SPOOFER_PRODUCT_ID_LEN) PWCHAR out);
ULONG    Util_GenInstallDate(VOID);
ULONG    Util_GenEdidSerial(VOID);
VOID     Util_GenGpuSerial(_Out_writes_(64) PCHAR out);
