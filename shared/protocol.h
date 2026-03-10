/*
 * shared/protocol.h
 * Shared IOCTL definitions and data structures between kernel driver and user-mode loader.
 * Include this in both kernel and user-mode compilation units.
 */

#pragma once

#ifdef _KERNEL_MODE
  #include <wdm.h>
#else
  #include <Windows.h>
#endif

/* ─── Device path (blends with volume filter drivers) ───────────────── */
#define SPOOFER_NT_DEVICE_NAME  L"\\Device\\VolFlt"
#define SPOOFER_DOS_SYMLINK     L"\\DosDevices\\VolFlt"
#define SPOOFER_USERMODE_PATH   L"\\\\.\\VolFlt"

/* ─── IOCTL codes ────────────────────────────────────────────────────── */
#define FILE_DEVICE_SPOOFER     0x00008100u

#define _SPOOFER_CTL(n) \
    CTL_CODE(FILE_DEVICE_SPOOFER, 0x900u + (n), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SPOOFER_SET_CONFIG   _SPOOFER_CTL(0)  /* IN:  SPOOFER_CONFIG  */
#define IOCTL_SPOOFER_GET_STATUS   _SPOOFER_CTL(1)  /* OUT: SPOOFER_STATUS  */
#define IOCTL_SPOOFER_ENABLE       _SPOOFER_CTL(2)  /* no buffer            */
#define IOCTL_SPOOFER_DISABLE      _SPOOFER_CTL(3)  /* no buffer            */
#define IOCTL_SPOOFER_REGENERATE   _SPOOFER_CTL(4)  /* no buffer – re-randomise IDs */

/* ─── Buffer size limits ─────────────────────────────────────────────── */
#define SPOOFER_DISK_SERIAL_LEN   64    /* null-terminated ANSI  */
#define SPOOFER_MAC_LEN           13    /* "AABBCCDDEEFF\0"       */
#define SPOOFER_GUID_LEN          39    /* "{hex-guid}\0" wide    */
#define SPOOFER_PRODUCT_ID_LEN    32    /* "XXXXX-OEM-XXXXXXX-XXXXX\0" */
#define SPOOFER_EDID_SERIAL_LEN   16    /* 4-byte EDID serial as hex+NUL */

/* ─── Config (user -> kernel) ────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct _SPOOFER_CONFIG {
    /* Feature flags */
    BOOLEAN  SpoofDiskSerial;
    BOOLEAN  SpoofMacAddress;
    BOOLEAN  SpoofMachineGuid;
    BOOLEAN  SpoofVolumeSerial;
    BOOLEAN  SpoofInstallIds;       /* ProductId, DigitalProductId, InstallDate */
    BOOLEAN  SpoofEdidSerial;       /* Monitor EDID serial via DISPLAY enum key */
    BOOLEAN  SpoofSmbios;          /* SMBIOS firmware tables (motherboard, BIOS) */
    BOOLEAN  SpoofGpu;             /* GPU adapter description / serial */
    BOOLEAN  AutoGenerate;          /* TRUE = driver generates random IDs    */

    CHAR     FakeDiskSerial[SPOOFER_DISK_SERIAL_LEN];
    CHAR     FakeMacAddress[SPOOFER_MAC_LEN];          /* "AABBCCDDEEFF"  */
    WCHAR    FakeMachineGuid[SPOOFER_GUID_LEN];        /* with braces     */
    ULONG    FakeVolumeSerial;
    WCHAR    FakeProductId[SPOOFER_PRODUCT_ID_LEN];    /* wide REG_SZ     */
    ULONG    FakeInstallDate;                          /* epoch seconds   */
    ULONG    FakeEdidSerial;                           /* 4-byte EDID SN  */
    UCHAR    FakeDigitalProductBytes[16];              /* pre-generated random blob for
                                                          DigitalProductId bytes 8-23 */
    /* SMBIOS fields */
    CHAR     FakeBiosSerial[64];
    CHAR     FakeBoardSerial[64];
    CHAR     FakeSystemSerial[64];  /* Type 1 System serial; falls back to FakeBoardSerial if empty */
    CHAR     FakeSystemUuid[37];   /* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */
    CHAR     FakeChassisSerial[64];

    /* GPU fields */
    CHAR     FakeGpuSerial[64];
    WCHAR    FakeGpuDescription[128];
} SPOOFER_CONFIG, *PSPOOFER_CONFIG;

/* ─── Status (kernel -> user) ────────────────────────────────────────── */
typedef struct _SPOOFER_STATUS {
    BOOLEAN  IsActive;
    ULONG    DiskFiltersAttached;
    ULONG    TotalIntercepts;        /* running counter of spoofed queries   */
    CHAR     ActiveDiskSerial[SPOOFER_DISK_SERIAL_LEN];
    CHAR     ActiveMacAddress[SPOOFER_MAC_LEN];
    WCHAR    ActiveMachineGuid[SPOOFER_GUID_LEN];
    ULONG    ActiveVolumeSerial;
    WCHAR    ActiveProductId[SPOOFER_PRODUCT_ID_LEN];
    ULONG    ActiveInstallDate;
    ULONG    ActiveEdidSerial;
    UCHAR    ActiveDigitalProductBytes[16];
    /* SMBIOS + GPU active values (needed for boot-start persistence) */
    CHAR     ActiveBiosSerial[64];
    CHAR     ActiveBoardSerial[64];
    CHAR     ActiveSystemSerial[64];
    CHAR     ActiveSystemUuid[37];
    CHAR     ActiveChassisSerial[64];
    CHAR     ActiveGpuSerial[64];
    WCHAR    ActiveGpuDescription[128];
} SPOOFER_STATUS, *PSPOOFER_STATUS;
#pragma pack(pop)
