/*
 * driver/smbios_spoof.h
 * SMBIOS firmware table spoofing — patches the kernel's cached SMBIOS data
 * so GetSystemFirmwareTable('RSMB', ...) and all WMI classes return fake values.
 */

#pragma once
#include "driver.h"

NTSTATUS SmbiosSpoof_Init(VOID);
VOID     SmbiosSpoof_Cleanup(VOID);
VOID     PatchSmbiosTable(PUCHAR tableData, ULONG tableLen);
VOID     PatchAcpiTable(ULONG tableId, PUCHAR tableData, ULONG tableLen);
