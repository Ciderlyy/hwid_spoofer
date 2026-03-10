# HWID Spoofer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)

Hypervisor-based Ring-0 HWID spoofing for **security research and red-teaming** of your own systems. Uses VT-x + EPT to intercept disk, SMBIOS, TPM, and registry fingerprinting.

> **Scope**: Security research / red-teaming your own anti-cheat only.  
> Run exclusively inside a VMware guest with snapshots so you can roll back instantly.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  User-mode  │  loader.exe  (CLI controller + config persist)   │
│             │    │  DeviceIoControl                            │
├─────────────┼────┼──────────────────────────────────────────────┤
│  Kernel     │  volflt.sys (boot-start)                         │
│  (Ring 0)   │  ├─ driver.c         DriverEntry/IOCTL/auto-boot │
│             │  ├─ disk_spoof.c     Storage filter (fallback)   │
│             │  ├─ registry_spoof.c CmCallback + GPU keys       │
│             │  ├─ smbios_spoof.c   Firmware table patching     │
│             │  └─ gpu_spoof.c      GPU ID generation           │
├─────────────┼──────────────────────────────────────────────────┤
│  Hypervisor │  hypervisor/ (Ring -1, VT-x)                     │
│             │  ├─ vmx.c            VMCS setup, VM-exit handler │
│             │  ├─ ept.c            EPT table + split-page hooks│
│             │  ├─ ept_hook.c       Disk/module/SMBIOS hooks    │
│             │  ├─ vmexits.c        CPUID/MSR/EPT dispatch      │
│             │  ├─ tpm_virt.c       TPM MMIO emulation          │
│             │  └─ asm.asm          VMLAUNCH/VMRESUME stubs     │
└────────────────────────────────────────────────────────────────┘
```

### Detection vectors addressed

| Vector | Solution |
|--------|----------|
| Boot-time serial caching | Boot-start driver (`SERVICE_BOOT_START`) loads before AC |
| Filter device stack walk | EPT hooks on `disk.sys` dispatch — no filter device needed |
| Module enumeration | EPT hook on `NtQuerySystemInformation` hides driver |
| SMBIOS/firmware tables | In-memory patching at boot + EPT interception |
| GPU fingerprinting | Registry intercepts for adapter description keys |
| TPM fingerprinting | EPT-based MMIO interception with command emulation |
| CPUID hypervisor detection | CPUID leaf 1 bit 31 cleared, 0x40000000+ zeroed |
| Named device visibility | Device renamed to `VolFlt` (blends with volume filter drivers) |

### What gets spoofed

| HWID | Technique | Intercept path |
|------|-----------|---------------|
| Disk serial (standard) | Storage filter / EPT hook | `IOCTL_STORAGE_QUERY_PROPERTY` |
| Disk serial (SCSI raw) | Storage filter / EPT hook | `IOCTL_SCSI_PASS_THROUGH[_DIRECT]` |
| Disk serial (NVMe) | Storage filter / EPT hook | `IOCTL_STORAGE_PROTOCOL_COMMAND` |
| MAC address | CmCallback | `NetworkAddress` registry key |
| Machine GUID | CmCallback | `MachineGuid` registry key |
| ProductId / DigitalProductId | CmCallback | `CurrentVersion` registry key |
| InstallDate | CmCallback | `CurrentVersion` registry key |
| Monitor EDID serial | CmCallback | `EDID` registry binary |
| SMBIOS serials / UUID | Boot-time table patching + EPT hook | Type 0/1/2/3; WMI Win32_BIOS/BaseBoard/SystemEnclosure |
| GPU adapter string | CmCallback | `DriverDesc`, `HardwareInformation.*` |
| GPU serial | CmCallback | `HardwareInformation.SerialNumber` |
| TPM manufacturer/EK | EPT MMIO emulation | `GetCapability`, `ReadPublic` commands |
| ACPI FACS | EPT hook on `NtQuerySystemInformation` | `GetSystemFirmwareTable('ACPI','FACS')` |

### Known limitations

| Limitation | Impact |
|------------|--------|
| **TPM attestation** | `TPM2_CC_Certify` and `TPM2_CC_Quote` return failure. PCR values are not spoofed. Remote attestation and EK certificate chain validation will detect spoofing. |
| **Live MAC address** | Only the `NetworkAddress` registry key is spoofed. `GetAdaptersInfo` / NDIS reads the live NIC MAC until the adapter is restarted. Restart the network adapter or reboot after enabling spoofing for consistency. |
| **PCI config space** | Not intercepted. Vendor/subsystem IDs from I/O ports 0xCF8/0xCFC are not spoofed. |
| **EFI variables** | Not intercepted. `GetFirmwareEnvironmentVariable` / UEFI runtime services are not hooked. |

---

## Prerequisites

| Tool | Version |
|------|---------|
| Visual Studio | 2022 (Community works) |
| Windows Driver Kit (WDK) | 10.0.22621+ matching your VS |
| VMware Workstation | Any recent version |
| Windows 10/11 guest | x64, Secure Boot **disabled** in VM settings |

---

## Build

### Kernel driver (volflt.sys)

Create a new **Empty WDK Kernel-Mode Driver** project in Visual Studio:

1. Add all files under `driver/`, `hypervisor/`, and `shared/` to the project.
2. Set the MASM item type for `hypervisor/asm.asm` (Right-click → Properties → Item Type → Microsoft Macro Assembler).
3. In **Linker → Input → Additional Dependencies**, add `cng.lib`.
4. Target: x64 / Release.
5. Rename output to `volflt.sys`.

### User-mode loader (.exe)

```bat
cd loader
cl /std:c++17 /W4 /EHsc /nologo loader.cpp /link advapi32.lib iphlpapi.lib /out:loader.exe
```

---

## VM Setup

```bat
REM Inside the VM — run as Administrator
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

### VMware CPUID mask (optional — hypervisor handles this now)

The built-in hypervisor intercepts CPUID to hide virtualization. For defense-in-depth, you can also add to `.vmx`:

```ini
hypervisor.cpuid.v0 = "FALSE"
cpuid.1.ecx = "0---:----:----:----:----:----:----:----"
```

---

## Usage

All commands require **Administrator**.

```bat
loader.exe install C:\path\to\volflt.sys
loader.exe start
loader.exe enable          REM auto-generates all IDs, persists config
loader.exe status          REM print all active fake values
loader.exe regen           REM regenerate all IDs
loader.exe disable
loader.exe stop
```

After `enable`, the config is persisted to the registry. On the next reboot, the boot-start driver auto-enables spoofing before any other driver loads.

---

## File tree

```
hwid_spoofer/
├── shared/
│   └── protocol.h            IOCTL codes + config/status structs
├── driver/
│   ├── driver.h              Internal declarations + global state
│   ├── driver.c              DriverEntry, IOCTL handler, utilities
│   ├── disk_spoof.c          Storage filter (fallback for non-EPT)
│   ├── registry_spoof.c      CmCallback (8 value intercepts + GPU)
│   ├── smbios_spoof.c        SMBIOS firmware table patching
│   └── gpu_spoof.c           GPU serial/description generation
├── hypervisor/
│   ├── hv.h                  Public API + VT-x/EPT structures
│   ├── vmx.c                 VMCS setup, VMXON, VM-exit handler
│   ├── ept.c                 EPT table management, split-page hooks
│   ├── ept_hook.c            Disk/module/SMBIOS EPT hook handlers
│   ├── vmexits.c             CPUID/MSR/EPT-violation dispatch
│   ├── tpm_virt.c            TPM 2.0 MMIO emulation
│   └── asm.asm               VMLAUNCH/VMRESUME MASM stubs
├── loader/
│   └── loader.cpp            CLI controller + boot-start installer
├── .gitignore
└── README.md
```

---

## Key technical risks

- **PatchGuard**: EPT hooks don't modify kernel code pages (the real page stays clean in EPT R/W view), so PatchGuard integrity checks pass. The hypervisor handles PatchGuard's own CPUID/MSR probes transparently.
- **Performance**: EPT violations cost ~1000 cycles each. Disk IOCTLs are infrequent. `NtQuerySystemInformation` is moderate. SMBIOS/TPM queries are rare.
- **HVCI**: If Hypervisor-enforced Code Integrity is enabled, Windows runs under Hyper-V. Our hypervisor can't coexist — HVCI must be disabled.
- **Nested virtualization**: Works with VT-x passthrough in VMware. Without passthrough, nested VT-x adds complexity.
- **Secure Boot**: Boot-start driver needs a valid signature or test-signing enabled.
- **TPM attestation**: `TPM2_CC_Certify` uses the real EK private key in hardware. Remote attestation cannot be spoofed.

---

## Safety notes

- Always run inside a **snapshot-protected VMware VM**
- The driver uses documented kernel APIs (CmCallback, IoCreateDevice) — PatchGuard-safe
- EPT-based hooks are invisible to both user-mode and kernel-mode integrity scans
- `BCryptGenRandom` + RDRAND fallback for crypto-quality PRNG
- `EX_SPIN_LOCK` (read/write) and `FAST_MUTEX` for thread-safe state management
- SPTD data buffers are MDL-locked at PASSIVE_LEVEL, safe in completion routines

---

## Contributing

Contributions are welcome. Please open an issue first for larger changes. Ensure any changes follow the existing architecture and are tested in a VM.

---

## License

MIT — see [LICENSE](LICENSE). Use at your own risk. Intended for research only.
