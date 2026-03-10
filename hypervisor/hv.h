/*
 * hypervisor/hv.h
 *
 * Public API for the VT-x thin hypervisor.
 * Called from driver.c DriverEntry to virtualize the current OS.
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif

/* ─── Status ────────────────────────────────────────────────────────── */

NTSTATUS HvInitialize(VOID);
VOID     HvShutdown(VOID);
BOOLEAN  HvIsActive(VOID);

/* ─── EPT Hook API (used by Phase 5) ────────────────────────────────── */

typedef VOID (*EPT_HOOK_HANDLER)(PVOID Context);

NTSTATUS HvInstallEptHook(
    _In_ PVOID  TargetFunction,
    _In_ PVOID  HookFunction,
    _Out_ PVOID* OriginalTrampoline);

NTSTATUS HvRemoveEptHook(_In_ PVOID TargetFunction);

NTSTATUS EptMarkPageNoAccess(ULONG64 physAddr);
NTSTATUS EptRestorePageAccess(ULONG64 physAddr);
PEPT_PTE EptFindPte(ULONG64 physAddr);

/* ─── Intel VT-x MSR definitions ────────────────────────────────────── */

#define IA32_FEATURE_CONTROL        0x03A
#define IA32_VMX_BASIC              0x480
#define IA32_VMX_PINBASED_CTLS      0x481
#define IA32_VMX_PROCBASED_CTLS     0x482
#define IA32_VMX_EXIT_CTLS          0x483
#define IA32_VMX_ENTRY_CTLS         0x484
#define IA32_VMX_PROCBASED_CTLS2    0x48B
#define IA32_VMX_EPT_VPID_CAP       0x48C
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS     0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS    0x490

#define IA32_DEBUGCTL               0x1D9
#define IA32_SYSENTER_CS            0x174
#define IA32_SYSENTER_ESP           0x175
#define IA32_SYSENTER_EIP           0x176
#define IA32_EFER                   0xC0000080
#define IA32_FS_BASE                0xC0000100
#define IA32_GS_BASE                0xC0000101
#define IA32_TSC_AUX                0xC0000103

/* Feature control bits */
#define FEATURE_CONTROL_LOCKED      (1ULL << 0)
#define FEATURE_CONTROL_VMXON       (1ULL << 2)

/* ─── VMCS field encodings ──────────────────────────────────────────── */

/* 16-bit guest fields */
#define VMCS_GUEST_ES_SEL           0x0800
#define VMCS_GUEST_CS_SEL           0x0802
#define VMCS_GUEST_SS_SEL           0x0804
#define VMCS_GUEST_DS_SEL           0x0806
#define VMCS_GUEST_FS_SEL           0x0808
#define VMCS_GUEST_GS_SEL           0x080A
#define VMCS_GUEST_LDTR_SEL         0x080C
#define VMCS_GUEST_TR_SEL           0x080E

/* 16-bit host fields */
#define VMCS_HOST_ES_SEL            0x0C00
#define VMCS_HOST_CS_SEL            0x0C02
#define VMCS_HOST_SS_SEL            0x0C04
#define VMCS_HOST_DS_SEL            0x0C06
#define VMCS_HOST_FS_SEL            0x0C08
#define VMCS_HOST_GS_SEL            0x0C0A
#define VMCS_HOST_TR_SEL            0x0C0C

/* 64-bit control fields */
#define VMCS_CTRL_EPT_POINTER       0x201A
#define VMCS_CTRL_MSR_BITMAP        0x2004
#define VMCS_GUEST_VMCS_LINK        0x2800

/* 32-bit control fields */
#define VMCS_CTRL_PIN_BASED         0x4000
#define VMCS_CTRL_PROC_BASED        0x4002
#define VMCS_CTRL_EXIT              0x400C
#define VMCS_CTRL_ENTRY             0x4012
#define VMCS_CTRL_PROC_BASED2       0x401E
#define VMCS_CTRL_EXIT_REASON       0x4402
#define VMCS_CTRL_EXIT_QUAL         0x6400

/* 32-bit guest fields */
#define VMCS_GUEST_ES_LIMIT         0x4800
#define VMCS_GUEST_CS_LIMIT         0x4802
#define VMCS_GUEST_SS_LIMIT         0x4804
#define VMCS_GUEST_DS_LIMIT         0x4806
#define VMCS_GUEST_FS_LIMIT         0x4808
#define VMCS_GUEST_GS_LIMIT         0x480A
#define VMCS_GUEST_LDTR_LIMIT       0x480C
#define VMCS_GUEST_TR_LIMIT         0x480E
#define VMCS_GUEST_GDTR_LIMIT       0x4810
#define VMCS_GUEST_IDTR_LIMIT       0x4812
#define VMCS_GUEST_ES_ACCESS        0x4814
#define VMCS_GUEST_CS_ACCESS        0x4816
#define VMCS_GUEST_SS_ACCESS        0x4818
#define VMCS_GUEST_DS_ACCESS        0x481A
#define VMCS_GUEST_FS_ACCESS        0x481C
#define VMCS_GUEST_GS_ACCESS        0x481E
#define VMCS_GUEST_LDTR_ACCESS      0x4820
#define VMCS_GUEST_TR_ACCESS        0x4822
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824
#define VMCS_GUEST_ACTIVITY         0x4826
#define VMCS_GUEST_SYSENTER_CS      0x482A

/* Natural-width guest fields */
#define VMCS_GUEST_CR0              0x6800
#define VMCS_GUEST_CR3              0x6802
#define VMCS_GUEST_CR4              0x6804
#define VMCS_GUEST_ES_BASE          0x6806
#define VMCS_GUEST_CS_BASE          0x6808
#define VMCS_GUEST_SS_BASE          0x680A
#define VMCS_GUEST_DS_BASE          0x680C
#define VMCS_GUEST_FS_BASE          0x680E
#define VMCS_GUEST_GS_BASE          0x6810
#define VMCS_GUEST_LDTR_BASE        0x6812
#define VMCS_GUEST_TR_BASE          0x6814
#define VMCS_GUEST_GDTR_BASE        0x6816
#define VMCS_GUEST_IDTR_BASE        0x6818
#define VMCS_GUEST_DR7              0x681A
#define VMCS_GUEST_RSP              0x681C
#define VMCS_GUEST_RIP              0x681E
#define VMCS_GUEST_RFLAGS           0x6820
#define VMCS_GUEST_SYSENTER_ESP     0x6824
#define VMCS_GUEST_SYSENTER_EIP     0x6826
#define VMCS_GUEST_DEBUGCTL         0x2802
#define VMCS_GUEST_EFER             0x2806

/* Natural-width host fields */
#define VMCS_HOST_CR0               0x6C00
#define VMCS_HOST_CR3               0x6C02
#define VMCS_HOST_CR4               0x6C04
#define VMCS_HOST_FS_BASE           0x6C06
#define VMCS_HOST_GS_BASE           0x6C08
#define VMCS_HOST_TR_BASE           0x6C0A
#define VMCS_HOST_GDTR_BASE         0x6C0C
#define VMCS_HOST_IDTR_BASE         0x6C0E
#define VMCS_HOST_SYSENTER_ESP      0x6C10
#define VMCS_HOST_SYSENTER_EIP      0x6C12
#define VMCS_HOST_RSP               0x6C14
#define VMCS_HOST_RIP               0x6C16
#define VMCS_HOST_EFER              0x2C02
#define VMCS_HOST_SYSENTER_CS       0x4C00

/* VM-exit reasons */
#define EXIT_REASON_CPUID           10
#define EXIT_REASON_RDTSC           16
#define EXIT_REASON_RDTSCP          17
#define EXIT_REASON_VMCALL          18
#define EXIT_REASON_MSR_READ        31
#define EXIT_REASON_MSR_WRITE       32
#define EXIT_REASON_EPT_VIOLATION   48

/* RDTSC exit overhead: base + TSC-derived jitter to reduce timing fingerprint */
#define RDTSC_OVERHEAD_BASE   2500ULL
#define RDTSC_JITTER_BITS     10   /* ±512 cycles variance */

/* VMX MSR range to intercept — hide hypervisor from guest RDMSR */
#define MSR_VMX_FIRST   0x480
#define MSR_VMX_LAST    0x490

/* Processor-based controls (primary) */
#define CPU_BASED_USE_MSR_BITMAPS   (1UL << 28)
#define CPU_BASED_ACTIVATE_SECONDARY (1UL << 31)
#define CPU_BASED_RDTSC_EXITING     (1UL << 12)

/* Secondary processor-based controls */
#define CPU_BASED2_ENABLE_EPT       (1UL << 1)
#define CPU_BASED2_RDTSCP           (1UL << 3)
#define CPU_BASED2_ENABLE_INVPCID   (1UL << 12)
#define CPU_BASED2_ENABLE_XSAVES    (1UL << 20)

/* VM-exit controls */
#define VM_EXIT_HOST_ADDR_SPACE_SIZE (1UL << 9)
#define VM_EXIT_SAVE_EFER            (1UL << 20)
#define VM_EXIT_LOAD_EFER            (1UL << 21)

/* VM-entry controls */
#define VM_ENTRY_IA32E_MODE          (1UL << 9)
#define VM_ENTRY_LOAD_EFER           (1UL << 15)

/* ─── Per-CPU virtual processor context ─────────────────────────────── */

#define HV_STACK_SIZE  0x6000
#define MAX_HOOK_COUNT 32
#define MAX_SPLIT_PAGES 64

/*
 * Layout must match the asm push order exactly:
 *   push r15, r14, ..., r8, rbp, rdi, rsi, rdx, rcx, rbx, rax
 * RSP points to Rax first. Rsp/Rip/Rflags come from VMCS reads.
 */
typedef struct _GUEST_CONTEXT {
    ULONG64 Rax;    /* +0x00  (top of stack after pushes) */
    ULONG64 Rbx;    /* +0x08 */
    ULONG64 Rcx;    /* +0x10 */
    ULONG64 Rdx;    /* +0x18 */
    ULONG64 Rsi;    /* +0x20 */
    ULONG64 Rdi;    /* +0x28 */
    ULONG64 Rbp;    /* +0x30 */
    ULONG64 R8;     /* +0x38 */
    ULONG64 R9;     /* +0x40 */
    ULONG64 R10;    /* +0x48 */
    ULONG64 R11;    /* +0x50 */
    ULONG64 R12;    /* +0x58 */
    ULONG64 R13;    /* +0x60 */
    ULONG64 R14;    /* +0x68 */
    ULONG64 R15;    /* +0x70 */
} GUEST_CONTEXT, *PGUEST_CONTEXT;

typedef struct _VCPU {
    BOOLEAN         Launched;
    PVOID           VmxonRegion;
    PHYSICAL_ADDRESS VmxonPhysical;
    PVOID           VmcsRegion;
    PHYSICAL_ADDRESS VmcsPhysical;
    PVOID           MsrBitmap;
    PHYSICAL_ADDRESS MsrBitmapPhysical;
    PVOID           HostStack;
    GUEST_CONTEXT   GuestContext;
} VCPU, *PVCPU;

/* ─── EPT structures ────────────────────────────────────────────────── */

typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 Accessed : 1;
        ULONG64 Reserved2 : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Reserved3 : 1;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved4 : 12;
    };
} EPT_PML4E, *PEPT_PML4E;

typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 Accessed : 1;
        ULONG64 Reserved2 : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Reserved3 : 1;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved4 : 12;
    };
} EPT_PDPTE, *PEPT_PDPTE;

typedef union _EPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 LargePage : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Reserved1 : 10;
        ULONG64 PageFrameNumber : 27;
        ULONG64 Reserved2 : 15;
        ULONG64 SuppressVe : 1;
    };
} EPT_PDE, *PEPT_PDE;

typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Reserved2 : 1;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 11;
        ULONG64 SuppressVe : 1;
    };
} EPT_PTE, *PEPT_PTE;

typedef struct _EPT_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E  Pml4[512];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE  Pdpt[512];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE    Pd[512][512]; /* 512 GB coverage */
    ULONG64 EptPointer;
} EPT_STATE, *PEPT_STATE;

/* Split page (4KB PTE table) — used by ept.c and vmexits.c */
typedef struct _EPT_SPLIT_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[512];
    ULONG PdIndex;
    ULONG PdptIndex;
} EPT_SPLIT_PAGE, *PEPT_SPLIT_PAGE;

typedef struct _EPT_HOOK_ENTRY {
    PVOID    TargetVa;
    ULONG64  TargetPa;
    PVOID    HookFunction;
    PVOID    ShadowPage;
    ULONG64  ShadowPa;
    PVOID    OriginalBytes;
    BOOLEAN  Active;
} EPT_HOOK_ENTRY, *PEPT_HOOK_ENTRY;

/* ─── Global hypervisor state ───────────────────────────────────────── */

typedef struct _HV_GLOBAL {
    BOOLEAN       Active;
    ULONG         ProcessorCount;
    PVCPU         Vcpus;
    PEPT_STATE    Ept;
    EPT_HOOK_ENTRY Hooks[MAX_HOOK_COUNT];
    ULONG         HookCount;
    EX_SPIN_LOCK  HookLock;
} HV_GLOBAL, *PHV_GLOBAL;

extern HV_GLOBAL g_Hv;
