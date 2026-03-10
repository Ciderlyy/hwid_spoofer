/*
 * hypervisor/vmx.c
 *
 * Intel VT-x hypervisor core: VMXON, VMCS setup, VM-exit handling.
 * Virtualizes the running OS from underneath (blue-pill style).
 */

#include "hv.h"
#include <intrin.h>

HV_GLOBAL g_Hv = { 0 };

/* GDT/IDT descriptor for SGDT/SIDT */
#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REG {
    USHORT  Limit;
    ULONG64 Base;
} DESCRIPTOR_TABLE_REG;
#pragma pack(pop)

/* Assembly helpers declared in asm.asm */
extern USHORT AsmReadCs(VOID);
extern USHORT AsmReadSs(VOID);
extern USHORT AsmReadDs(VOID);
extern USHORT AsmReadEs(VOID);
extern USHORT AsmReadFs(VOID);
extern USHORT AsmReadGs(VOID);
extern USHORT AsmReadTr(VOID);
extern USHORT AsmReadLdtr(VOID);
extern ULONG64 AsmVmxLaunch(PVOID Vcpu);
extern ULONG64 AsmVmxCall(ULONG64 code);

/* ─── Segment descriptor helpers ────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR {
    USHORT LimitLow;
    USHORT BaseLow;
    UCHAR  BaseMid;
    UCHAR  Access;
    UCHAR  Granularity;
    UCHAR  BaseHigh;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;
#pragma pack(pop)

static ULONG64 GetSegmentBase(ULONG64 gdtBase, USHORT selector)
{
    if (!selector) return 0;
    PSEGMENT_DESCRIPTOR desc =
        (PSEGMENT_DESCRIPTOR)(gdtBase + (selector & ~7));
    ULONG64 base = desc->BaseLow | ((ULONG64)desc->BaseMid << 16) |
                   ((ULONG64)desc->BaseHigh << 24);
    if (!(desc->Access & 0x10)) {
        base |= (*(PULONG64)((PUCHAR)desc + 8)) << 32;
    }
    return base;
}

static ULONG GetAccessRightsFromGdt(ULONG64 gdtBase, USHORT selector)
{
    if (!selector) return 0x10000;
    PSEGMENT_DESCRIPTOR desc =
        (PSEGMENT_DESCRIPTOR)(gdtBase + (selector & ~7));
    ULONG ar = desc->Access | ((desc->Granularity & 0xF0) << 8);
    ar &= 0xF0FF;
    return ar;
}

static ULONG GetSegmentLimit(ULONG64 gdtBase, USHORT selector)
{
    if (!selector) return 0;
    PSEGMENT_DESCRIPTOR desc =
        (PSEGMENT_DESCRIPTOR)(gdtBase + (selector & ~7));
    ULONG limit = desc->LimitLow | ((ULONG)(desc->Granularity & 0x0F) << 16);
    if (desc->Granularity & 0x80) limit = (limit << 12) | 0xFFF;
    return limit;
}

/* ─── VMCS field adjustment ─────────────────────────────────────────── */

static ULONG AdjustControls(ULONG desired, ULONG msr)
{
    LARGE_INTEGER msrVal;
    msrVal.QuadPart = __readmsr(msr);
    desired |= msrVal.LowPart;   /* required 1-settings */
    desired &= msrVal.HighPart;  /* required 0-settings */
    return desired;
}

/* ─── EPT initialization ────────────────────────────────────────────── */

static NTSTATUS InitializeEpt(VOID)
{
    g_Hv.Ept = (PEPT_STATE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EPT_STATE), 'MmPg');
    if (!g_Hv.Ept) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Hv.Ept, sizeof(EPT_STATE));

    /* PML4[0] → PDPT */
    PHYSICAL_ADDRESS pdptPa = MmGetPhysicalAddress(&g_Hv.Ept->Pdpt[0]);
    g_Hv.Ept->Pml4[0].Read = 1;
    g_Hv.Ept->Pml4[0].Write = 1;
    g_Hv.Ept->Pml4[0].Execute = 1;
    g_Hv.Ept->Pml4[0].PageFrameNumber = pdptPa.QuadPart >> 12;

    /* PDPT[i] → PD[i] — covers 512 GB */
    for (ULONG i = 0; i < 512; i++) {
        PHYSICAL_ADDRESS pdPa = MmGetPhysicalAddress(&g_Hv.Ept->Pd[i][0]);
        g_Hv.Ept->Pdpt[i].Read = 1;
        g_Hv.Ept->Pdpt[i].Write = 1;
        g_Hv.Ept->Pdpt[i].Execute = 1;
        g_Hv.Ept->Pdpt[i].PageFrameNumber = pdPa.QuadPart >> 12;
    }

    /* PD entries: 2MB large pages, identity-mapped */
    for (ULONG i = 0; i < 512; i++) {
        for (ULONG j = 0; j < 512; j++) {
            ULONG64 physBase = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);
            g_Hv.Ept->Pd[i][j].Read = 1;
            g_Hv.Ept->Pd[i][j].Write = 1;
            g_Hv.Ept->Pd[i][j].Execute = 1;
            g_Hv.Ept->Pd[i][j].LargePage = 1;
            g_Hv.Ept->Pd[i][j].MemoryType = 6; /* write-back */
            g_Hv.Ept->Pd[i][j].PageFrameNumber = physBase >> 21;
        }
    }

    /* EPTP: WB memory type, page-walk length 3 (=4 levels - 1) */
    PHYSICAL_ADDRESS pml4Pa = MmGetPhysicalAddress(&g_Hv.Ept->Pml4[0]);
    g_Hv.Ept->EptPointer = pml4Pa.QuadPart | (3ULL << 3) | 6;

    return STATUS_SUCCESS;
}

/* ─── Allocate per-CPU region (4KB-aligned for VMXON/VMCS) ──────────── */

static PVOID AllocateVmxRegion(PHYSICAL_ADDRESS* outPhysical)
{
    PHYSICAL_ADDRESS lowAddr  = { 0 };
    PHYSICAL_ADDRESS highAddr = { .QuadPart = -1 };
    PHYSICAL_ADDRESS boundary = { .QuadPart = PAGE_SIZE };

    PVOID region = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lowAddr, highAddr, boundary, MmCached);
    if (!region) return NULL;

    RtlZeroMemory(region, PAGE_SIZE);
    *outPhysical = MmGetPhysicalAddress(region);

    /* Write revision ID from IA32_VMX_BASIC */
    ULONG revisionId = (ULONG)(__readmsr(IA32_VMX_BASIC) & 0x7FFFFFFF);
    *(PULONG)region = revisionId;

    return region;
}

/* ─── VM-exit handler (called from assembly stub) ───────────────────── */

VOID VmExitHandler(PGUEST_CONTEXT ctx)
{
    ULONG exitReason = 0;
    __vmx_vmread(VMCS_CTRL_EXIT_REASON, (size_t*)&exitReason);
    exitReason &= 0xFFFF;

    ULONG64 guestRip = 0, guestRsp = 0;
    __vmx_vmread(VMCS_GUEST_RIP, (size_t*)&guestRip);
    __vmx_vmread(VMCS_GUEST_RSP, (size_t*)&guestRsp);

    BOOLEAN advanceRip = FALSE;

    switch (exitReason) {

    case EXIT_REASON_RDTSC:
    case EXIT_REASON_RDTSCP:
    {
        ULONG64 tsc = __rdtsc();
        /* Jitter: use low TSC bits for per-call variance (±512 cycles) */
        ULONG64 jitter = (tsc & ((1ULL << RDTSC_JITTER_BITS) - 1))
                         - (1ULL << (RDTSC_JITTER_BITS - 1));
        tsc -= (RDTSC_OVERHEAD_BASE + jitter);
        ctx->Rax = tsc & 0xFFFFFFFFULL;
        ctx->Rdx = (tsc >> 32) & 0xFFFFFFFFULL;
        if (exitReason == EXIT_REASON_RDTSCP)
            ctx->Rcx = (ULONG)__readmsr(IA32_TSC_AUX);
        advanceRip = TRUE;
        break;
    }

    case EXIT_REASON_CPUID:
    {
        int cpuInfo[4] = { 0 };
        __cpuidex(cpuInfo, (int)ctx->Rax, (int)ctx->Rcx);

        /* Hide hypervisor presence */
        if ((ULONG)ctx->Rax == 1) {
            cpuInfo[2] &= ~(1 << 31); /* clear hypervisor bit */
        } else if ((ULONG)ctx->Rax >= 0x40000000 &&
                   (ULONG)ctx->Rax <= 0x400000FF) {
            cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
        }

        ctx->Rax = (ULONG64)(ULONG)cpuInfo[0];
        ctx->Rbx = (ULONG64)(ULONG)cpuInfo[1];
        ctx->Rcx = (ULONG64)(ULONG)cpuInfo[2];
        ctx->Rdx = (ULONG64)(ULONG)cpuInfo[3];
        advanceRip = TRUE;
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        ULONG msr = (ULONG)ctx->Rcx;
        ULARGE_INTEGER val;
        if (msr >= MSR_VMX_FIRST && msr <= MSR_VMX_LAST) {
            /* Hide VMX capability MSRs — return 0 (consistent with CPUID VMX bit cleared) */
            val.QuadPart = 0;
        } else {
            val.QuadPart = __readmsr(msr);
        }
        ctx->Rax = val.LowPart;
        ctx->Rdx = val.HighPart;
        advanceRip = TRUE;
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        ULONG msr = (ULONG)ctx->Rcx;
        if (msr >= MSR_VMX_FIRST && msr <= MSR_VMX_LAST) {
            /* VMX capability MSRs are read-only — ignore write, pretend success */
        } else {
            ULONG64 val = (ctx->Rdx << 32) | (ctx->Rax & 0xFFFFFFFF);
            __writemsr(msr, val);
        }
        advanceRip = TRUE;
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        if (ctx->Rcx == 0xDEADC0DE) {
            /* Advance guest RIP past VMCALL in VMCS so the asm
               shutdown path reads the correct resume address. */
            ULONG instrLen = 0;
            __vmx_vmread(0x440C, (size_t*)&instrLen);
            guestRip += instrLen;
            __vmx_vmwrite(VMCS_GUEST_RIP, guestRip);
            ctx->Rax = 0xDEADC0DE; /* signal to asm stub */
            return;
        }
        advanceRip = TRUE;
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        ULONG64 exitQual = 0, guestPhys = 0;
        __vmx_vmread(VMCS_CTRL_EXIT_QUAL, (size_t*)&exitQual);
        __vmx_vmread(0x2400, (size_t*)&guestPhys);

        /* Check if this is a TPM MMIO access */
        extern BOOLEAN TpmVirt_HandleMmioAccess(
            ULONG64, BOOLEAN, ULONG, PULONG64);
        if (guestPhys >= 0xFED40000ULL &&
            guestPhys < 0xFED45000ULL) {
            BOOLEAN isWrite = (exitQual & 2) != 0;
            ULONG64 val = ctx->Rax;
            if (TpmVirt_HandleMmioAccess(guestPhys, isWrite, 4, &val)) {
                if (!isWrite) ctx->Rax = val;
                advanceRip = TRUE;
                break;
            }
        }

        /* Check EPT hook table */
        extern BOOLEAN HandleEptViolation(ULONG64, ULONG64);
        if (HandleEptViolation(exitQual, guestPhys)) {
            /* Handled — re-execute the faulting instruction */
            break;
        }

        break;
    }

    default:
        /* Unhandled exit — advance RIP to avoid infinite loop */
        advanceRip = TRUE;
        break;
    }

    if (advanceRip) {
        ULONG instrLen = 0;
        __vmx_vmread(0x440C, (size_t*)&instrLen); /* VM_EXIT_INSTRUCTION_LEN */
        guestRip += instrLen;
        __vmx_vmwrite(VMCS_GUEST_RIP, guestRip);
    }
}

/* ─── Per-processor setup ───────────────────────────────────────────── */

static NTSTATUS VmxSetupProcessor(ULONG cpuIndex)
{
    PVCPU vcpu = &g_Hv.Vcpus[cpuIndex];

    /* Allocate VMXON region */
    vcpu->VmxonRegion = AllocateVmxRegion(&vcpu->VmxonPhysical);
    if (!vcpu->VmxonRegion) return STATUS_INSUFFICIENT_RESOURCES;

    /* Allocate VMCS */
    vcpu->VmcsRegion = AllocateVmxRegion(&vcpu->VmcsPhysical);
    if (!vcpu->VmcsRegion) return STATUS_INSUFFICIENT_RESOURCES;

    /* Allocate MSR bitmap (4KB). Layout: [0,1K)=low RDMSR, [1K,2K)=high RDMSR,
       [2K,3K)=low WRMSR, [3K,4K)=high WRMSR. Bit=1 => intercept. */
    vcpu->MsrBitmap = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'MmBt');
    if (!vcpu->MsrBitmap) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(vcpu->MsrBitmap, PAGE_SIZE);

    /* Intercept RDMSR and WRMSR of VMX capability MSRs (0x480–0x490) */
    for (ULONG msr = MSR_VMX_FIRST; msr <= MSR_VMX_LAST; msr++) {
        ULONG byteOff = msr / 8;
        ULONG bit = msr % 8;
        ((PUCHAR)vcpu->MsrBitmap)[byteOff] |= (UCHAR)(1 << bit);           /* RDMSR low */
        ((PUCHAR)vcpu->MsrBitmap)[2048 + byteOff] |= (UCHAR)(1 << bit);   /* WRMSR low */
    }

    vcpu->MsrBitmapPhysical = MmGetPhysicalAddress(vcpu->MsrBitmap);

    /* Allocate host stack */
    vcpu->HostStack = ExAllocatePool2(POOL_FLAG_NON_PAGED, HV_STACK_SIZE, 'VcSt');
    if (!vcpu->HostStack) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(vcpu->HostStack, HV_STACK_SIZE);

    /* Enable VMX in CR4 */
    ULONG64 cr4 = __readcr4();
    cr4 |= (1ULL << 13); /* CR4.VMXE */
    __writecr4(cr4);

    /* Fix CR0/CR4 bits required by VMX */
    ULONG64 cr0 = __readcr0();
    cr0 |= __readmsr(0x486);  /* IA32_VMX_CR0_FIXED0 */
    cr0 &= __readmsr(0x487);  /* IA32_VMX_CR0_FIXED1 */
    __writecr0(cr0);
    ULONG64 cr4val = __readcr4();
    cr4val |= __readmsr(0x488);  /* IA32_VMX_CR4_FIXED0 */
    cr4val &= __readmsr(0x489);  /* IA32_VMX_CR4_FIXED1 */
    __writecr4(cr4val);

    /* VMXON */
    if (__vmx_on(&vcpu->VmxonPhysical.QuadPart) != 0)
        return STATUS_UNSUCCESSFUL;

    /* VMCLEAR + VMPTRLD */
    if (__vmx_vmclear(&vcpu->VmcsPhysical.QuadPart) != 0)
        return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&vcpu->VmcsPhysical.QuadPart) != 0)
        return STATUS_UNSUCCESSFUL;

    /* ── Configure VMCS ─────────────────────────────────────────────── */

    /* Control fields */
    ULONG pinBased = AdjustControls(0, IA32_VMX_TRUE_PINBASED_CTLS);
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED, pinBased);

    ULONG procBased = AdjustControls(
        CPU_BASED_USE_MSR_BITMAPS | CPU_BASED_ACTIVATE_SECONDARY |
        CPU_BASED_RDTSC_EXITING,
        IA32_VMX_TRUE_PROCBASED_CTLS);
    /* Force CPUID exiting */
    procBased |= (1UL << 7); /* not needed — CPUID always exits */
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED, procBased);

    ULONG procBased2 = AdjustControls(
        CPU_BASED2_ENABLE_EPT | CPU_BASED2_RDTSCP | CPU_BASED2_ENABLE_INVPCID,
        IA32_VMX_PROCBASED_CTLS2);
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED2, procBased2);

    ULONG exitCtls = AdjustControls(
        VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_SAVE_EFER | VM_EXIT_LOAD_EFER,
        IA32_VMX_TRUE_EXIT_CTLS);
    __vmx_vmwrite(VMCS_CTRL_EXIT, exitCtls);

    ULONG entryCtls = AdjustControls(
        VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_EFER,
        IA32_VMX_TRUE_ENTRY_CTLS);
    __vmx_vmwrite(VMCS_CTRL_ENTRY, entryCtls);

    /* MSR bitmap */
    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP, vcpu->MsrBitmapPhysical.QuadPart);

    /* EPT pointer */
    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, g_Hv.Ept->EptPointer);

    /* VMCS link pointer = -1 (no shadow VMCS) */
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK, (size_t)-1);

    /* ── Guest state = current CPU state ────────────────────────────── */

    USHORT cs, ss, ds, es, fs, gs, tr, ldtr;
    cs   = AsmReadCs();
    ss   = AsmReadSs();
    ds   = AsmReadDs();
    es   = AsmReadEs();
    fs   = AsmReadFs();
    gs   = AsmReadGs();
    tr   = AsmReadTr();
    ldtr = AsmReadLdtr();

    __vmx_vmwrite(VMCS_GUEST_CS_SEL, cs);
    __vmx_vmwrite(VMCS_GUEST_SS_SEL, ss);
    __vmx_vmwrite(VMCS_GUEST_DS_SEL, ds);
    __vmx_vmwrite(VMCS_GUEST_ES_SEL, es);
    __vmx_vmwrite(VMCS_GUEST_FS_SEL, fs);
    __vmx_vmwrite(VMCS_GUEST_GS_SEL, gs);
    __vmx_vmwrite(VMCS_GUEST_TR_SEL, tr);
    __vmx_vmwrite(VMCS_GUEST_LDTR_SEL, ldtr);

    DESCRIPTOR_TABLE_REG gdtr = { 0 }, idtr = { 0 };
    _sgdt(&gdtr);
    __sidt(&idtr);

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    /* Segment bases, limits, access rights */
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, GetSegmentBase(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, GetSegmentBase(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, GetSegmentBase(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, GetSegmentBase(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, GetSegmentBase(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, GetSegmentBase(gdtr.Base, ldtr));

    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, GetSegmentLimit(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, GetSegmentLimit(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, GetSegmentLimit(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, GetSegmentLimit(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, GetSegmentLimit(gdtr.Base, fs));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, GetSegmentLimit(gdtr.Base, gs));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, GetSegmentLimit(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, GetSegmentLimit(gdtr.Base, ldtr));

    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS, GetAccessRightsFromGdt(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS, GetAccessRightsFromGdt(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS, GetAccessRightsFromGdt(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS, GetAccessRightsFromGdt(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS, GetAccessRightsFromGdt(gdtr.Base, fs));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS, GetAccessRightsFromGdt(gdtr.Base, gs));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS, GetAccessRightsFromGdt(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS, GetAccessRightsFromGdt(gdtr.Base, ldtr));

    /* Control registers and MSRs */
    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, __readeflags());
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_EFER, __readmsr(IA32_EFER));
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY, 0);

    /* Guest RSP/RIP are set by the assembly launch stub */

    /* ── Host state ─────────────────────────────────────────────────── */

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    __vmx_vmwrite(VMCS_HOST_CS_SEL, cs & ~7);
    __vmx_vmwrite(VMCS_HOST_SS_SEL, ss & ~7);
    __vmx_vmwrite(VMCS_HOST_DS_SEL, ds & ~7);
    __vmx_vmwrite(VMCS_HOST_ES_SEL, es & ~7);
    __vmx_vmwrite(VMCS_HOST_FS_SEL, fs & ~7);
    __vmx_vmwrite(VMCS_HOST_GS_SEL, gs & ~7);
    __vmx_vmwrite(VMCS_HOST_TR_SEL, tr & ~7);

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_HOST_TR_BASE, GetSegmentBase(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_EFER, __readmsr(IA32_EFER));

    /* Host RSP = top of host stack, Host RIP = AsmVmExitHandler */
    ULONG64 hostStackTop = (ULONG64)vcpu->HostStack + HV_STACK_SIZE - 8;
    __vmx_vmwrite(VMCS_HOST_RSP, hostStackTop);

    /* Host RIP will be set by the assembly VMLAUNCH stub */

    return STATUS_SUCCESS;
}

/* ─── Public API ────────────────────────────────────────────────────── */

NTSTATUS HvInitialize(VOID)
{
    /* Check VT-x support */
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) return STATUS_NOT_SUPPORTED;

    /* Check IA32_FEATURE_CONTROL */
    ULONG64 featureCtrl = __readmsr(IA32_FEATURE_CONTROL);
    if ((featureCtrl & FEATURE_CONTROL_LOCKED) &&
        !(featureCtrl & FEATURE_CONTROL_VMXON))
        return STATUS_NOT_SUPPORTED;

    /* Allocate per-CPU structures */
    g_Hv.ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    g_Hv.Vcpus = (PVCPU)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        g_Hv.ProcessorCount * sizeof(VCPU), 'VcPu');
    if (!g_Hv.Vcpus) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Hv.Vcpus, g_Hv.ProcessorCount * sizeof(VCPU));

    /* Initialize EPT */
    NTSTATUS st = InitializeEpt();
    if (!NT_SUCCESS(st)) return st;

    /* Virtualize each processor */
    for (ULONG i = 0; i < g_Hv.ProcessorCount; i++) {
        PROCESSOR_NUMBER procNum;
        KeGetProcessorNumberFromIndex(i, &procNum);
        GROUP_AFFINITY affinity = { 0 };
        affinity.Group = procNum.Group;
        affinity.Mask  = 1ULL << procNum.Number;
        GROUP_AFFINITY oldAffinity;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        st = VmxSetupProcessor(i);
        if (!NT_SUCCESS(st)) {
            KeRevertToUserGroupAffinityThread(&oldAffinity);
            HvShutdown();
            return st;
        }

        ULONG64 launchResult = AsmVmxLaunch(&g_Hv.Vcpus[i]);
        KeRevertToUserGroupAffinityThread(&oldAffinity);
        if (launchResult != 0) {
            HvShutdown();
            return STATUS_UNSUCCESSFUL;
        }
        g_Hv.Vcpus[i].Launched = TRUE;
    }

    g_Hv.Active = TRUE;
    return STATUS_SUCCESS;
}

VOID HvShutdown(VOID)
{
    if (!g_Hv.Active && !g_Hv.Vcpus) return;

    for (ULONG i = 0; i < g_Hv.ProcessorCount; i++) {
        PVCPU vcpu = &g_Hv.Vcpus[i];

        if (vcpu->Launched) {
            /* Must call VMCALL from this CPU to trigger VMXOFF in root mode */
            PROCESSOR_NUMBER procNum;
            KeGetProcessorNumberFromIndex(i, &procNum);
            GROUP_AFFINITY affinity = { 0 }, oldAffinity;
            affinity.Group = procNum.Group;
            affinity.Mask  = 1ULL << procNum.Number;
            KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);
            AsmVmxCall(0xDEADC0DE);

            KeRevertToUserGroupAffinityThread(&oldAffinity);
            vcpu->Launched = FALSE;
        }

        if (vcpu->VmxonRegion)
            MmFreeContiguousMemory(vcpu->VmxonRegion);
        if (vcpu->VmcsRegion)
            MmFreeContiguousMemory(vcpu->VmcsRegion);
        if (vcpu->MsrBitmap)
            ExFreePoolWithTag(vcpu->MsrBitmap, 'MmBt');
        if (vcpu->HostStack)
            ExFreePoolWithTag(vcpu->HostStack, 'VcSt');
    }

    if (g_Hv.Vcpus)
        ExFreePoolWithTag(g_Hv.Vcpus, 'VcPu');
    if (g_Hv.Ept) {
        extern VOID EptCleanup(VOID);
        EptCleanup();
        ExFreePoolWithTag(g_Hv.Ept, 'MmPg');
    }

    RtlZeroMemory(&g_Hv, sizeof(g_Hv));
}

BOOLEAN HvIsActive(VOID)
{
    return g_Hv.Active;
}
