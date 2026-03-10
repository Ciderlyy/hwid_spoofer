;
; hypervisor/asm.asm
;
; x64 MASM assembly stubs for VT-x hypervisor operations.
; Handles register save/restore around VM-exits and VMLAUNCH.
;

.CODE

EXTERN VmExitHandler:PROC

;─────────────────────────────────────────────────────────────────
; AsmVmExitHandler
;
; Called on every VM-exit. Host RIP in VMCS points here.
; Saves all guest GPRs into a GUEST_CONTEXT on the stack,
; calls the C handler, then restores and does VMRESUME.
;─────────────────────────────────────────────────────────────────
AsmVmExitHandler PROC

    ; Save all general-purpose registers
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rbp
    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    rbx
    push    rax

    ; First parameter (rcx) = pointer to saved registers on stack
    mov     rcx, rsp
    sub     rsp, 28h        ; Shadow space for Windows x64 ABI
    call    VmExitHandler
    add     rsp, 28h

    ; Check if VmExitHandler signaled shutdown (RAX on stack = 0xDEADC0DE)
    mov     rax, [rsp]      ; Check saved RAX
    cmp     rax, 0DEADC0DEh
    je      _vmx_shutdown

    ; Normal path: restore registers and VMRESUME
    pop     rax
    pop     rbx
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rbp
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    vmresume

    ; If VMRESUME fails, spin (should never happen)
    int     3
    jmp     $

_vmx_shutdown:
    ; Shutdown path: VmExitHandler advanced guest RIP in VMCS past VMCALL
    ; and set saved RAX = 0xDEADC0DE as the signal.
    ;
    ; Strategy:
    ;   1. VMREAD guest RSP and RIP while we still have scratch regs
    ;   2. Write guest RIP onto the guest stack as a return address
    ;   3. Stash adjusted guest RSP into the saved-RAX slot
    ;   4. Pop all 15 GPRs (RAX gets the stashed guest RSP)
    ;   5. Switch RSP to guest stack, VMXOFF, clear CR4.VMXE, RET

    ; Read guest RSP and guest RIP from VMCS (still in VMX-root)
    mov     rdx, 681Ch          ; VMCS_GUEST_RSP
    vmread  rax, rdx            ; rax = guest RSP
    mov     rdx, 681Eh          ; VMCS_GUEST_RIP (already advanced past VMCALL)
    vmread  rcx, rdx            ; rcx = guest RIP

    ; Push guest RIP as return address on the guest stack
    sub     rax, 8
    mov     [rax], rcx          ; guest stack: [guestRSP - 8] = guest RIP

    ; Overwrite saved RAX on host stack with adjusted guest RSP
    ; so we can retrieve it after popping all registers
    mov     [rsp], rax

    ; Restore all 15 GPRs — RAX gets the adjusted guest RSP
    pop     rax
    pop     rbx
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rbp
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    ; Switch to guest stack (RAX = guest RSP - 8, with RIP at [RSP])
    mov     rsp, rax

    vmxoff

    ; Disable CR4.VMXE
    mov     rax, cr4
    and     rax, NOT (1 SHL 13)
    mov     cr4, rax

    xor     rax, rax            ; clean return value
    ret                         ; pops guest RIP from guest stack

AsmVmExitHandler ENDP

;─────────────────────────────────────────────────────────────────
; AsmVmxLaunch
;
; Captures current CPU state as guest state in VMCS, sets up
; the host state, then executes VMLAUNCH. On success, execution
; continues at the instruction after the call to AsmVmxLaunch
; (now running as a guest under the hypervisor).
;
; RCX = pointer to VCPU structure
;─────────────────────────────────────────────────────────────────
AsmVmxLaunch PROC

    ; Save callee-saved registers
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    pushfq

    ; Write guest RSP (current stack pointer)
    mov     rax, rsp
    mov     rdx, 681Ch      ; VMCS_GUEST_RSP encoding
    vmwrite rdx, rax

    ; Write guest RIP = _guest_resume label
    lea     rax, _guest_resume
    mov     rdx, 681Eh      ; VMCS_GUEST_RIP encoding
    vmwrite rdx, rax

    ; Write Host RIP = AsmVmExitHandler
    lea     rax, AsmVmExitHandler
    mov     rdx, 6C16h      ; VMCS_HOST_RIP encoding
    vmwrite rdx, rax

    ; VMLAUNCH
    vmlaunch

    ; If we get here, VMLAUNCH failed
    ; CF=1 or ZF=1 indicates error
    jc      _launch_fail_cf
    jz      _launch_fail_zf

    ; Unknown failure
    mov     eax, 3
    jmp     _launch_cleanup

_launch_fail_cf:
    mov     eax, 1          ; VMLAUNCH failed: CF=1 (invalid VMCS)
    jmp     _launch_cleanup

_launch_fail_zf:
    mov     eax, 2          ; VMLAUNCH failed: ZF=1 (valid VMCS, error in field)
    jmp     _launch_cleanup

_guest_resume:
    ; We arrive here when VMLAUNCH succeeds.
    ; CPU is now running as guest under the hypervisor.
    xor     eax, eax        ; Return 0 = success

_launch_cleanup:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

AsmVmxLaunch ENDP

;─────────────────────────────────────────────────────────────────
; AsmVmxCall
;
; RCX = hypercall code (0xDEADC0DE for shutdown)
; Returns RAX = 0 on success
;─────────────────────────────────────────────────────────────────
AsmVmxCall PROC
    vmcall
    ret
AsmVmxCall ENDP

;─────────────────────────────────────────────────────────────────
; AsmInvept
;
; Execute INVEPT instruction.
; RCX = invept type (1 = single-context, 2 = all-context)
; RDX = pointer to INVEPT descriptor (128-bit: EPTP + reserved)
;─────────────────────────────────────────────────────────────────
AsmInvept PROC

    invept  rcx, OWORD PTR [rdx]
    jz      _invept_fail
    jc      _invept_fail
    xor     rax, rax
    ret

_invept_fail:
    mov     rax, 1
    ret

AsmInvept ENDP

;─────────────────────────────────────────────────────────────────
; AsmInvvpid
;
; Execute INVVPID instruction.
; RCX = invvpid type
; RDX = pointer to INVVPID descriptor
;─────────────────────────────────────────────────────────────────
AsmInvvpid PROC

    invvpid rcx, OWORD PTR [rdx]
    jz      _invvpid_fail
    jc      _invvpid_fail
    xor     rax, rax
    ret

_invvpid_fail:
    mov     rax, 1
    ret

AsmInvvpid ENDP

;─────────────────────────────────────────────────────────────────
; Segment register read helpers (x64 doesn't have C intrinsics
; for all segment registers)
;─────────────────────────────────────────────────────────────────
AsmReadCs  PROC
    mov     ax, cs
    ret
AsmReadCs  ENDP

AsmReadSs  PROC
    mov     ax, ss
    ret
AsmReadSs  ENDP

AsmReadDs  PROC
    mov     ax, ds
    ret
AsmReadDs  ENDP

AsmReadEs  PROC
    mov     ax, es
    ret
AsmReadEs  ENDP

AsmReadFs  PROC
    mov     ax, fs
    ret
AsmReadFs  ENDP

AsmReadGs  PROC
    mov     ax, gs
    ret
AsmReadGs  ENDP

AsmReadTr  PROC
    str     ax
    ret
AsmReadTr  ENDP

AsmReadLdtr PROC
    sldt    ax
    ret
AsmReadLdtr ENDP

END
