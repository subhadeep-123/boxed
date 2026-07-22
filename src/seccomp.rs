use anyhow::{Context, Result};
use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, seccomp_data, sock_filter, sock_fprog,
};

// AUDIT_ARCH_X86_64 isn't in the libc crate — from linux/audit.h,
// EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

// Dangerous  Syscalls
const DANGEROUS_SYSCALLS: &[i64] = &[
    // system state / boot / power
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    // filesystem mounting — container escape surface
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_by_handle_at,
    libc::SYS_sysfs,
    // kernel module loading — arbitrary kernel code execution
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    // kernel image loading
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    // debugging/introspection of other processes
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    // direct hardware I/O
    libc::SYS_iopl,
    libc::SYS_ioperm,
    // clock/time tampering
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    // kernel keyring
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    // eBPF, perf, io_uring — kernel-level tracing/execution surfaces
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // NUMA memory policy — rarely needed, historically buggy
    libc::SYS_mbind,
    libc::SYS_set_mempolicy,
    libc::SYS_get_mempolicy,
    libc::SYS_move_pages,
    // namespace joining
    libc::SYS_setns,
    // obsolete/rarely-needed, historically privilege-adjacent
    libc::SYS_quotactl,
    libc::SYS_nfsservctl,
    libc::SYS_lookup_dcookie,
    libc::SYS_uselib,
    libc::SYS_ustat,
    libc::SYS_userfaultfd,
    libc::SYS__sysctl,
    libc::SYS_personality,
];

// Instruction Constructors (Internal Helpers)
fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: jt,
        jf: jf,
        k,
    }
}

// Assembly
fn build_filter() -> Vec<sock_filter> {
    let mut prog = Vec::new();

    // 1. Arch gate - Must be the first two Instruction
    // Step <0> Load the 4 bytes at arch's offset into the scratch register
    prog.push(stmt(
        (BPF_LD | BPF_W | BPF_ABS) as u16,
        std::mem::offset_of!(seccomp_data, arch) as u32,
    ));
    // Step <1> If scratch == x86_64, skip forward 1 (→ #3); else fall through (→ #2)
    prog.push(jump(
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        1,
        0,
        AUDIT_ARCH_X86_64,
    ));
    // Step <2> Wrong arch - die
    prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));

    // 2. load syscall nr once, every check below reuses it
    // Step <3> Load the 4 bytes at nr's offset into scratch
    prog.push(stmt(
        (BPF_LD | BPF_W | BPF_ABS) as u16,
        std::mem::offset_of!(seccomp_data, nr) as u32,
    ));

    // Step <4> one Pair Per Dangerous SYSCall - same shape as before,  RET payload flipped
    for &nr in DANGEROUS_SYSCALLS {
        prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, nr as u32));
        prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));
    }

    // Step <4> Fell through every pair without matching -> Allow
    prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW));

    prog
}

// Installer Stage
fn install_filter(prog: &mut [libc::sock_filter]) -> Result<()> {
    let fprog = sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &fprog as *const sock_fprog as libc::c_ulong,
        )
    };

    if ret != 0 {
        return Err(nix::errno::Errno::last()).context("failed to install seccomp filter");
    }
    Ok(())
}

pub fn apply_default_filter() -> Result<()> {
    let mut prog = build_filter();
    install_filter(&mut prog)
}
