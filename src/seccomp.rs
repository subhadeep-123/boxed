use anyhow::{Context, Result};
use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, seccomp_data, sock_filter, sock_fprog,
};

// AUDIT_ARCH_X86_64 isn't in the libc crate — from linux/audit.h,
// EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

// Allowed Syscalls from strace -f /bin/echo hello
const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_access,
    libc::SYS_openat,
    libc::SYS_fstat,
    libc::SYS_close,
    libc::SYS_read,
    libc::SYS_pread64,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_getrandom,
    libc::SYS_write,
    libc::SYS_exit_group,
    libc::SYS_prlimit64,
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

    // Step <4> one [compare, allow] PAIR per allowed syscall — this pairing
    //    is the trick that avoids hand-computing long forward jump
    //    offsets: jf=1 always means "skip just the next instruction",
    //    which is always the RET_ALLOW directly below this JEQ.
    for &nr in ALLOWED_SYSCALLS {
        prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, nr as u32));
        prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW));
    }

    // Step <4> Fell through every pair without matching -> Kill
    prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));

    prog
}

// Installer Stage
fn install_filter(prog: &mut [libc::sock_filter]) -> Result<()> {
    // build sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() }
    // unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog as *const _ as c_ulong, 0, 0) }
    // ret == -1 -> Err(Errno::last()).context(...)
    // else Ok(())

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
