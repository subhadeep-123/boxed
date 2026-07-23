use std::path::Path;

use anyhow::{Context, Result, bail};
use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
use libc::{
    PR_SET_SECCOMP, SECCOMP_MODE_FILTER, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL,
    SECCOMP_RET_KILL_PROCESS,
};
use libc::{seccomp_data, sock_filter, sock_fprog};
use log::info;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    default_action: String,
    #[serde(default)]
    architectures: Vec<String>,
    #[serde(default)]
    syscalls: Vec<SyscallRule>,
}

#[derive(Deserialize)]
struct SyscallRule {
    names: Vec<String>,
    action: String,
    #[serde(default)]
    args: Vec<ArgRule>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ArgRule {
    index: u32,
    value: u64,
    value_two: Option<u64>,
    op: String,
}

#[derive(Debug)]
struct ResolveRule {
    numbers: Vec<i64>,
    action: u32,
}

#[derive(Debug)]
pub struct ResolvedProfile {
    rules: Vec<ResolveRule>,
    default_action: u32,
}

impl SeccompProfile {
    pub fn from_file(path: impl AsRef<Path>) -> Result<ResolvedProfile> {
        let path = path.as_ref();
        info!("loading seccomp profile from {}", path.display());

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read seccomp profile at {}", path.display()))?;

        let profile: SeccompProfile = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse seccomp profile at {}", path.display()))?;

        let profile = profile
            .resolve()
            .context("seccomp profile validation failed")?;

        info!(
            "seccomp profile validated: {} rule(s), default action resolved",
            profile.rules.len()
        );

        Ok(profile)
    }

    fn resolve(&self) -> Result<ResolvedProfile> {
        if !self.architectures.is_empty()
            && !self.architectures.iter().any(|a| a == "SCMP_ARCH_X86_64")
        {
            bail!("profile does not target SCMP_ARCH_X86_64, the only architecture boxed supports");
        }

        let rules = self
            .syscalls
            .iter()
            .map(|rule| rule.resolve())
            .collect::<Result<Vec<_>>>()?;

        let default_action = resolve_action(&self.default_action).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown or unsupported default action name: {}",
                self.default_action
            )
        })?;

        Ok(ResolvedProfile {
            rules,
            default_action,
        })
    }
}

impl SyscallRule {
    fn resolve(&self) -> Result<ResolveRule> {
        if self.names.is_empty() {
            bail!("syscall rule must contain at least one name");
        }

        if !self.args.is_empty() {
            bail!(
                "syscall rule for {:?} uses arg-conditional matching, which isn't supported yet",
                self.names
            );
        }

        let action = resolve_action(&self.action).ok_or_else(|| {
            anyhow::anyhow!("unknown or unsupported action name: {}", self.action)
        })?;

        let numbers = self
            .names
            .iter()
            .map(|name| {
                syscall_number(name)
                    .ok_or_else(|| anyhow::anyhow!("unknown or unsupported syscall name: {name}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ResolveRule { numbers, action })
    }
}

fn resolve_action(action: &str) -> Option<u32> {
    match action {
        "SCMP_ACT_ALLOW" => Some(SECCOMP_RET_ALLOW),
        "SCMP_ACT_ERRNO" => Some(SECCOMP_RET_ERRNO),
        "SCMP_ACT_KILL" => Some(SECCOMP_RET_KILL),
        "SCMP_ACT_KILL_PROCESS" => Some(SECCOMP_RET_KILL_PROCESS),
        _ => None,
    }
}

fn syscall_number(name: &str) -> Option<i64> {
    match name {
        // system state / boot / power
        "reboot" => Some(libc::SYS_reboot),
        "acct" => Some(libc::SYS_acct),
        "swapon" => Some(libc::SYS_swapon),
        "swapoff" => Some(libc::SYS_swapoff),

        // filesystem mounting — container escape surface
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        "pivot_root" => Some(libc::SYS_pivot_root),
        "open_by_handle_at" => Some(libc::SYS_open_by_handle_at),
        "sysfs" => Some(libc::SYS_sysfs),

        // kernel module loading — arbitrary kernel code execution
        "init_module" => Some(libc::SYS_init_module),
        "finit_module" => Some(libc::SYS_finit_module),
        "delete_module" => Some(libc::SYS_delete_module),

        // kernel image loading
        "kexec_load" => Some(libc::SYS_kexec_load),
        "kexec_file_load" => Some(libc::SYS_kexec_file_load),

        // debugging/introspection of other processes
        "ptrace" => Some(libc::SYS_ptrace),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv),
        "process_vm_writev" => Some(libc::SYS_process_vm_writev),
        "kcmp" => Some(libc::SYS_kcmp),

        // direct hardware I/O
        "iopl" => Some(libc::SYS_iopl),
        "ioperm" => Some(libc::SYS_ioperm),

        // clock/time tampering
        "settimeofday" => Some(libc::SYS_settimeofday),
        "clock_settime" => Some(libc::SYS_clock_settime),
        "clock_adjtime" => Some(libc::SYS_clock_adjtime),
        "adjtimex" => Some(libc::SYS_adjtimex),

        // kernel keyring
        "add_key" => Some(libc::SYS_add_key),
        "request_key" => Some(libc::SYS_request_key),
        "keyctl" => Some(libc::SYS_keyctl),

        // eBPF, perf, io_uring
        "bpf" => Some(libc::SYS_bpf),
        "perf_event_open" => Some(libc::SYS_perf_event_open),
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),

        // NUMA memory policy
        "mbind" => Some(libc::SYS_mbind),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "move_pages" => Some(libc::SYS_move_pages),

        // namespace joining
        "setns" => Some(libc::SYS_setns),

        // obsolete/rarely-needed, historically privilege-adjacent
        "quotactl" => Some(libc::SYS_quotactl),
        "nfsservctl" => Some(libc::SYS_nfsservctl),
        "lookup_dcookie" => Some(libc::SYS_lookup_dcookie),
        "uselib" => Some(libc::SYS_uselib),
        "ustat" => Some(libc::SYS_ustat),
        "userfaultfd" => Some(libc::SYS_userfaultfd),
        "_sysctl" => Some(libc::SYS__sysctl),
        "personality" => Some(libc::SYS_personality),

        // baseline / dynamic-linker syscalls — needed by any ALLOW rule
        // for a real binary (see Step 2's echo/prlimit64 investigation)
        "execve" => Some(libc::SYS_execve),
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "close" => Some(libc::SYS_close),
        "openat" => Some(libc::SYS_openat),
        "fstat" => Some(libc::SYS_fstat),
        "brk" => Some(libc::SYS_brk),
        "mmap" => Some(libc::SYS_mmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "munmap" => Some(libc::SYS_munmap),
        "access" => Some(libc::SYS_access),
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "rseq" => Some(libc::SYS_rseq),
        "getrandom" => Some(libc::SYS_getrandom),
        "exit_group" => Some(libc::SYS_exit_group),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "pread64" => Some(libc::SYS_pread64),

        _ => None,
    }
}

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
    sock_filter { code, jt, jf, k }
}

fn initialize_filters() -> Vec<sock_filter> {
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

    prog
}

fn build_filter(profile: Option<&ResolvedProfile>) -> Vec<sock_filter> {
    let mut prog = initialize_filters();

    match profile {
        Some(profile) => {
            for rule in &profile.rules {
                for nr in &rule.numbers {
                    prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, *nr as u32));
                    prog.push(stmt((BPF_RET | BPF_K) as u16, rule.action));
                }
            }

            prog.push(stmt((BPF_RET | BPF_K) as u16, profile.default_action));
        }
        None => {
            // Step <4> one Pair Per Dangerous SYSCall - same shape as before,  RET payload flipped
            for &nr in DANGEROUS_SYSCALLS {
                prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, nr as u32));
                prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));
            }

            // Step <4> Fell through every pair without matching -> Allow
            prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW));
        }
    }

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
    info!("seccomp filter installed ({} BPF instructions)", prog.len());
    Ok(())
}

pub fn apply_default_filter(profile: Option<&ResolvedProfile>) -> Result<()> {
    match profile {
        Some(profile) => info!(
            "applying custom seccomp filter ({} rule(s))",
            profile.rules.len()
        ),
        None => info!(
            "applying default seccomp filter ({} syscalls denied)",
            DANGEROUS_SYSCALLS.len()
        ),
    }

    let mut prog = build_filter(profile);

    install_filter(&mut prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_number_resolves_known_name() {
        assert_eq!(syscall_number("reboot"), Some(libc::SYS_reboot));
        assert_eq!(syscall_number("execve"), Some(libc::SYS_execve));
    }

    #[test]
    fn syscall_number_rejects_unknown_name() {
        assert_eq!(syscall_number("not_a_real_syscall"), None);
    }

    #[test]
    fn resolve_action_resolves_known_action() {
        assert_eq!(resolve_action("SCMP_ACT_ALLOW"), Some(SECCOMP_RET_ALLOW));
        assert_eq!(
            resolve_action("SCMP_ACT_KILL_PROCESS"),
            Some(SECCOMP_RET_KILL_PROCESS)
        );
    }

    #[test]
    fn resolve_action_rejects_unknown_action() {
        assert_eq!(resolve_action("SCMP_ACT_NOTIFY"), None);
        assert_eq!(resolve_action(""), None);
    }

    #[test]
    fn dangerous_syscalls_not_empty() {
        assert!(!DANGEROUS_SYSCALLS.is_empty());
    }

    #[test]
    fn dangerous_syscalls_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &nr in DANGEROUS_SYSCALLS {
            assert!(seen.insert(nr), "duplicate syscall number: {nr}");
        }
    }

    fn parse(json: &str) -> Result<ResolvedProfile> {
        let profile: SeccompProfile = serde_json::from_str(json)?;
        profile.resolve()
    }

    #[test]
    fn resolve_valid_profile_succeeds() {
        let profile = parse(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["execve", "write"], "action": "SCMP_ACT_ALLOW"},
                    {"names": ["reboot"], "action": "SCMP_ACT_KILL"}
                ]
            }"#,
        )
        .expect("valid profile should resolve");

        assert_eq!(profile.rules.len(), 2);
        assert_eq!(profile.default_action, SECCOMP_RET_ERRNO);
        assert_eq!(
            profile.rules[0].numbers,
            vec![libc::SYS_execve, libc::SYS_write]
        );
        assert_eq!(profile.rules[0].action, SECCOMP_RET_ALLOW);
        assert_eq!(profile.rules[1].action, SECCOMP_RET_KILL);
    }

    #[test]
    fn resolve_rejects_empty_names() {
        let err = parse(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": [], "action": "SCMP_ACT_ALLOW"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one name"));
    }

    #[test]
    fn resolve_rejects_unknown_syscall_name() {
        let err = parse(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["not_real"], "action": "SCMP_ACT_ALLOW"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not_real"));
    }

    #[test]
    fn resolve_rejects_unknown_action() {
        let err = parse(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_TRACE"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("SCMP_ACT_TRACE"));
    }

    #[test]
    fn resolve_rejects_args_conditional_rule() {
        let err = parse(
            r#"{
                "defaultAction": "SCMP_ACT_ALLOW",
                "syscalls": [{
                    "names": ["personality"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]
                }]
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("arg-conditional matching"));
    }

    #[test]
    fn resolve_rejects_unknown_default_action() {
        let err = parse(r#"{"defaultAction": "SCMP_ACT_NOTIFY", "syscalls": []}"#).unwrap_err();
        assert!(err.to_string().contains("default action"));
    }

    #[test]
    fn resolve_rejects_non_x86_64_architecture() {
        let err = parse(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_AARCH64"], "syscalls": []}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("SCMP_ARCH_X86_64"));
    }

    #[test]
    fn resolve_accepts_empty_architectures() {
        parse(r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}"#)
            .expect("empty architectures should be treated as x86_64");
    }

    #[test]
    fn resolve_accepts_architectures_containing_x86_64() {
        parse(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_ARM", "SCMP_ARCH_X86_64"], "syscalls": []}"#,
        )
        .expect("x86_64 present among other architectures should be accepted");
    }

    #[test]
    fn build_filter_default_ends_with_allow() {
        let prog = build_filter(None);
        let last = prog.last().expect("default filter should not be empty");
        assert_eq!(last.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn build_filter_from_profile_uses_resolved_default_action() {
        let profile = parse(r#"{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}"#).unwrap();
        let prog = build_filter(Some(&profile));
        let last = prog.last().expect("profile filter should not be empty");
        assert_eq!(last.k, SECCOMP_RET_ERRNO);
    }
}
