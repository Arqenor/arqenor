// SPDX-License-Identifier: GPL-2.0
//
// B2 — Process execution telemetry (T1059)
//
// Tracepoints hooked:
//   - syscalls/sys_enter_execve
//   - syscalls/sys_enter_execveat  (shares the same handler)
//
// Every call to execve(2)/execveat(2) emits one `execve_event` to the
// `execve_events` ring buffer, capturing the PID, PPID, UID, process name,
// target binary path, and the first positional argument (argv[0]).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must stay ABI-compatible with ExecveEvent in events.rs (repr(C)).
struct execve_event {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];      // current process name (kernel comm, max 16 bytes)
    char filename[256]; // path of the executable being launched
    char argv0[128];    // argv[0] from userspace (may differ from filename)
    u64  ts_ns;         // bpf_ktime_get_ns() at event time
};

// Ring buffer consumed by the userspace loader (EbpfAgent).
// 16 MB capacity — large enough to absorb short bursts of fork-heavy workloads.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} execve_events SEC(".maps");

// ── sys_enter_execve ─────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct execve_event *e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // ctx->args[0] — const char __user *filename
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // ctx->args[1] — const char __user *const __user *argv
    // Read argv[0] (the first element of the argv array).
    const char **argv = (const char **)ctx->args[1];
    const char  *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0)
        bpf_probe_read_user_str(e->argv0, sizeof(e->argv0), arg0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── sys_enter_execveat ───────────────────────────────────────────────────────
// execveat(dirfd, pathname, argv, envp, flags) — args layout differs slightly:
//   args[0] = dirfd, args[1] = pathname, args[2] = argv

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct execve_event *e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // args[1] = pathname
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // args[2] = argv
    const char **argv = (const char **)ctx->args[2];
    const char  *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0)
        bpf_probe_read_user_str(e->argv0, sizeof(e->argv0), arg0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
