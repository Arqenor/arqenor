// SPDX-License-Identifier: GPL-2.0
//
// B4 — Persistence detection via sensitive file access monitoring
//       (T1574.006 — LD_PRELOAD hijack, T1053.003 — cron-based persistence)
//
// Tracepoint hooked:
//   - syscalls/sys_enter_openat
//
// Sensitive paths monitored (prefix-matched in kernel space):
//   /etc/ld     → /etc/ld.so.preload      (LD_PRELOAD hijack)
//   /etc/cr     → /etc/cron.d/, /etc/crontab, /etc/cron.{hourly,daily,…}
//
// The probe fires on *open* (before write) because we get the filename at
// open time.  A production deployment could add a secondary map keyed on fd
// to confirm a subsequent write(2) call if required.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must stay ABI-compatible with FileWriteEvent in events.rs (repr(C)).
struct file_write_event {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    char filename[256];
    u64  ts_ns;
};

// 1 MiB ring buffer — persistence events are rare.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} file_write_events SEC(".maps");

// ── tracepoint: sys_enter_openat ─────────────────────────────────────────────
//
// syscall: openat(dirfd, pathname, flags, mode)
//   args[0] = dirfd
//   args[1] = pathname (const char __user *)
//   args[2] = flags
//   args[3] = mode

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *fname = (const char *)ctx->args[1];

    // Read the first 16 bytes of the path for a cheap prefix check.
    // Full path is read later only if the prefix matches — avoids unnecessary
    // work on the hot path for every open() call on the system.
    char prefix[16] = {};
    bpf_probe_read_user_str(prefix, sizeof(prefix), fname);

    // Must start with "/etc/"
    if (prefix[0] != '/') return 0;
    if (prefix[1] != 'e') return 0;
    if (prefix[2] != 't') return 0;
    if (prefix[3] != 'c') return 0;
    if (prefix[4] != '/') return 0;

    // Sixth character must be 'l' (/etc/ld…) or 'c' (/etc/cr…).
    if (prefix[5] != 'l' && prefix[5] != 'c') return 0;

    // Path matched — reserve a ring buffer slot and capture the full event.
    struct file_write_event *e = bpf_ringbuf_reserve(&file_write_events, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
