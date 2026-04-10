// SPDX-License-Identifier: GPL-2.0
//
// B5 — Privilege escalation detection (T1068)
//
// kprobe: commit_creds
//
// `commit_creds(struct cred *new)` is the single kernel function that installs
// new process credentials.  Any path that elevates a non-root process to uid 0
// must call it — including exploits leveraging kernel vulnerabilities.
//
// Detection logic:
//   - Read the *incoming* (new) uid.
//   - If new_uid != 0, ignore (not a root escalation).
//   - Read the *current* (old) uid from task->real_cred.
//   - If old_uid == 0, ignore (process was already root).
//   - Emit an event — this is a non-root → root transition.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must stay ABI-compatible with CredsEvent in events.rs (repr(C)).
struct creds_event {
    u32  pid;
    u32  ppid;
    u32  old_uid;
    u32  new_uid;
    char comm[16];
    u64  ts_ns;
};

// 1 MiB ring buffer — privilege escalations should be infrequent.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} creds_events SEC(".maps");

// ── kprobe: commit_creds ─────────────────────────────────────────────────────
//
// Kernel prototype:
//   int commit_creds(struct cred *new);

SEC("kprobe/commit_creds")
int BPF_KPROBE(handle_commit_creds, struct cred *new_cred)
{
    // Fast path: bail early if new credentials are not uid 0.
    u32 new_uid = BPF_CORE_READ(new_cred, uid.val);
    if (new_uid != 0) return 0;

    // Retrieve the current (old) credentials from task_struct.
    struct task_struct *task     = (struct task_struct *)bpf_get_current_task();
    const struct cred  *old_cred = BPF_CORE_READ(task, real_cred);
    u32                 old_uid  = BPF_CORE_READ(old_cred, uid.val);

    // Skip if the process was already running as root — not an escalation.
    if (old_uid == 0) return 0;

    struct creds_event *e = bpf_ringbuf_reserve(&creds_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid     = bpf_get_current_pid_tgid() >> 32;
    e->ppid    = BPF_CORE_READ(task, real_parent, tgid);
    e->old_uid = old_uid;
    e->new_uid = new_uid; // always 0 here, kept for schema consistency
    e->ts_ns   = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
