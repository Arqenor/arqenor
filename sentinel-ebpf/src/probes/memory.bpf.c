// SPDX-License-Identifier: GPL-2.0
//
// B3 — Memory injection detection (T1055, T1055.008)
//
// Probes:
//   - kprobe/do_mmap         — anonymous RWX mappings (shellcode injection)
//   - tracepoint/syscalls/sys_enter_ptrace — ptrace attach to a foreign process
//
// Only events that cross a security boundary are emitted:
//   do_mmap   : prot must be RWX *and* the mapping must be anonymous (no file).
//   ptrace    : the attaching PID must differ from the target PID.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4
#define PROT_RWX   (PROT_READ | PROT_WRITE | PROT_EXEC)

// Must stay ABI-compatible with MmapEvent in events.rs (repr(C)).
struct mmap_event {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    u64  addr;   // requested / returned virtual address
    u64  len;    // mapping length in bytes
    u32  prot;   // PROT_* flags
    u32  flags;  // MAP_* flags
    u64  ts_ns;
};

// Must stay ABI-compatible with PtraceEvent in events.rs (repr(C)).
struct ptrace_event {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    u64  request;    // PTRACE_ATTACH, PTRACE_PEEKDATA, …
    u64  target_pid;
    u64  ts_ns;
};

// 4 MiB ring buffer for mmap events (high frequency — sized conservatively).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} mmap_events SEC(".maps");

// 1 MiB ring buffer for ptrace events (lower frequency).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} ptrace_events SEC(".maps");

// ── kprobe: do_mmap ──────────────────────────────────────────────────────────
//
// Kernel prototype (simplified):
//   unsigned long do_mmap(struct file *file, unsigned long addr,
//                         unsigned long len,  unsigned long prot,
//                         unsigned long flags, ...);

SEC("kprobe/do_mmap")
int BPF_KPROBE(handle_mmap,
               struct file    *file,
               unsigned long   addr,
               unsigned long   len,
               unsigned long   prot,
               unsigned long   flags)
{
    // Only care about RWX mappings — everything else is benign.
    if ((prot & PROT_RWX) != PROT_RWX) return 0;

    // Only flag *anonymous* mappings (file == NULL).
    // File-backed RWX mappings are used legitimately by JIT compilers.
    if (file != NULL) return 0;

    struct mmap_event *e = bpf_ringbuf_reserve(&mmap_events, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->addr  = addr;
    e->len   = len;
    e->prot  = (u32)prot;
    e->flags = (u32)flags;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── tracepoint: sys_enter_ptrace ─────────────────────────────────────────────
//
// syscall: ptrace(request, pid, addr, data)
//   args[0] = request
//   args[1] = pid  (target process)
//   args[2] = addr
//   args[3] = data

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    u64 request    = ctx->args[0];
    u64 target_pid = ctx->args[1];
    u32 cur_pid    = bpf_get_current_pid_tgid() >> 32;

    // Skip self-ptrace (legitimate use by debuggers, sanitizers, etc.).
    if ((u32)target_pid == cur_pid) return 0;

    struct ptrace_event *e = bpf_ringbuf_reserve(&ptrace_events, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid        = cur_pid;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->request    = request;
    e->target_pid = target_pid;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
