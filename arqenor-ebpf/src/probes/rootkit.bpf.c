// SPDX-License-Identifier: GPL-2.0
//
// B6 — Rootkit / kernel module load detection (T1014)
//
// kprobe: do_init_module
//
// `do_init_module(struct module *mod)` is called by the kernel immediately
// after a module has been loaded and linked but before its `init()` function
// runs.  Hooking this function gives us:
//   - The module name (mod->name) before any rootkit self-hiding code executes.
//   - The loading process identity (pid, comm).
//
// Every call — including legitimate insmod/modprobe — is emitted.  Downstream
// detection rules are responsible for allow-listing expected modules.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must stay ABI-compatible with ModuleEvent in events.rs (repr(C)).
struct module_event {
    u32  pid;
    char comm[16];
    char name[64];  // module name from mod->name (kernel max is MODULE_NAME_LEN = 56)
    u64  ts_ns;
};

// 1 MiB ring buffer — kernel module loads are rare in normal operation.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} module_events SEC(".maps");

// ── kprobe: do_init_module ───────────────────────────────────────────────────
//
// Kernel prototype:
//   static noinline int do_init_module(struct module *mod);

SEC("kprobe/do_init_module")
int BPF_KPROBE(handle_do_init_module, struct module *mod)
{
    struct module_event *e = bpf_ringbuf_reserve(&module_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // BPF_CORE_READ_STR_INTO reads a fixed-length string from a kernel pointer
    // using CO-RE relocations — safe across kernel versions.
    BPF_CORE_READ_STR_INTO(&e->name, mod, name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
