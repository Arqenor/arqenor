use crate::linux::persistence_advanced::{
    detect_git_hooks, detect_pam_modules, detect_shell_profiles, detect_ssh_authorized_keys,
};
use arqenor_core::{
    error::ArqenorError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};
use async_trait::async_trait;
use std::{fs, path::Path};

pub struct LinuxPersistenceDetector;

impl LinuxPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

const SYSTEMD_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
];

const CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

/// Known-legitimate kernel modules — filesystem, storage, network, crypto, USB,
/// PCI, input, video, and Bluetooth families.  Modules in this set are skipped
/// during C3 scanning.
const KERNEL_MODULE_WHITELIST: &[&str] = &[
    // filesystems
    "ext4",
    "ext3",
    "ext2",
    "xfs",
    "btrfs",
    "f2fs",
    "vfat",
    "fat",
    "ntfs",
    "nfs",
    "nfs_acl",
    "nfsd",
    "nfsv4",
    "nfsv3",
    "nfsv2",
    "overlay",
    "squashfs",
    "tmpfs",
    "ramfs",
    "iso9660",
    "udf",
    "fuse",
    "ceph",
    "erofs",
    // storage / DM / RAID
    "loop",
    "dm_mod",
    "dm_crypt",
    "dm_mirror",
    "dm_multipath",
    "dm_thin_pool",
    "dm_log",
    "dm_region_hash",
    "md_mod",
    "raid0",
    "raid1",
    "raid10",
    "raid456",
    "libcrc32c",
    "scsi_mod",
    "sd_mod",
    "sr_mod",
    "sg",
    "ahci",
    "libahci",
    "libata",
    "ata_piix",
    "ata_generic",
    "mpt3sas",
    "megaraid_sas",
    "nvme",
    "nvme_core",
    "nvme_fabrics",
    "nvme_tcp",
    "virtio_blk",
    "virtio_scsi",
    // network
    "tcp_cubic",
    "tcp_bbr",
    "ipv6",
    "inet_diag",
    "tcp_diag",
    "udp_diag",
    "nf_conntrack",
    "nf_nat",
    "nf_tables",
    "nft_counter",
    "nft_log",
    "nft_nat",
    "nft_masq",
    "ipt_MASQUERADE",
    "xt_conntrack",
    "xt_state",
    "xt_multiport",
    "xt_tcpudp",
    "xt_REDIRECT",
    "xt_LOG",
    "xt_mark",
    "veth",
    "bridge",
    "bonding",
    "team",
    "tun",
    "tap",
    "dummy",
    "e1000",
    "e1000e",
    "igb",
    "ixgbe",
    "i40e",
    "ice",
    "mlx4_core",
    "mlx5_core",
    "virtio_net",
    "vmxnet3",
    // crypto
    "aes",
    "aes_generic",
    "aes_x86_64",
    "aesni_intel",
    "ghash_clmulni_intel",
    "sha1_generic",
    "sha256_generic",
    "sha512_generic",
    "sha1_ssse3",
    "sha256_ssse3",
    "sha512_ssse3",
    "crct10dif_generic",
    "crct10dif_pclmul",
    "crc32_generic",
    "crc32c_generic",
    "crc32c_intel",
    "crc32_pclmul",
    "chacha20poly1305",
    "chacha_x86_64",
    "poly1305_x86_64",
    "curve25519_x86_64",
    "ecdh_generic",
    "ecb",
    "cbc",
    "ctr",
    "gcm",
    "ccm",
    "xts",
    "lrw",
    "hmac",
    "drbg",
    "jitterentropy_rng",
    "ansi_cprng",
    // USB
    "usbcore",
    "usb_common",
    "ehci_hcd",
    "xhci_hcd",
    "ohci_hcd",
    "uhci_hcd",
    "usb_storage",
    "uas",
    "hid",
    "hid_generic",
    "usbhid",
    "cdc_acm",
    "cdc_ether",
    "rndis_host",
    // PCI / platform
    "pci_stub",
    "pciehp",
    "shpchp",
    "acpi_cpufreq",
    "intel_pstate",
    "powernow_k8",
    "acpiphp",
    "button",
    "thermal",
    "fan",
    // input / HID
    "input_core",
    "evdev",
    "mousedev",
    "joydev",
    "psmouse",
    "i8042",
    "atkbd",
    "libps2",
    "serio",
    "serio_raw",
    // GPU / video / DRM
    "drm",
    "drm_kms_helper",
    "drm_panel_orientation_quirks",
    "fbdev",
    "fb",
    "fbcon",
    "cfbfillrect",
    "cfbcopyarea",
    "cfbimgblt",
    "i915",
    "radeon",
    "amdgpu",
    "nouveau",
    "virtio_gpu",
    "vmwgfx",
    // Bluetooth
    "bluetooth",
    "btusb",
    "btrtl",
    "btbcm",
    "btintel",
    "rfcomm",
    "bnep",
    "hidp",
    "hci_uart",
    // sound
    "snd",
    "snd_timer",
    "snd_pcm",
    "snd_rawmidi",
    "snd_seq",
    "snd_seq_device",
    "snd_hda_core",
    "snd_hda_intel",
    "snd_hda_codec",
    "snd_hda_codec_generic",
    "snd_ac97_codec",
    "snd_soc_core",
    "snd_compress",
    "soundcore",
    // virtualisation
    "kvm",
    "kvm_intel",
    "kvm_amd",
    "vhost",
    "vhost_net",
    "vhost_scsi",
    "virtio",
    "virtio_pci",
    "virtio_ring",
    "virtio_mmio",
    // misc kernel subsystems
    "autofs4",
    "autofs",
    "sunrpc",
    "rpcsec_gss_krb5",
    "auth_rpcgss",
    "lockd",
    "grace",
    "configfs",
    "efivarfs",
    "zstd",
    "lz4",
    "lz4hc",
    "zlib_inflate",
    "zlib_deflate",
    "binfmt_misc",
    "cpuid",
    "msr",
];

// ── helpers ──────────────────────────────────────────────────────────────────

/// Return the value of `key=` from a plain key=value unit-file line, trimmed.
fn ini_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let line = line.trim();
    let stripped = line.strip_prefix(key)?.strip_prefix('=')?;
    Some(stripped.trim())
}

/// Parse a systemd unit file and return the value of the first occurrence
/// of `key` (e.g. `"ExecStart"`, `"OnCalendar"`, `"Unit"`).
fn parse_unit_field(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .find_map(|l| ini_value(l, key))
        .map(|v| v.to_owned())
}

// ── C1: systemd services & timers  (ATT&CK T1053.006) ────────────────────────

/// Detect systemd service units and timer units.
///
/// ATT&CK T1053.006 — Scheduled Task/Job: Systemd Timers.
/// Services are enumerated for completeness; timers are the primary persistence
/// mechanism.  For each `.timer` file we also resolve the associated `.service`
/// to extract the actual `ExecStart` command.
fn detect_systemd(entries: &mut Vec<PersistenceEntry>) {
    for dir in SYSTEMD_DIRS {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        let rd = match fs::read_dir(path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for de in rd.filter_map(|e| e.ok()) {
            let file_name = de.file_name().to_string_lossy().into_owned();
            let file_path = de.path();

            if file_name.ends_with(".timer") {
                // --- timer unit ---
                let timer_content = fs::read_to_string(&file_path).unwrap_or_default();

                let on_calendar = parse_unit_field(&timer_content, "OnCalendar")
                    .or_else(|| parse_unit_field(&timer_content, "OnBootSec"))
                    .unwrap_or_default();

                // resolve associated service file
                let service_name = parse_unit_field(&timer_content, "Unit").unwrap_or_else(|| {
                    file_name.trim_end_matches(".timer").to_owned() + ".service"
                });

                let exec_start = {
                    // look for the service in the same directory first, then all dirs
                    let service_path = file_path.with_file_name(&service_name);
                    let content = if service_path.exists() {
                        fs::read_to_string(&service_path).unwrap_or_default()
                    } else {
                        // search remaining systemd dirs
                        SYSTEMD_DIRS
                            .iter()
                            .map(|d| Path::new(d).join(&service_name))
                            .find(|p| p.exists())
                            .and_then(|p| fs::read_to_string(p).ok())
                            .unwrap_or_default()
                    };
                    parse_unit_field(&content, "ExecStart").unwrap_or_default()
                };

                let schedule_info = if on_calendar.is_empty() {
                    String::new()
                } else {
                    format!(" [schedule: {on_calendar}]")
                };

                entries.push(PersistenceEntry {
                    kind: PersistenceKind::SystemdUnit,
                    name: format!("timer: {file_name} → {exec_start}{schedule_info}"),
                    command: exec_start,
                    location: file_path.to_string_lossy().into_owned(),
                    is_new: false,
                });
            } else if file_name.ends_with(".service") {
                // --- service unit ---
                let content = fs::read_to_string(&file_path).unwrap_or_default();
                let exec_start = parse_unit_field(&content, "ExecStart").unwrap_or_default();

                entries.push(PersistenceEntry {
                    kind: PersistenceKind::SystemdUnit,
                    name: file_name,
                    command: exec_start,
                    location: file_path.to_string_lossy().into_owned(),
                    is_new: false,
                });
            }
        }
    }
}

// ── cron  (ATT&CK T1053.003) ─────────────────────────────────────────────────

/// Detect cron job files in standard cron directories.
///
/// ATT&CK T1053.003 — Scheduled Task/Job: Cron.
fn detect_cron(entries: &mut Vec<PersistenceEntry>) {
    for dir in CRON_DIRS {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        let rd = match fs::read_dir(path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for de in rd.filter_map(|e| e.ok()) {
            let name = de.file_name().to_string_lossy().into_owned();
            entries.push(PersistenceEntry {
                kind: PersistenceKind::Cron,
                name,
                command: String::new(),
                location: de.path().to_string_lossy().into_owned(),
                is_new: false,
            });
        }
    }
}

// ── C2: LD_PRELOAD  (ATT&CK T1574.006) ───────────────────────────────────────

/// Detect LD_PRELOAD-based library injection via the environment variable and
/// the system-wide `/etc/ld.so.preload` file.
///
/// ATT&CK T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking.
/// The `/etc/ld.so.preload` file is higher severity than the env var because it
/// affects every dynamically linked process on the system.
fn detect_ld_preload(entries: &mut Vec<PersistenceEntry>) {
    // env var — affects only processes launched in this session
    if let Ok(val) = std::env::var("LD_PRELOAD") {
        if !val.is_empty() {
            entries.push(PersistenceEntry {
                kind: PersistenceKind::LdPreload,
                name: "LD_PRELOAD".into(),
                command: val,
                location: "environment".into(),
                is_new: false,
            });
        }
    }

    // /etc/ld.so.preload — system-wide, applies to every process
    const PRELOAD_FILE: &str = "/etc/ld.so.preload";
    if let Some(content) = fs::read_to_string(PRELOAD_FILE).ok() {
        for line in content.lines() {
            let lib = line.trim();
            if lib.is_empty() || lib.starts_with('#') {
                continue;
            }
            entries.push(PersistenceEntry {
                kind: PersistenceKind::LdPreload,
                name: format!("ld.so.preload: {lib}"),
                command: lib.to_owned(),
                location: PRELOAD_FILE.into(),
                is_new: false,
            });
        }
    }
}

// ── C3: kernel modules  (ATT&CK T1014) ───────────────────────────────────────

/// Detect suspicious loaded kernel modules by reading `/proc/modules`.
///
/// ATT&CK T1014 — Rootkit.
/// Each line in `/proc/modules` has the format:
///   `module_name size instances dependencies state offset`
/// Modules whose names appear in `KERNEL_MODULE_WHITELIST` are skipped.
/// Everything else is flagged so analysts can review unknown or third-party
/// kernel code.
fn detect_kernel_modules(entries: &mut Vec<PersistenceEntry>) {
    const PROC_MODULES: &str = "/proc/modules";
    let content = match fs::read_to_string(PROC_MODULES).ok() {
        Some(c) => c,
        None => return,
    };

    for line in content.lines() {
        // fields: name size instances deps state offset
        let mut fields = line.split_whitespace();
        let name = match fields.next() {
            Some(n) => n,
            None => continue,
        };
        // skip past size and instances
        let _ = fields.next();
        let _ = fields.next();
        // skip deps field
        let _ = fields.next();
        let state = fields.next().unwrap_or("Unknown");

        // normalise: kernel uses underscores and hyphens interchangeably
        let normalised = name.replace('-', "_");

        if KERNEL_MODULE_WHITELIST
            .iter()
            .any(|&w| w == normalised || w == name)
        {
            continue;
        }

        entries.push(PersistenceEntry {
            kind: PersistenceKind::KernelModule,
            name: name.to_owned(),
            command: state.to_owned(),
            location: PROC_MODULES.into(),
            is_new: false,
        });
    }
}

// ── trait impl ────────────────────────────────────────────────────────────────

#[async_trait]
impl PersistenceDetector for LinuxPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        let mut entries = Vec::new();

        detect_systemd(&mut entries);
        detect_cron(&mut entries);
        detect_ld_preload(&mut entries);
        detect_kernel_modules(&mut entries);
        entries.extend(detect_ssh_authorized_keys()); // C4 — T1098.004
        entries.extend(detect_pam_modules()); // C5 — T1556.003
        entries.extend(detect_shell_profiles()); // C6 — T1546.004
        entries.extend(detect_git_hooks()); // C7 — T1059

        Ok(entries)
    }

    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, ArqenorError> {
        let current = self.detect().await?;
        Ok(current
            .into_iter()
            .filter(|e| {
                !baseline
                    .iter()
                    .any(|b| b.name == e.name && b.location == e.location)
            })
            .map(|mut e| {
                e.is_new = true;
                e
            })
            .collect())
    }
}
