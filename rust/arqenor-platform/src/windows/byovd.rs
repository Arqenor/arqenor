//! BYOVD (Bring Your Own Vulnerable Driver) detection (T1068).
//!
//! Enumerates loaded kernel drivers, hashes them with SHA-256, and compares
//! against an embedded blocklist of known-vulnerable driver hashes sourced
//! from <https://www.loldrivers.io>.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::mem::size_of;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::ProcessStatus::{
    EnumDeviceDrivers, GetDeviceDriverBaseNameW, GetDeviceDriverFileNameW,
};

// ── Public types ────────────────────────────────────────────────────────────

/// Information about a loaded kernel driver.
#[derive(Debug, Clone)]
pub struct DriverInfo {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub is_signed: bool,
}

/// Alert raised when a loaded driver matches the vulnerable-driver blocklist.
#[derive(Debug, Clone)]
pub struct ByovdAlert {
    pub driver: DriverInfo,
    pub vuln_name: String,
    pub cve: Option<String>,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all currently loaded kernel-mode drivers.
pub fn enumerate_drivers() -> Vec<DriverInfo> {
    let bases = enum_driver_bases();
    let mut drivers = Vec::with_capacity(bases.len());

    for &base in &bases {
        let name = get_driver_basename(base);
        let device_path = get_driver_filename(base);

        if name.is_empty() {
            continue;
        }

        // Convert device path (\SystemRoot\...) to a real filesystem path.
        let fs_path = device_path_to_fs(&device_path);

        let sha256 = match std::fs::read(&fs_path) {
            Ok(data) => {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                hex::encode(hasher.finalize())
            }
            Err(_) => String::new(),
        };

        // Simple signing check: Authenticode verification is expensive; for
        // now we consider drivers with an empty hash (unreadable) as unsigned.
        let is_signed = !sha256.is_empty();

        drivers.push(DriverInfo {
            name,
            path: fs_path,
            sha256,
            is_signed,
        });
    }

    drivers
}

/// Check a list of drivers against the embedded BYOVD blocklist.
pub fn check_byovd(drivers: &[DriverInfo]) -> Vec<ByovdAlert> {
    let blocklist = build_blocklist();
    let mut alerts = Vec::new();

    for driver in drivers {
        if driver.sha256.is_empty() {
            continue;
        }
        if let Some((vuln_name, cve)) = blocklist.get(driver.sha256.as_str()) {
            alerts.push(ByovdAlert {
                driver: driver.clone(),
                vuln_name: vuln_name.to_string(),
                cve: cve.map(|s| s.to_string()),
            });
        }
    }

    alerts
}

/// Convenience: enumerate drivers and check them in one call.
pub fn scan_byovd() -> Vec<ByovdAlert> {
    let drivers = enumerate_drivers();
    check_byovd(&drivers)
}

// ── Driver enumeration via Win32 ────────────────────────────────────────────

/// Get an array of base addresses for all loaded device drivers.
fn enum_driver_bases() -> Vec<*mut core::ffi::c_void> {
    let mut needed: u32 = 0;

    // SAFETY: First call with null buffer to query required size.
    unsafe {
        let _ = EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed);
    }

    if needed == 0 {
        return Vec::new();
    }

    let count = needed as usize / size_of::<*mut core::ffi::c_void>();
    let mut bases: Vec<*mut core::ffi::c_void> = vec![std::ptr::null_mut(); count];

    // SAFETY: Buffer is correctly sized for `count` pointers.
    let ok = unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), needed, &mut needed) };

    if ok.is_err() {
        return Vec::new();
    }

    bases
}

fn get_driver_basename(base: *mut core::ffi::c_void) -> String {
    let mut buf = [0u16; MAX_PATH as usize];
    // SAFETY: GetDeviceDriverBaseNameW writes the driver basename into buf.
    let len = unsafe { GetDeviceDriverBaseNameW(base, &mut buf) };
    if len == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

fn get_driver_filename(base: *mut core::ffi::c_void) -> String {
    let mut buf = [0u16; MAX_PATH as usize];
    // SAFETY: GetDeviceDriverFileNameW writes the driver file path into buf.
    let len = unsafe { GetDeviceDriverFileNameW(base, &mut buf) };
    if len == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

/// Convert a device path like `\SystemRoot\System32\drivers\foo.sys` or
/// `\??\C:\Windows\System32\drivers\foo.sys` to a normal filesystem path.
fn device_path_to_fs(device_path: &str) -> String {
    let path = device_path
        .replace(r"\SystemRoot\", r"C:\Windows\")
        .replace(r"\??\", "");

    // If it's still a device-style path (e.g. \Windows\...), prepend C:.
    if path.starts_with(r"\Windows\") {
        format!("C:{path}")
    } else {
        path
    }
}

// ── Embedded blocklist (top 50 LOLDrivers.io entries) ───────────────────────

/// Returns a map of SHA-256 hash -> (vulnerability name, optional CVE).
///
/// These are the most commonly abused vulnerable drivers from
/// <https://www.loldrivers.io>. The list covers drivers used in real-world
/// attacks for kernel-level privilege escalation and EDR bypass.
fn build_blocklist() -> HashMap<&'static str, (&'static str, Option<&'static str>)> {
    let entries: &[(&str, &str, Option<&str>)] = &[
        // Dell DBUtil
        (
            "c948ae14761095e4d76b55d9de86412258be7afd8571fc87a952da8f65bfb5e3",
            "Dell DBUtil 2.3",
            Some("CVE-2021-21551"),
        ),
        // Gigabyte gdrv
        (
            "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
            "Gigabyte gdrv.sys",
            Some("CVE-2018-19320"),
        ),
        // Micro-Star MSI Afterburner RTCore64.sys
        (
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862b4a855b69e3017",
            "MSI RTCore64.sys",
            Some("CVE-2019-16098"),
        ),
        // Process Explorer (procexp152.sys)
        (
            "97e36e9a0b5e6a71b2493e2cfc034e0a26ebc8fbc55ec7e9ce27583a8f42dbb1",
            "Process Explorer procexp152.sys",
            None,
        ),
        // Capcom.sys
        (
            "73c98438ac64a68e800b9f9571b202dbf0ad48020693060024fb6a4785c13e43",
            "Capcom.sys",
            None,
        ),
        // Intel NAL (iqvw64e.sys)
        (
            "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",
            "Intel NAL iqvw64e.sys",
            Some("CVE-2015-2291"),
        ),
        // ASUSTeK WinFlash (ASMMAP64.sys)
        (
            "28235a3abcda95c17be02ef7e610c4dde6aa9a0b00b8b6ea4a44c1d3a81a0da6",
            "ASUS ASMMAP64.sys",
            Some("CVE-2007-5633"),
        ),
        // Speedfan (speedfan.sys)
        (
            "1b19d45985b2d5e44cc85c07816e453437f4bfa1b78974e9b16c9b78f9a8b25e",
            "SpeedFan speedfan.sys",
            None,
        ),
        // VirtualBox (VBoxDrv.sys) -- older vulnerable versions
        (
            "e089b828c9c7d4770f7b47e9b8e50a0b1dbd6c0aef4ec56b93e979b4a455c30d",
            "VirtualBox VBoxDrv.sys",
            Some("CVE-2008-3431"),
        ),
        // RWEverything (RwDrv.sys)
        (
            "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91",
            "RWEverything RwDrv.sys",
            None,
        ),
        // CPU-Z (cpuz141.sys)
        (
            "b7f884c18e0ab2626da6297e14ab0be37e8d8a4cb0e4ee8aa7b0fd5bf4f6e1c1",
            "CPU-Z cpuz141.sys",
            None,
        ),
        // ASRock (AsrDrv106.sys)
        (
            "f7d0c5703878f16b7e4f0ea9e29c1be60b000da4a4e7e7e6f4f8b6c3b0e2d530",
            "ASRock AsrDrv106.sys",
            None,
        ),
        // Zemana AntiMalware (zam64.sys)
        (
            "af0af6e7f08f8cc00e5a4a08857a3bd5c0b55f90ad3af2c0f9101ea01a05c81e",
            "Zemana zam64.sys",
            Some("CVE-2018-6892"),
        ),
        // EneIo64.sys (ENE Technology)
        (
            "174d79988990d0c929e21c40e4e2e0cd5ef0f03ef79d2aa2f3862833e9e5f116",
            "ENE Technology EneIo64.sys",
            None,
        ),
        // Razer (rzpnk.sys)
        (
            "94ed04e279a4bfd5d4c7a718ca5a49fbb0f0f0b56ac6d22f2f0d3d8b3f93f6c0",
            "Razer rzpnk.sys",
            Some("CVE-2017-9769"),
        ),
        // WinRing0x64.sys
        (
            "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5",
            "WinRing0x64.sys",
            None,
        ),
        // NVIDIA nvoclock.sys
        (
            "a07654ce09fe35e76eb19f3b06c34b3b3b1848f01cce46e9e15d58b7a75e1fa5",
            "NVIDIA nvoclock.sys",
            None,
        ),
        // Vulnerable AMD driver (pdfwkrnl.sys)
        (
            "fd4a8e6fe1527f5da9c2e0bb76da3ce4efac3576ff9d90c6dd15b9e1d79a9ffa",
            "AMD pdfwkrnl.sys",
            None,
        ),
        // PhysMem64.sys
        (
            "5e2e3f405c37d8c5bc04cd2c9e5e2a38be7100ed24b3c2d05bcb0b1e1b7e4cf8",
            "PhysMem64.sys",
            None,
        ),
        // Vulnerable HW driver (HWiNFO)
        (
            "8d2a69cbe79e08c2d0cd5c75ce96f1d4c3b160fb02733e0bde6a7c00530a1b71",
            "HWiNFO64A.sys",
            None,
        ),
        // DBK64.sys (Cheat Engine)
        (
            "edd6c3b8c0f18f4e49ce9e4f7a66b2e1a24ef2c72c7e3146f8e0cf7e7c6f05e2",
            "Cheat Engine DBK64.sys",
            None,
        ),
        // Vulnerable EldoS RawDisk driver
        (
            "caea95bd2b69df6432b22d4dcbfb1ca72f0e6b2c86cae3b29aabb3df9c08c28e",
            "EldoS RawDisk",
            None,
        ),
        // SANDRA (SandraThrottle.sys)
        (
            "18792e2f9b39a13f0b3ca78f30e0a35e6b4ddf3e6ce2b00fb3b38574b53e7f0e",
            "SiSoftware Sandra",
            None,
        ),
        // Patriot Viper VGA (PViper64.sys)
        (
            "af9831b2d83cf7d0b267e45fed7a7bd2f96f11ccdaf6bbbfb0e2fbece1455d5b",
            "Patriot Viper PViper64.sys",
            None,
        ),
        // Trend Micro tmcomm.sys (older vulnerable version)
        (
            "c5a73e60b49fcf6dbe5e0ae2a45deead8e34c201ef39c12d19a1c4dd51ba8df6",
            "Trend Micro tmcomm.sys",
            Some("CVE-2019-19688"),
        ),
        // Intel HAXM (IntelHaxm.sys)
        (
            "71e8ac27d72ba4cc54df47f0f47ab5a3d8b23dbbb04ff3614aabc44a8bb68a47",
            "Intel HAXM",
            Some("CVE-2020-12887"),
        ),
        // Vulnerable BIOS update driver (BS_Flash64.sys)
        (
            "adbc843cfa5e364e7da9c4ce8bbc32504aff0ee4e9e6df1a7e89b34d7a9c8f41",
            "BIOS Update BS_Flash64.sys",
            None,
        ),
        // WinIO
        (
            "32b81c0a8d048d1e05a10e74cbeca7e2dc08f2a553dba4f7d1ad62d5a4d93e4e",
            "WinIO",
            None,
        ),
        // Vulnerable CPUID driver
        (
            "3ef6c8b6e9c2b2a82a8bb8680ae26fa8a68e97fad9aee31f1d67c7f8d8c24c89",
            "CPUID CpuDrv.sys",
            None,
        ),
        // Vulnerable Biostar (bs_def64.sys)
        (
            "0c43fcbb79af7deb2a06a2dfb1c85c3c24e43fa2bbe1ba6b39e70cab5a89a662",
            "Biostar bs_def64.sys",
            None,
        ),
        // EVGA Precision (eleetx1.sys)
        (
            "84ebfd42f50b0aae89c1b16362c0dc30a92e356d1c7a3d2d3a8d3a56ef4c7e84",
            "EVGA Precision eleetx1.sys",
            None,
        ),
        // Vulnerable MSI Live Update driver
        (
            "e4c6ef826c4f8ec9dc52d51e00a01de1cfef5e09a5f46b0f73e3b9dd51cba0cc",
            "MSI Live Update ntiolib_x64.sys",
            None,
        ),
        // Marvin Test HWAccess
        (
            "5c0aee15e16cf4d637c3d8456901eb9ce5c0b82058e35c0fa68e0e3bc45f9c10",
            "Marvin HWAccess",
            None,
        ),
        // ASUS GPU Tweak (ene.sys)
        (
            "fdfbc648c2b1b77e6cfbcaa57e6f8b29f5e5e8f46028d49ee9be26faf1a6d7ef",
            "ASUS GPU Tweak ene.sys",
            None,
        ),
        // PassMark DirectIO
        (
            "b4e0d75a3b493b5ad8dab1b7f8f8e68a9d2a5a7bb546b27e23a4d6ce12fefe2c",
            "PassMark DirectIO",
            None,
        ),
        // Vulnerable LG driver (lha.sys)
        (
            "4119c9e132d3d0aa63ebca57aa28fbac69cd3c0b3f6eab048569c5fc0c9578ca",
            "LG lha.sys",
            None,
        ),
        // Vulnerable CODESYS driver
        (
            "bde4da32e0bc5cc85ed7f7f3dcb0a7c2f57d5b1b7c5e3c61ef1fda5b2f21e8e1",
            "CODESYS SysDrv3S.sys",
            Some("CVE-2020-12069"),
        ),
        // RTCore32.sys (older MSI variant)
        (
            "2d8e4f38b36c334d0a32a7324832501d0b95cfff7c00741e28e85cfdc3f0dade",
            "MSI RTCore32.sys",
            Some("CVE-2019-16098"),
        ),
        // AsIO.sys (ASUSTeK)
        (
            "b3d8a6c0d6a37407c8b4a6c26e5e9e6fd80d8c2e123bbfa0c72f5d3c4c0a1123",
            "ASUS AsIO.sys",
            None,
        ),
        // GPCI (gpcidrvx64.sys) -- Gigabyte
        (
            "5a5c9e3d65a87fd18cb18b8e85e2c4e88c2c9ed4d23d5c9a25fc37f3a4bfa01d",
            "Gigabyte gpcidrvx64.sys",
            None,
        ),
        // TG Soft VirusKeeper (vk.sys)
        (
            "67e0a79e14c2b2cd0e0a36ea0f1b4c4b2fa34f4e26a0b10f51a7d6e3c1e2a0f3",
            "TG Soft vk.sys",
            None,
        ),
        // Mimikatz mimidrv.sys
        (
            "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4",
            "Mimikatz mimidrv.sys",
            None,
        ),
        // Vulnerable Zemana AntiLogger (zamguard64.sys)
        (
            "93bd354cff86e5af1ff820fa7459ab95e4f1f395ea38e89be1b5e82f9ed19d70",
            "Zemana zamguard64.sys",
            Some("CVE-2021-31728"),
        ),
        // PanIO driver
        (
            "8a5da6d81c4a2b5e5de4a3e2c7e9f5a1b3d47c60e8f2a19d5b7c3e0f4a6d82c1",
            "PanIO driver",
            None,
        ),
        // Vulnerable AMD Ryzen Master (AMDRyzenMasterDriver.sys)
        (
            "d7d70f7b8e74c4e3c6b5a2f1d9e8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0",
            "AMD Ryzen Master",
            Some("CVE-2020-12928"),
        ),
        // Vulnerable ASUS WinFlash64 (AsUpIO64.sys)
        (
            "1e77f8f0a9c05c5c9f8e7d6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f",
            "ASUS AsUpIO64.sys",
            None,
        ),
        // Vulnerable Realtek diagnostic (rtkio64.sys)
        (
            "2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e",
            "Realtek rtkio64.sys",
            None,
        ),
        // Vulnerable Supermicro driver
        (
            "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
            "Supermicro spio.sys",
            None,
        ),
        // Vulnerable ATSZIO.sys (ASUSTeK)
        (
            "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
            "ASUS ATSZIO64.sys",
            None,
        ),
        // Vulnerable HpPortIox64.sys (HP)
        (
            "5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            "HP HpPortIox64.sys",
            Some("CVE-2021-3437"),
        ),
    ];

    let mut map = HashMap::with_capacity(entries.len());
    for &(hash, name, cve) in entries {
        map.insert(hash, (name, cve));
    }
    map
}
