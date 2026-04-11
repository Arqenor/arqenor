//! Advanced Linux persistence detectors: C4–C7
//!
//! C4 — SSH authorized_keys   (ATT&CK T1098.004)
//! C5 — PAM modules           (ATT&CK T1556.003)
//! C6 — Shell profiles        (ATT&CK T1546.004)
//! C7 — Git hooks             (ATT&CK T1059)

use arqenor_core::models::persistence::{PersistenceEntry, PersistenceKind};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `/etc/passwd` and return `(username, home_dir, shell)` tuples.
fn parse_passwd() -> Vec<(String, String, String)> {
    let content = match fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|line| {
            let fields: Vec<&str> = line.splitn(7, ':').collect();
            if fields.len() < 7 {
                return None;
            }
            Some((
                fields[0].to_owned(),
                fields[5].to_owned(),
                fields[6].to_owned(),
            ))
        })
        .collect()
}

/// Compute SHA-256 of a file's contents, returning a hex string.
/// Falls back to `"sha256:unreadable"` on any I/O error.
fn sha256_file(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            format!("sha256:{}", hex::encode(digest))
        }
        Err(_) => "sha256:unreadable".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// C4 — SSH authorized_keys  (T1098.004)
// ---------------------------------------------------------------------------

/// Detect persistence via SSH `authorized_keys` files (ATT&CK T1098.004).
///
/// Enumerates every user with a valid home directory and login shell, then
/// records each public-key entry found in their `~/.ssh/authorized_keys`.
pub fn detect_ssh_authorized_keys() -> Vec<PersistenceEntry> {
    // Shells that indicate the account cannot log in interactively.
    const NO_LOGIN_SHELLS: &[&str] = &[
        "/usr/sbin/nologin",
        "/bin/false",
        "/bin/nologin",
        "/sbin/nologin",
    ];

    let mut entries = Vec::new();

    for (username, home_dir, shell) in parse_passwd() {
        if home_dir.is_empty() || home_dir == "/" {
            continue;
        }
        if NO_LOGIN_SHELLS.contains(&shell.as_str()) {
            continue;
        }

        let ak_path = PathBuf::from(&home_dir)
            .join(".ssh")
            .join("authorized_keys");
        if !ak_path.exists() {
            continue;
        }

        let content = match fs::read_to_string(&ak_path) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => continue,
        };

        let location = ak_path.to_string_lossy().into_owned();

        for line in content.lines() {
            let trimmed = line.trim();
            // Skip blank lines and comment lines.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // A key line has the form:
            //   [options] keytype base64key [comment]
            // Skip option tokens (they don't contain spaces in a single token
            // sense but may appear as quoted strings). A reliable heuristic:
            // find the token that starts with "ssh-" or "ecdsa-" or "sk-".
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            let key_type_idx = tokens.iter().position(|t| {
                t.starts_with("ssh-")
                    || t.starts_with("ecdsa-")
                    || t.starts_with("sk-")
                    || *t == "pgp-sign-rsa"
            });

            let (base64_key, comment) = match key_type_idx {
                Some(i) => {
                    let b64 = tokens.get(i + 1).copied().unwrap_or("");
                    let comment = tokens.get(i + 2).copied().unwrap_or("");
                    (b64, comment)
                }
                // Unrecognised format — still record it.
                None => (tokens.first().copied().unwrap_or(trimmed), ""),
            };

            // First 40 chars of the base64 blob as a fingerprint-like field.
            let fingerprint: String = base64_key.chars().take(40).collect();

            let name = if comment.is_empty() {
                username.clone()
            } else {
                format!("{}: {}", username, comment)
            };

            entries.push(PersistenceEntry {
                kind: PersistenceKind::SshAuthorizedKey,
                name,
                command: fingerprint,
                location: location.clone(),
                is_new: false,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// C5 — PAM modules  (T1556.003)
// ---------------------------------------------------------------------------

/// Standard locations for PAM security modules.
const PAM_STANDARD_DIRS: &[&str] = &[
    "/lib/security",
    "/lib/x86_64-linux-gnu/security",
    "/lib64/security",
    "/usr/lib/security",
    "/usr/lib/x86_64-linux-gnu/security",
];

/// Detect persistence via rogue or out-of-place PAM modules (ATT&CK T1556.003).
///
/// Reads every file in `/etc/pam.d/`, extracts referenced `.so` module paths,
/// hashes the binary on disk, and flags modules that live outside the standard
/// security library directories.
pub fn detect_pam_modules() -> Vec<PersistenceEntry> {
    let pam_dir = Path::new("/etc/pam.d");
    if !pam_dir.exists() {
        return Vec::new();
    }

    let rd = match fs::read_dir(pam_dir) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();

    for dir_entry in rd.filter_map(|e| e.ok()) {
        let config_path = dir_entry.path();
        if config_path.is_dir() {
            continue;
        }

        let content = match fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let location = config_path.to_string_lossy().into_owned();

        for line in content.lines() {
            let trimmed = line.trim();
            // Skip blank lines and comments.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // PAM line format: <type> <control> <module-path> [args…]
            // The module-path token ends with `.so` (optionally with version).
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() < 3 {
                continue;
            }

            let module_token = tokens[2];
            if !module_token.contains(".so") {
                continue;
            }

            // Resolve absolute path: bare names are relative to standard dirs.
            let module_path: PathBuf = if module_token.starts_with('/') {
                PathBuf::from(module_token)
            } else {
                // Find in standard dirs; fall back to first standard dir.
                PAM_STANDARD_DIRS
                    .iter()
                    .map(|d| PathBuf::from(d).join(module_token))
                    .find(|p| p.exists())
                    .unwrap_or_else(|| PathBuf::from(PAM_STANDARD_DIRS[0]).join(module_token))
            };

            let module_name = module_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| module_token.to_owned());

            let in_standard_dir = PAM_STANDARD_DIRS.iter().any(|std_dir| {
                module_path
                    .to_str()
                    .map(|p| p.starts_with(std_dir))
                    .unwrap_or(false)
            });

            if in_standard_dir && !module_token.starts_with('/') {
                // Module is in a standard location referenced by bare name — skip.
                continue;
            }

            // Build the `command` field.
            let command = if !in_standard_dir && module_token.starts_with('/') {
                format!("path: {}", module_token)
            } else {
                sha256_file(&module_path)
            };

            entries.push(PersistenceEntry {
                kind: PersistenceKind::PamModule,
                name: module_name,
                command,
                location: location.clone(),
                is_new: false,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// C6 — Shell profiles  (T1546.004)
// ---------------------------------------------------------------------------

/// Per-user profile file names to check in the home directory.
const USER_PROFILE_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
];

/// System-wide profile files to check unconditionally.
const SYSTEM_PROFILE_FILES: &[&str] = &["/etc/profile", "/etc/bash.bashrc", "/etc/environment"];

/// Suspicious patterns that may indicate malicious injection in a shell profile.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    " nc ",
    "ncat ",
    "python ",
    "python3 ",
    "perl ",
    "ruby ",
    " exec ",
    "base64 ",
    "base64 -d",
    "LD_PRELOAD=",
];

/// Return the first suspicious line in `content`, if any.
fn first_suspicious_line(content: &str) -> Option<&str> {
    content.lines().find(|line| {
        let l = line.trim();
        if l.starts_with('#') {
            return false;
        }
        // Check for LD_PRELOAD or PATH pointing outside standard dirs.
        if l.starts_with("PATH=") {
            let rhs = &l["PATH=".len()..];
            let outside_std = !rhs.contains("/usr/") && !rhs.contains("/bin");
            if outside_std {
                return true;
            }
        }
        SUSPICIOUS_PATTERNS.iter().any(|pat| l.contains(pat))
    })
}

/// Detect persistence via malicious shell profile modification (ATT&CK T1546.004).
///
/// Scans per-user profile files (`~/.bashrc`, `.zshrc`, …) and system-wide
/// profiles, records a SHA-256 hash of each file, and annotates entries where
/// suspicious commands (downloaders, reverse shells, `LD_PRELOAD` overrides)
/// are detected.
pub fn detect_shell_profiles() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Per-user profile files.
    for (username, home_dir, _shell) in parse_passwd() {
        if home_dir.is_empty() || home_dir == "/" {
            continue;
        }

        for filename in USER_PROFILE_FILES {
            let path = PathBuf::from(&home_dir).join(filename);
            if !path.exists() {
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(c) if !c.trim().is_empty() => c,
                _ => continue,
            };

            let hash = sha256_file(&path);
            let command = match first_suspicious_line(&content) {
                Some(sus) => {
                    let truncated: String = sus.chars().take(120).collect();
                    format!("{} suspicious: {}", hash, truncated)
                }
                None => hash,
            };

            entries.push(PersistenceEntry {
                kind: PersistenceKind::ShellProfile,
                name: format!("profile: {}/{}", username, filename),
                command,
                location: path.to_string_lossy().into_owned(),
                is_new: false,
            });
        }
    }

    // System-wide profile files.
    for &sys_path in SYSTEM_PROFILE_FILES {
        let path = Path::new(sys_path);
        if !path.exists() {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => continue,
        };

        let hash = sha256_file(path);
        let command = match first_suspicious_line(&content) {
            Some(sus) => {
                let truncated: String = sus.chars().take(120).collect();
                format!("{} suspicious: {}", hash, truncated)
            }
            None => hash,
        };

        entries.push(PersistenceEntry {
            kind: PersistenceKind::ShellProfile,
            name: format!("system: {}", sys_path),
            command,
            location: sys_path.to_owned(),
            is_new: false,
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// C7 — Git hooks  (T1059)
// ---------------------------------------------------------------------------

/// Git hook filenames that are actively executed by git.
const GIT_HOOK_NAMES: &[&str] = &[
    "pre-commit",
    "post-commit",
    "pre-push",
    "post-merge",
    "pre-receive",
    "post-receive",
    "update",
    "pre-rebase",
];

/// Root directories to search for git repositories.
const GIT_SEARCH_ROOTS: &[&str] = &["/home", "/var/www", "/opt", "/srv", "/root"];

/// Suspicious content patterns in hook scripts.
const HOOK_SUSPICIOUS_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    " nc ",
    "ncat ",
    "python -c",
    "python3 -c",
    "eval ",
    "base64 ",
    "base64 -d",
    "|bash",
    "| bash",
    "|sh",
    "| sh",
];

/// Walk `dir` up to `max_depth` levels, collecting `.git` directory paths.
fn find_git_dirs(dir: &Path, max_depth: usize, results: &mut Vec<PathBuf>) {
    if max_depth == 0 {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git" {
            results.push(path);
            // Don't recurse into .git itself.
        } else if !name_str.starts_with('.') {
            // Recurse into non-hidden subdirectories.
            find_git_dirs(&path, max_depth - 1, results);
        }
    }
}

/// Return the first suspicious line found within the first `line_limit` lines.
fn first_suspicious_hook_line<'a>(content: &'a str, line_limit: usize) -> Option<&'a str> {
    content.lines().take(line_limit).find(|line| {
        let l = line.trim();
        HOOK_SUSPICIOUS_PATTERNS.iter().any(|pat| l.contains(pat))
    })
}

/// Detect persistence via executable git hooks (ATT&CK T1059).
///
/// Walks common repository root directories up to 4 levels deep, identifies
/// `.git/hooks/` directories, and flags any hook file that is executable,
/// non-empty, and not a `.sample` file. The first five lines are inspected
/// for known suspicious command patterns.
pub fn detect_git_hooks() -> Vec<PersistenceEntry> {
    let mut git_dirs: Vec<PathBuf> = Vec::new();

    for root in GIT_SEARCH_ROOTS {
        let root_path = Path::new(root);
        if root_path.exists() {
            find_git_dirs(root_path, 4, &mut git_dirs);
        }
    }

    let mut entries = Vec::new();

    for git_dir in git_dirs {
        let hooks_dir = git_dir.join("hooks");
        if !hooks_dir.is_dir() {
            continue;
        }

        // The repo root is the parent of `.git`.
        let repo_root = git_dir
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| git_dir.to_string_lossy().into_owned());

        for hook_name in GIT_HOOK_NAMES {
            let hook_path = hooks_dir.join(hook_name);
            if !hook_path.exists() {
                continue;
            }

            // Skip `.sample` files.
            if hook_path
                .extension()
                .map(|e| e == "sample")
                .unwrap_or(false)
            {
                continue;
            }

            // Check executable bit and non-empty.
            let meta = match fs::metadata(&hook_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if meta.len() == 0 {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }

            // On non-Unix targets the executable check is skipped;
            // the file is still recorded if non-empty.

            let content = fs::read_to_string(&hook_path).unwrap_or_default();
            let command = first_suspicious_hook_line(&content, 5)
                .map(|l| l.trim().to_owned())
                .unwrap_or_else(|| "executable hook".to_owned());

            entries.push(PersistenceEntry {
                kind: PersistenceKind::GitHook,
                name: format!("{} @ {}", hook_name, repo_root),
                command,
                location: hook_path.to_string_lossy().into_owned(),
                is_new: false,
            });
        }
    }

    entries
}
