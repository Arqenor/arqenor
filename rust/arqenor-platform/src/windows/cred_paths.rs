//! Credential-store path matcher.
//!
//! Used by the ETW Kernel-File classifier to flag opens against files that
//! store secrets — browser login DBs, KeePass vaults, SSH private keys, AWS /
//! GCP / Azure CLI credentials.
//!
//! The matcher is intentionally OS-shape agnostic: ETW reports paths in
//! NT-device form (`\Device\HarddiskVolume3\Users\alice\…`) while user-space
//! tooling sees DOS form (`C:\Users\alice\…`). Every pattern is anchored on
//! the lowercased *suffix* or *substring* — both forms match.
//!
//! A match by itself is **not** evidence of theft: legitimate browsers and
//! managers open these files routinely. The downstream pipeline is
//! responsible for de-noising via process-name allowlists.

use arqenor_core::models::alert::Severity;

/// Family of credential store the path belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredStoreKind {
    ChromeBrowser,
    EdgeBrowser,
    FirefoxBrowser,
    KeePassDb,
    SshPrivateKey,
    AwsCredentials,
    GcpCredentials,
    AzureCredentials,
}

impl CredStoreKind {
    /// Human-readable label embedded in alert metadata.
    pub fn label(self) -> &'static str {
        match self {
            CredStoreKind::ChromeBrowser => "Chrome",
            CredStoreKind::EdgeBrowser => "Edge",
            CredStoreKind::FirefoxBrowser => "Firefox",
            CredStoreKind::KeePassDb => "KeePass",
            CredStoreKind::SshPrivateKey => "SSH",
            CredStoreKind::AwsCredentials => "AWS-CLI",
            CredStoreKind::GcpCredentials => "GCP-CLI",
            CredStoreKind::AzureCredentials => "Azure-CLI",
        }
    }

    /// MITRE ATT&CK technique mapping.
    pub fn attack_id(self) -> &'static str {
        match self {
            CredStoreKind::ChromeBrowser
            | CredStoreKind::EdgeBrowser
            | CredStoreKind::FirefoxBrowser => "T1555.003",
            _ => "T1552.001",
        }
    }

    /// Severity prior on a raw match (no process-name allowlist applied yet).
    ///
    /// Browsers legitimately read their own DBs all day, so we keep these at
    /// `Medium` to give downstream filters a useful gate. Files that almost
    /// nothing legitimate opens (SSH keys, AWS creds, KeePass DBs) are `High`.
    pub fn severity(self) -> Severity {
        match self {
            CredStoreKind::ChromeBrowser
            | CredStoreKind::EdgeBrowser
            | CredStoreKind::FirefoxBrowser => Severity::Medium,
            _ => Severity::High,
        }
    }
}

/// Classify a file path against the known credential-store patterns.
///
/// Returns `None` if the path doesn't look like any credential store we track.
pub fn match_credential_path(path: &str) -> Option<CredStoreKind> {
    let lower = path.to_lowercase();

    if lower.contains(r"\google\chrome\user data\")
        && (ends_with_segment(&lower, "login data")
            || ends_with_segment(&lower, "cookies")
            || ends_with_segment(&lower, "web data"))
    {
        return Some(CredStoreKind::ChromeBrowser);
    }
    if lower.contains(r"\microsoft\edge\user data\")
        && (ends_with_segment(&lower, "login data")
            || ends_with_segment(&lower, "cookies")
            || ends_with_segment(&lower, "web data"))
    {
        return Some(CredStoreKind::EdgeBrowser);
    }
    // Firefox: logins.json holds the password DB; key4.db holds the master key.
    if lower.ends_with(r"\logins.json") || lower.ends_with(r"\key4.db") {
        return Some(CredStoreKind::FirefoxBrowser);
    }
    if lower.ends_with(".kdbx") || lower.ends_with(".kdb") {
        return Some(CredStoreKind::KeePassDb);
    }
    let ssh_keys = [
        r"\.ssh\id_rsa",
        r"\.ssh\id_dsa",
        r"\.ssh\id_ecdsa",
        r"\.ssh\id_ed25519",
    ];
    if ssh_keys.iter().any(|k| lower.ends_with(k)) {
        return Some(CredStoreKind::SshPrivateKey);
    }
    if lower.ends_with(r"\.aws\credentials") {
        return Some(CredStoreKind::AwsCredentials);
    }
    if lower.ends_with(r"\application_default_credentials.json")
        || lower.contains(r"\gcloud\credentials.db")
    {
        return Some(CredStoreKind::GcpCredentials);
    }
    if lower.ends_with(r"\.azure\accesstokens.json")
        || lower.ends_with(r"\.azure\azureprofile.json")
    {
        return Some(CredStoreKind::AzureCredentials);
    }

    None
}

/// Suffix-match restricted to whole `\\`-delimited segments — `login data`
/// must be the basename, not part of a longer file name like `xlogin data`.
fn ends_with_segment(lower: &str, segment: &str) -> bool {
    if !lower.ends_with(segment) {
        return false;
    }
    let prefix_end = lower.len() - segment.len();
    if prefix_end == 0 {
        return true;
    }
    lower.as_bytes()[prefix_end - 1] == b'\\'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_login_data_matches() {
        let p = r"\Device\HarddiskVolume3\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        assert_eq!(match_credential_path(p), Some(CredStoreKind::ChromeBrowser));
    }

    #[test]
    fn chrome_dos_form_matches() {
        let p = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        assert_eq!(match_credential_path(p), Some(CredStoreKind::ChromeBrowser));
    }

    #[test]
    fn edge_cookies_matches() {
        let p = r"C:\Users\bob\AppData\Local\Microsoft\Edge\User Data\Profile 1\Cookies";
        assert_eq!(match_credential_path(p), Some(CredStoreKind::EdgeBrowser));
    }

    #[test]
    fn firefox_logins_json_matches() {
        let p = r"C:\Users\carol\AppData\Roaming\Mozilla\Firefox\Profiles\xyz.default-release\logins.json";
        assert_eq!(
            match_credential_path(p),
            Some(CredStoreKind::FirefoxBrowser),
        );
    }

    #[test]
    fn keepass_kdbx_matches() {
        assert_eq!(
            match_credential_path(r"C:\Users\dave\Documents\Vault.kdbx"),
            Some(CredStoreKind::KeePassDb),
        );
    }

    #[test]
    fn ssh_private_key_matches_but_pub_does_not() {
        let p = r"C:\Users\eve\.ssh\id_ed25519";
        assert_eq!(match_credential_path(p), Some(CredStoreKind::SshPrivateKey));
        // The public key carries no secret.
        assert_eq!(match_credential_path(&format!("{p}.pub")), None);
    }

    #[test]
    fn aws_credentials_matches() {
        let p = r"C:\Users\frank\.aws\credentials";
        assert_eq!(
            match_credential_path(p),
            Some(CredStoreKind::AwsCredentials),
        );
    }

    #[test]
    fn gcp_application_default_matches() {
        let p = r"C:\Users\grace\AppData\Roaming\gcloud\application_default_credentials.json";
        assert_eq!(
            match_credential_path(p),
            Some(CredStoreKind::GcpCredentials),
        );
    }

    #[test]
    fn azure_access_tokens_matches() {
        let p = r"C:\Users\heidi\.azure\accessTokens.json";
        assert_eq!(
            match_credential_path(p),
            Some(CredStoreKind::AzureCredentials),
        );
    }

    /// A file whose basename ends with `login data` but whose path is NOT
    /// rooted under Chrome's User Data dir must not match Chrome.
    #[test]
    fn unrelated_login_data_does_not_match_chrome() {
        let p = r"C:\Users\ivan\Documents\Login Data";
        assert_eq!(match_credential_path(p), None);
    }

    /// `xlogin data` must not match `login data` — segment boundary required.
    #[test]
    fn segment_boundary_is_enforced() {
        let p = r"C:\Users\jane\AppData\Local\Google\Chrome\User Data\Default\xLogin Data";
        assert_eq!(match_credential_path(p), None);
    }

    /// Random unrelated file paths return `None`.
    #[test]
    fn unrelated_paths_do_not_match() {
        assert_eq!(
            match_credential_path(r"C:\Windows\System32\ntdll.dll"),
            None
        );
        assert_eq!(match_credential_path(r"D:\dev\target\debug\app.exe"), None);
        assert_eq!(match_credential_path(""), None);
    }

    #[test]
    fn attack_id_routing() {
        assert_eq!(CredStoreKind::ChromeBrowser.attack_id(), "T1555.003");
        assert_eq!(CredStoreKind::FirefoxBrowser.attack_id(), "T1555.003");
        assert_eq!(CredStoreKind::SshPrivateKey.attack_id(), "T1552.001");
        assert_eq!(CredStoreKind::KeePassDb.attack_id(), "T1552.001");
    }
}
