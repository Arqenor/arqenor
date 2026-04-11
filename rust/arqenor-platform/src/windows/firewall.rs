// Windows Firewall rule query via COM / INetFwPolicy2.
//
// Checks whether an active inbound Block rule covers a given port.
// Gated behind the `firewall-check` feature flag.

use arqenor_core::error::ArqenorError;
use std::collections::HashSet;
use windows::core::{Interface, BSTR};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_IN,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;

/// Result of querying the Windows Firewall for a specific port.
#[derive(Debug, Clone)]
pub struct FirewallPortStatus {
    pub port: u16,
    /// True when at least one *enabled* inbound Block rule covers this port.
    pub blocked: bool,
    /// Name of the first matching block rule (for diagnostics / TUI display).
    pub rule_name: Option<String>,
}

/// Query the Windows Firewall for all ports in `ports` and return the block
/// status of each.
///
/// Handles its own `CoInitializeEx` / `CoUninitialize` pair, so it's safe
/// to call from a Tokio `spawn_blocking` context.
pub fn query_firewall_block_status(ports: &[u16]) -> Result<Vec<FirewallPortStatus>, ArqenorError> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }

    unsafe {
        let com_init = CoInitializeEx(None, COINIT_MULTITHREADED);
        let needs_uninit = com_init.is_ok();

        let result = query_inner(ports);

        if needs_uninit {
            CoUninitialize();
        }

        result
    }
}

unsafe fn query_inner(ports: &[u16]) -> Result<Vec<FirewallPortStatus>, ArqenorError> {
    let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
        .map_err(|e| {
            ArqenorError::Platform(format!("CoCreateInstance(NetFwPolicy2) failed: {e}"))
        })?;

    let rules: INetFwRules = policy
        .Rules()
        .map_err(|e| ArqenorError::Platform(format!("INetFwPolicy2::Rules() failed: {e}")))?;

    let port_set: HashSet<u16> = ports.iter().copied().collect();

    // Pre-fill results as "not blocked".
    let mut results: Vec<FirewallPortStatus> = ports
        .iter()
        .map(|&p| FirewallPortStatus {
            port: p,
            blocked: false,
            rule_name: None,
        })
        .collect();

    // Get the IUnknown enumerator and cast to IEnumVARIANT.
    let enumerator = rules
        ._NewEnum()
        .map_err(|e| ArqenorError::Platform(format!("INetFwRules::_NewEnum() failed: {e}")))?;

    let enum_var: IEnumVARIANT = enumerator
        .cast()
        .map_err(|e| ArqenorError::Platform(format!("cast to IEnumVARIANT failed: {e}")))?;

    let mut fetched: u32 = 0;
    loop {
        let mut variant = [VARIANT::default()];
        let hr = enum_var.Next(&mut variant, &mut fetched as *mut u32);

        if hr.is_err() || fetched == 0 {
            break;
        }

        // Extract IDispatch from the VARIANT, then cast to INetFwRule.
        // pdispVal is ManuallyDrop<Option<IDispatch>>.
        let dispatch: IDispatch = {
            let opt = &*variant[0].Anonymous.Anonymous.Anonymous.pdispVal;
            match opt {
                Some(d) => d.clone(),
                None => continue,
            }
        };
        let rule: INetFwRule = match dispatch.cast() {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Fast-reject: must be enabled, inbound, block.
        let enabled = rule.Enabled().unwrap_or_default();
        if !enabled.as_bool() {
            continue;
        }
        let direction = rule.Direction().unwrap_or_default();
        if direction != NET_FW_RULE_DIR_IN {
            continue;
        }
        let action = rule.Action().unwrap_or_default();
        if action != NET_FW_ACTION_BLOCK {
            continue;
        }

        // Parse the "LocalPorts" string — can be "445", "135,139,445",
        // "100-200", or "*" (all ports).
        let local_ports_bstr: BSTR = match rule.LocalPorts() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let local_ports_str = local_ports_bstr.to_string();

        let covered = ports_covered_by_spec(&local_ports_str, &port_set);
        if covered.is_empty() {
            continue;
        }

        let rule_name = rule.Name().ok().map(|b| b.to_string());

        for &port in &covered {
            if let Some(entry) = results.iter_mut().find(|r| r.port == port && !r.blocked) {
                entry.blocked = true;
                entry.rule_name = rule_name.clone();
            }
        }
    }

    Ok(results)
}

/// Parse a Windows Firewall "LocalPorts" spec and return which ports from
/// `interest` it covers.  Spec examples: "445", "135,139,445", "100-200", "*".
fn ports_covered_by_spec(spec: &str, interest: &HashSet<u16>) -> Vec<u16> {
    let trimmed = spec.trim();
    if trimmed == "*" {
        return interest.iter().copied().collect();
    }

    let mut matched = Vec::new();
    for token in trimmed.split(',') {
        let token = token.trim();
        if let Some((lo, hi)) = token.split_once('-') {
            let lo: u16 = match lo.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let hi: u16 = match hi.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            for &p in interest {
                if p >= lo && p <= hi && !matched.contains(&p) {
                    matched.push(p);
                }
            }
        } else if let Ok(p) = token.parse::<u16>() {
            if interest.contains(&p) && !matched.contains(&p) {
                matched.push(p);
            }
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_single_port() {
        let interest: HashSet<u16> = [445, 139].into_iter().collect();
        assert_eq!(ports_covered_by_spec("445", &interest), vec![445]);
    }

    #[test]
    fn spec_csv() {
        let interest: HashSet<u16> = [445, 135, 80].into_iter().collect();
        let mut res = ports_covered_by_spec("135,445,8080", &interest);
        res.sort();
        assert_eq!(res, vec![135, 445]);
    }

    #[test]
    fn spec_range() {
        let interest: HashSet<u16> = [445, 139, 135].into_iter().collect();
        let mut res = ports_covered_by_spec("100-200", &interest);
        res.sort();
        assert_eq!(res, vec![135, 139]);
    }

    #[test]
    fn spec_wildcard() {
        let interest: HashSet<u16> = [445, 3389].into_iter().collect();
        let mut res = ports_covered_by_spec("*", &interest);
        res.sort();
        assert_eq!(res, vec![445, 3389]);
    }
}
