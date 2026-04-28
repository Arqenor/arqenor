/// Map a TCP/UDP port number to the well-known service label registered with
/// IANA (or the de-facto label used by the modern infrastructure stack).
///
/// The list is intentionally curated rather than complete — we keep entries
/// that are actually useful for an EDR scan report (admin services, common
/// app servers, databases, observability stack). Returns `None` for ports
/// without a recognised mapping; the caller should fall back to an empty
/// service string in that case.
pub fn well_known_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 => Some("dhcp"),
        68 => Some("dhcp"),
        80 => Some("http"),
        88 => Some("kerberos"),
        110 => Some("pop3"),
        123 => Some("ntp"),
        135 => Some("dcerpc"),
        143 => Some("imap"),
        161 => Some("snmp"),
        162 => Some("snmp-trap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        587 => Some("submission"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        2375 => Some("docker"),
        2376 => Some("docker-tls"),
        3000 => Some("grafana"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5000 => Some("flask"),
        5432 => Some("postgresql"),
        5601 => Some("kibana"),
        5900 => Some("vnc"),
        5984 => Some("couchdb"),
        6379 => Some("redis"),
        6443 => Some("kubernetes-api"),
        8000 => Some("django"),
        8080 => Some("http-alt"),
        8081 => Some("http-alt"),
        8082 => Some("http-alt"),
        8083 => Some("http-alt"),
        8084 => Some("http-alt"),
        8085 => Some("http-alt"),
        8086 => Some("http-alt"),
        8087 => Some("http-alt"),
        8088 => Some("http-alt"),
        8089 => Some("http-alt"),
        8090 => Some("http-alt"),
        8443 => Some("https-alt"),
        8888 => Some("jupyter"),
        9000 => Some("portainer"),
        9001 => Some("cassandra"),
        9200 => Some("elasticsearch"),
        9300 => Some("elastic-cluster"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        50051 => Some("grpc"),
        _ => None,
    }
}

/// Extract a best-effort version / product token from the raw banner read
/// during a TCP probe. The heuristic is deliberately tiny: it only handles
/// the three formats we routinely see (SSH, HTTP `Server:`, FTP `220 …`).
/// On no match it returns an empty string — callers should treat the field
/// as missing rather than as a parse error.
pub fn extract_version_from_banner(banner: &str) -> String {
    if let Some(rest) = banner.strip_prefix("SSH-2.0-") {
        let line = rest.split(['\r', '\n']).next().unwrap_or("");
        return line.trim().to_string();
    }

    for line in banner.split("\r\n").chain(banner.split('\n')) {
        if let Some(value) = line
            .strip_prefix("Server:")
            .or_else(|| line.strip_prefix("server:"))
        {
            return value.trim().to_string();
        }
    }

    if let Some(rest) = banner.strip_prefix("220 ") {
        let line = rest.split(['\r', '\n']).next().unwrap_or("");
        return line.trim().to_string();
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_service_known_ports() {
        assert_eq!(well_known_service(22), Some("ssh"));
        assert_eq!(well_known_service(80), Some("http"));
        assert_eq!(well_known_service(443), Some("https"));
        assert_eq!(well_known_service(3389), Some("rdp"));
        assert_eq!(well_known_service(5432), Some("postgresql"));
        assert_eq!(well_known_service(27017), Some("mongodb"));
    }

    #[test]
    fn well_known_service_unknown_returns_none() {
        assert_eq!(well_known_service(0), None);
        assert_eq!(well_known_service(7777), None);
        assert_eq!(well_known_service(65535), None);
    }

    #[test]
    fn extract_version_from_ssh_banner() {
        assert_eq!(
            extract_version_from_banner("SSH-2.0-OpenSSH_8.4\r\n"),
            "OpenSSH_8.4"
        );
    }

    #[test]
    fn extract_version_from_http_banner() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_version_from_banner(banner), "nginx/1.18.0");
    }

    #[test]
    fn extract_version_from_ftp_banner() {
        assert_eq!(
            extract_version_from_banner("220 ProFTPD 1.3.7 Server ready.\r\n"),
            "ProFTPD 1.3.7 Server ready."
        );
    }

    #[test]
    fn extract_version_from_unknown_banner_returns_empty() {
        assert_eq!(extract_version_from_banner(""), "");
        assert_eq!(extract_version_from_banner("garbled\x00\x7f data"), "");
        assert_eq!(extract_version_from_banner("HELLO"), "");
    }
}
