use std::net::IpAddr;

pub fn validate_domain(domain: &str) -> Result<(), &'static str> {
    if domain.is_empty() || domain.len() > 253 {
        return Err("invalid domain name");
    }
    if !domain.contains('.') {
        return Err("invalid domain name");
    }
    if let Ok(addr) = domain.parse::<IpAddr>() {
        return if is_restricted_ip(addr) {
            Err("private or reserved addresses not allowed")
        } else {
            Ok(())
        };
    }
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid domain name");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("invalid domain name");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("invalid domain name");
        }
    }
    Ok(())
}

fn is_restricted_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}
