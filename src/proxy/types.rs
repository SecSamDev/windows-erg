//! Types for Windows proxy discovery and resolution.

use std::collections::HashMap;

/// Proxy settings discovered from Windows configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Raw proxy server string (for example: "http=proxy:8080;https=proxy:8443").
    pub server: String,
    /// Bypass entries parsed from `ProxyOverride`.
    pub bypass: Vec<String>,
    /// Proxy endpoints parsed by scheme (for example `http -> proxy:8080`).
    pub by_scheme: HashMap<String, String>,
    /// WPAD/auto-detect setting.
    pub auto_detect: bool,
    /// PAC script URL (`AutoConfigURL`) when configured.
    pub auto_config_url: Option<String>,
}

impl ProxyConfig {
    /// Build a proxy config from raw registry values.
    pub fn from_registry_values(
        server: String,
        bypass_raw: Option<String>,
        auto_detect: bool,
        auto_config_url: Option<String>,
    ) -> Self {
        ProxyConfig {
            by_scheme: parse_proxy_server(&server),
            bypass: parse_proxy_bypass(bypass_raw.as_deref()),
            server,
            auto_detect,
            auto_config_url,
        }
    }
}

/// Effective proxy result for a specific URL.
#[derive(Debug, Clone)]
pub struct ProxyResolution {
    /// URL that was resolved.
    pub url: String,
    /// Raw proxy string returned by WinHTTP.
    pub proxy: Option<String>,
    /// Parsed proxy endpoints by scheme.
    pub by_scheme: HashMap<String, String>,
    /// Bypass entries returned by WinHTTP.
    pub bypass: Vec<String>,
    /// Whether auto-detect (WPAD) was used for discovery.
    pub used_auto_detect: bool,
    /// Whether PAC URL was used for discovery.
    pub used_auto_config_url: bool,
}

impl ProxyResolution {
    /// Build a resolution from raw WinHTTP proxy output.
    pub fn from_winhttp(
        url: &str,
        proxy: Option<String>,
        bypass_raw: Option<String>,
        used_auto_detect: bool,
        used_auto_config_url: bool,
    ) -> Self {
        let by_scheme = proxy.as_deref().map(parse_proxy_server).unwrap_or_default();

        ProxyResolution {
            url: url.to_string(),
            proxy,
            by_scheme,
            bypass: parse_proxy_bypass(bypass_raw.as_deref()),
            used_auto_detect,
            used_auto_config_url,
        }
    }
}

/// IE proxy settings returned from WinHTTP/IE integration APIs.
#[derive(Debug, Clone)]
pub struct IeProxyConfig {
    /// WPAD auto-detect setting.
    pub auto_detect: bool,
    /// PAC script URL.
    pub auto_config_url: Option<String>,
    /// Raw static proxy server value.
    pub proxy: Option<String>,
    /// Raw bypass list value.
    pub proxy_bypass: Option<String>,
}

/// Parse `ProxyServer` style value into a scheme map.
///
/// Supported formats:
/// - `proxy.company.local:8080`
/// - `http=proxy:8080;https=proxy:8443`
pub fn parse_proxy_server(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return map;
    }

    let entries = trimmed
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty());

    for entry in entries {
        if let Some((scheme, endpoint)) = entry.split_once('=') {
            let scheme = scheme.trim().to_ascii_lowercase();
            let endpoint = endpoint.trim();
            if !scheme.is_empty() && !endpoint.is_empty() {
                map.insert(scheme, endpoint.to_string());
            }
        } else {
            map.insert("all".to_string(), entry.to_string());
        }
    }

    map
}

/// Parse `ProxyOverride` style bypass list.
pub fn parse_proxy_bypass(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_proxy_bypass, parse_proxy_server};

    #[test]
    fn parse_single_proxy_server() {
        let parsed = parse_proxy_server("proxy.local:8080");
        assert_eq!(parsed.get("all"), Some(&"proxy.local:8080".to_string()));
    }

    #[test]
    fn parse_scheme_proxy_server() {
        let parsed = parse_proxy_server("http=proxy:8080;https=secure:8443");
        assert_eq!(parsed.get("http"), Some(&"proxy:8080".to_string()));
        assert_eq!(parsed.get("https"), Some(&"secure:8443".to_string()));
    }

    #[test]
    fn parse_bypass_list() {
        let bypass = parse_proxy_bypass(Some("<local>;*.contoso.com;10.*"));
        assert_eq!(bypass.len(), 3);
        assert_eq!(bypass[0], "<local>");
    }
}
