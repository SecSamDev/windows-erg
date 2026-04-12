//! Windows proxy discovery and URL-specific proxy resolution.

mod types;

pub use types::{
    IeProxyConfig, ProxyConfig, ProxyResolution, parse_proxy_bypass, parse_proxy_server,
};

use crate::error::{
    InvalidParameterError, ProxyConfigError, ProxyError, ProxyResolutionError, RegistryError,
    WindowsApiError,
};
use crate::registry::{self, Hive};
use crate::{Error, Result};
use windows::Win32::Foundation::{GetLastError, GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_AUTO_DETECT_TYPE_DHCP,
    WINHTTP_AUTO_DETECT_TYPE_DNS_A, WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTOPROXY_CONFIG_URL,
    WINHTTP_AUTOPROXY_OPTIONS, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
    WinHttpCloseHandle, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

const INTERNET_SETTINGS_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
const POLICIES_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Read system-level proxy configuration from registry.
pub fn get_system_proxy() -> Result<Option<ProxyConfig>> {
    get_proxy_from_hive(Hive::LocalMachine)
}

/// Read user-level proxy configuration from registry.
pub fn get_user_proxy() -> Result<Option<ProxyConfig>> {
    get_proxy_from_hive(Hive::CurrentUser)
}

/// Read effective proxy configuration based on `ProxySettingsPerUser` policy.
pub fn get_effective_proxy() -> Result<Option<ProxyConfig>> {
    if use_user_proxy_settings()? {
        return get_user_proxy();
    }
    get_system_proxy()
}

/// Read IE/WinHTTP proxy discovery configuration for the current user.
pub fn get_ie_proxy_config() -> Result<IeProxyConfig> {
    unsafe {
        let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        WinHttpGetIEProxyConfigForCurrentUser(&mut config).map_err(|err| {
            Error::WindowsApi(WindowsApiError::with_context(
                err,
                "WinHttpGetIEProxyConfigForCurrentUser",
            ))
        })?;

        let auto_config_url = take_optional_pwstr(config.lpszAutoConfigUrl)?;
        let proxy = take_optional_pwstr(config.lpszProxy)?;
        let proxy_bypass = take_optional_pwstr(config.lpszProxyBypass)?;

        Ok(IeProxyConfig {
            auto_detect: config.fAutoDetect.as_bool(),
            auto_config_url,
            proxy,
            proxy_bypass,
        })
    }
}

/// Resolve proxy for a specific URL using WinHTTP auto-proxy behavior.
pub fn get_proxy_for_url(url: &str) -> Result<Option<ProxyResolution>> {
    if url.trim().is_empty() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "url",
            "url cannot be empty",
        )));
    }

    let ie_config = get_ie_proxy_config()?;

    unsafe {
        let session = WinHttpSession::new()?;
        let mut proxy_info = WINHTTP_PROXY_INFO::default();

        let mut options = WINHTTP_AUTOPROXY_OPTIONS::default();
        if ie_config.auto_detect {
            options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
            options.dwAutoDetectFlags =
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        }

        if let Some(auto_url) = &ie_config.auto_config_url {
            options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
            let auto_url_wide = HSTRING::from(auto_url);
            options.lpszAutoConfigUrl = PCWSTR(auto_url_wide.as_ptr());

            let url_wide = HSTRING::from(url);
            let result = WinHttpGetProxyForUrl(
                session.handle,
                PCWSTR(url_wide.as_ptr()),
                &mut options,
                &mut proxy_info,
            );

            if result.is_err() {
                return Ok(None);
            }
        } else if ie_config.auto_detect {
            let url_wide = HSTRING::from(url);
            let result = WinHttpGetProxyForUrl(
                session.handle,
                PCWSTR(url_wide.as_ptr()),
                &mut options,
                &mut proxy_info,
            );

            if result.is_err() {
                return Ok(None);
            }
        } else if let Some(proxy) = ie_config.proxy {
            return Ok(Some(ProxyResolution::from_winhttp(
                url,
                Some(proxy),
                ie_config.proxy_bypass,
                false,
                false,
            )));
        } else {
            return Ok(None);
        }

        let proxy = take_optional_pwstr(proxy_info.lpszProxy)?;
        let bypass = take_optional_pwstr(proxy_info.lpszProxyBypass)?;

        Ok(Some(ProxyResolution::from_winhttp(
            url,
            proxy,
            bypass,
            ie_config.auto_detect,
            ie_config.auto_config_url.is_some(),
        )))
    }
}

fn get_proxy_from_hive(hive: Hive) -> Result<Option<ProxyConfig>> {
    let proxy_enabled =
        read_u32_optional(hive, INTERNET_SETTINGS_PATH, "ProxyEnable")?.unwrap_or(0) == 1;

    let server = read_string_optional(hive, INTERNET_SETTINGS_PATH, "ProxyServer")?
        .filter(|value| !value.trim().is_empty());

    let bypass = read_string_optional(hive, INTERNET_SETTINGS_PATH, "ProxyOverride")?;
    let auto_detect =
        read_u32_optional(hive, INTERNET_SETTINGS_PATH, "AutoDetect")?.unwrap_or(0) == 1;
    let auto_config_url = read_string_optional(hive, INTERNET_SETTINGS_PATH, "AutoConfigURL")?;

    if !proxy_enabled && !auto_detect && auto_config_url.is_none() {
        return Ok(None);
    }

    if proxy_enabled {
        if let Some(server) = server {
            return Ok(Some(ProxyConfig::from_registry_values(
                server,
                bypass,
                auto_detect,
                auto_config_url,
            )));
        }

        return Err(Error::Proxy(ProxyError::InvalidConfig(
            ProxyConfigError::new("ProxyServer", "ProxyEnable is 1 but ProxyServer is missing"),
        )));
    }

    Ok(Some(ProxyConfig {
        server: String::new(),
        bypass: parse_proxy_bypass(bypass.as_deref()),
        by_scheme: Default::default(),
        auto_detect,
        auto_config_url,
    }))
}

fn use_user_proxy_settings() -> Result<bool> {
    Ok(
        read_u32_optional(Hive::CurrentUser, POLICIES_PATH, "ProxySettingsPerUser")?.unwrap_or(0)
            == 1,
    )
}

fn read_string_optional(hive: Hive, path: &str, value_name: &str) -> Result<Option<String>> {
    match registry::read_string(hive, path, value_name) {
        Ok(value) => Ok(Some(value)),
        Err(Error::Registry(RegistryError::KeyNotFound(_))) => Ok(None),
        Err(Error::Registry(RegistryError::ValueNotFound(_))) => Ok(None),
        Err(err) => Err(err),
    }
}

fn read_u32_optional(hive: Hive, path: &str, value_name: &str) -> Result<Option<u32>> {
    match registry::read_u32(hive, path, value_name) {
        Ok(value) => Ok(Some(value)),
        Err(Error::Registry(RegistryError::KeyNotFound(_))) => Ok(None),
        Err(Error::Registry(RegistryError::ValueNotFound(_))) => Ok(None),
        Err(err) => Err(err),
    }
}

fn take_optional_pwstr(pwstr: PWSTR) -> Result<Option<String>> {
    if pwstr.is_null() {
        return Ok(None);
    }

    let mut len = 0usize;
    unsafe {
        while *pwstr.0.add(len) != 0 {
            len += 1;
        }
    }

    let data = unsafe { std::slice::from_raw_parts(pwstr.0, len) };
    let value = String::from_utf16_lossy(data);

    unsafe {
        GlobalFree(HGLOBAL(pwstr.0 as _)).map_err(|err| {
            Error::WindowsApi(WindowsApiError::with_context(err, "GlobalFree(PWSTR)"))
        })?;
    }

    Ok(Some(value))
}

struct WinHttpSession {
    handle: *mut core::ffi::c_void,
}

impl WinHttpSession {
    fn new() -> Result<Self> {
        unsafe {
            let agent = HSTRING::from("windows-erg/proxy");
            let handle = WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            );

            if handle.is_null() {
                let code = GetLastError();
                return Err(Error::Proxy(ProxyError::ResolutionFailed(
                    ProxyResolutionError::new(
                        "WinHttpOpen",
                        format!("WinHttpOpen returned null (error: 0x{:08X})", code.0),
                    ),
                )));
            }

            Ok(WinHttpSession { handle })
        }
    }
}

impl Drop for WinHttpSession {
    fn drop(&mut self) {
        unsafe {
            let _ = WinHttpCloseHandle(self.handle);
        }
    }
}
