use windows_erg::proxy;

fn main() -> Result<(), windows_erg::Error> {
    let url = "https://example.com";

    match proxy::get_proxy_for_url(url)? {
        Some(resolution) => {
            println!("URL: {}", resolution.url);
            println!("Proxy raw: {:?}", resolution.proxy);
            println!("By scheme: {:?}", resolution.by_scheme);
            println!("Bypass: {:?}", resolution.bypass);
            println!("Used auto-detect: {}", resolution.used_auto_detect);
            println!("Used PAC URL: {}", resolution.used_auto_config_url);
        }
        None => {
            println!("No proxy needed for {}", url);
        }
    }

    Ok(())
}
