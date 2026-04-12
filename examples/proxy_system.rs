use windows_erg::proxy;

fn main() -> Result<(), windows_erg::Error> {
    match proxy::get_effective_proxy()? {
        Some(config) => {
            println!("Proxy server raw: {}", config.server);
            println!("Bypass: {:?}", config.bypass);
            println!("By scheme: {:?}", config.by_scheme);
            println!("Auto detect: {}", config.auto_detect);
            println!("Auto config URL: {:?}", config.auto_config_url);
        }
        None => {
            println!("No proxy configuration detected.");
        }
    }

    Ok(())
}
