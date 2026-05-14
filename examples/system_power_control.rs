use windows_erg::system::{
    PowerActionOptions, restart, restart_with_enabled_privilege, shutdown,
    shutdown_with_enabled_privilege,
};

fn print_usage() {
    println!("Usage:");
    println!("  cargo run --example system_power_control -- <shutdown|restart> [--force] [--planned] [--timeout <secs>] [--comment <text>] [--preenabled] --execute");
    println!();
    println!("Safety:");
    println!("  This example performs NO power action unless --execute is supplied.");
    println!("  Run in an elevated terminal when testing on a real system.");
    println!("  Use --preenabled to call the variant that expects SeShutdownPrivilege already enabled.");
}

fn parse_options(args: &[String]) -> Result<(bool, bool, PowerActionOptions, bool), String> {
    if args.is_empty() {
        return Err("missing action (shutdown|restart)".to_string());
    }

    let is_restart = match args[0].as_str() {
        "shutdown" => false,
        "restart" => true,
        _ => return Err("first argument must be 'shutdown' or 'restart'".to_string()),
    };

    let mut options = PowerActionOptions::default();
    let mut execute = false;
    let mut preenabled = false;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--force" => {
                options.force_apps_closed = true;
                i += 1;
            }
            "--planned" => {
                options.planned = true;
                i += 1;
            }
            "--execute" => {
                execute = true;
                i += 1;
            }
            "--preenabled" => {
                preenabled = true;
                i += 1;
            }
            "--timeout" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--timeout requires a numeric value".to_string())?;
                options.timeout_secs = value
                    .parse::<u32>()
                    .map_err(|_| "--timeout must be a valid u32".to_string())?;
                i += 2;
            }
            "--comment" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--comment requires text".to_string())?;
                options.comment = Some(value.clone());
                i += 2;
            }
            unknown => {
                return Err(format!("unknown argument: {unknown}"));
            }
        }
    }

    Ok((is_restart, execute, options, preenabled))
}

fn main() -> windows_erg::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (is_restart, execute, options, preenabled) = match parse_options(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            print_usage();
            return Ok(());
        }
    };

    println!("action: {}", if is_restart { "restart" } else { "shutdown" });
    println!("force: {}", options.force_apps_closed);
    println!("planned: {}", options.planned);
    println!("timeout_secs: {}", options.timeout_secs);
    println!("comment: {}", options.comment.as_deref().unwrap_or("<none>"));
    println!(
        "permission model: {}",
        if preenabled {
            "caller-preenabled privilege"
        } else {
            "auto-enable SeShutdownPrivilege"
        }
    );

    if !execute {
        println!("Dry run only. Append --execute to perform the power action.");
        return Ok(());
    }

    if preenabled {
        if is_restart {
            restart_with_enabled_privilege(&options)?;
        } else {
            shutdown_with_enabled_privilege(&options)?;
        }
    } else if is_restart {
        restart(&options)?;
    } else {
        shutdown(&options)?;
    }

    println!("Power action requested successfully.");
    println!("If the machine does not transition, verify elevation and privilege policy.");

    Ok(())
}
