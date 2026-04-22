//! Basic service operations example.
//!
//! Demonstrates query, restart, start, and stop operations.
//! Run elevated if your target service requires administrative permissions.

use std::time::Duration;
use windows_erg::service::{self, ServiceState};

fn main() -> windows_erg::Result<()> {
    let service_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Spooler".to_string());

    println!("Using service: {}", service_name);

    let status = service::query(&service_name)?;
    println!(
        "Initial state: {:?}, pid: {}, wait_hint_ms: {}",
        status.state, status.process_id, status.wait_hint_ms
    );

    println!("Attempting restart with 20s timeout...");
    match service::restart(&service_name, Duration::from_secs(20)) {
        Ok(()) => println!("Restart succeeded"),
        Err(err) => println!("Restart failed: {}", err),
    }

    let after_restart = service::query(&service_name)?;
    println!("State after restart attempt: {:?}", after_restart.state);

    if after_restart.state == ServiceState::Stopped {
        println!("Service is stopped, trying start...");
        let _ = service::start(&service_name);
    } else {
        println!("Service is not stopped, trying stop...");
        let _ = service::stop(&service_name);
    }

    let final_status = service::query(&service_name)?;
    println!("Final state: {:?}", final_status.state);

    Ok(())
}
