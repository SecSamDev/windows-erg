//! Service enumeration example.
//!
//! Demonstrates list, list_with_buffer, and list_with_filter APIs.

use windows_erg::service::{self, ServiceState};

fn main() -> windows_erg::Result<()> {
    println!("=== service::list() ===");
    let services = service::list()?;
    println!("Total services: {}", services.len());

    for svc in services.iter().take(10) {
        println!("{} [{:?}] pid={}", svc.name, svc.state, svc.process_id);
    }

    println!("\n=== service::list_with_buffer() ===");
    let mut out_services = Vec::with_capacity(512);
    let count = service::list_with_buffer(&mut out_services)?;
    println!("Buffered count: {}", count);

    println!("\n=== service::list_with_filter() running only ===");
    out_services.clear();
    let running_count =
        service::list_with_filter(&mut out_services, |svc| svc.state == ServiceState::Running)?;
    println!("Running services: {}", running_count);

    for svc in out_services.iter().take(10) {
        println!("running: {} pid={}", svc.name, svc.process_id);
    }

    Ok(())
}
