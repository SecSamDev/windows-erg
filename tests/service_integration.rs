#![cfg(windows)]

use windows_erg::service::{self, ServiceManager};

#[test]
fn list_services_returns_buffer_count() -> windows_erg::Result<()> {
    let manager = ServiceManager::connect()?;
    let mut out_services = Vec::with_capacity(128);
    let count = manager.list_with_buffer(&mut out_services)?;

    assert_eq!(count, out_services.len());
    assert!(count > 0);

    Ok(())
}

#[test]
fn query_first_listed_service() -> windows_erg::Result<()> {
    let listed = service::list()?;
    assert!(!listed.is_empty());

    let first = &listed[0];
    let status = service::query(&first.name)?;

    assert_eq!(status.name, first.name);
    Ok(())
}
