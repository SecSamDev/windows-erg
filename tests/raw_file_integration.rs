#![cfg(windows)]

use std::fs;
use std::io::Write;

use tempfile::NamedTempFile;

use windows_erg::file;

#[test]
#[ignore = "requires elevated privileges and raw disk access"]
fn raw_copy_round_trip_matches_source_content() -> windows_erg::Result<()> {
    if !windows_erg::is_elevated()? {
        return Ok(());
    }

    let mut source = NamedTempFile::new().map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to create source temp file: {}",
            e
        )))
    })?;

    // Write enough data to span multiple reads in typical configurations.
    let payload = vec![0xABu8; 96 * 1024];
    source.write_all(&payload).map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to write source payload: {}",
            e
        )))
    })?;
    source.flush().map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to flush source payload: {}",
            e
        )))
    })?;

    let destination = NamedTempFile::new().map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to create destination temp file: {}",
            e
        )))
    })?;
    let destination_path = destination.path().to_path_buf();
    drop(destination);

    file::raw_copy(source.path(), &destination_path)?;

    let source_bytes = fs::read(source.path()).map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to read source file: {}",
            e
        )))
    })?;
    let destination_bytes = fs::read(&destination_path).map_err(|e| {
        windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
            "failed to read destination file: {}",
            e
        )))
    })?;

    assert_eq!(destination_bytes, source_bytes);
    Ok(())
}
