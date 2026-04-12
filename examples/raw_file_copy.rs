use std::path::PathBuf;

use windows_erg::file;

fn main() -> windows_erg::Result<()> {
    if !windows_erg::is_elevated()? {
        println!("This example requires Administrator privileges for raw file operations.");
        println!(
            "Run an elevated terminal and execute: cargo run --example raw_file_copy_executable"
        );
        return Ok(());
    }

    let source = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
    let destination = std::env::temp_dir().join("hosts.raw.executable.copy");

    file::raw_copy(&source, &destination)?;

    println!("Raw copy completed.");
    println!("Source:      {}", source.display());
    println!("Destination: {}", destination.display());

    Ok(())
}
