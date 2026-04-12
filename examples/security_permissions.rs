use windows_erg::security::{AccessMask, ApplyMode, PermissionEditor, PermissionTarget, Sid};
use windows_erg::{Error, error::OtherError};

fn main() -> windows_erg::Result<()> {
    let path = std::env::temp_dir().join("windows_erg_permissions_example.txt");
    std::fs::write(&path, b"example").map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to create temp file for security example: {}",
            e
        )))
    })?;

    let target = PermissionTarget::file(path.to_string_lossy().to_string());

    // Dry-run a planned grant before any apply.
    let users = Sid::parse("S-1-5-32-545")?; // BUILTIN\Users
    let plan = PermissionEditor::new()
        .grant(users, AccessMask::from_bits(0x120089))
        .build()?;

    let diff = plan.execute_against_target(&target, ApplyMode::DryRunDiff)?;
    println!(
        "Dry run changes: +{} -{}",
        diff.diff.added.len(),
        diff.diff.removed.len()
    );

    // Validate-only execution from current target state.
    let _ = plan.execute_against_target(&target, ApplyMode::ValidateOnly)?;

    std::fs::remove_file(path).map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to clean up temp file for security example: {}",
            e
        )))
    })?;
    Ok(())
}
