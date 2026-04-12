use windows_erg::mitigation::{MitigationPlan, ProcessMitigation, query_current};

fn main() -> windows_erg::Result<()> {
    let before = query_current()?;
    println!(
        "Before: dynamic_code={}, payload={}, child_block={}",
        before.disable_dynamic_code, before.restrict_payload, before.block_child_process_creation
    );

    MitigationPlan::new()
        .enable(ProcessMitigation::DisableDynamicCode)
        .enable(ProcessMitigation::BlockChildProcessCreation)
        .apply_to_current()?;

    let after = query_current()?;
    println!(
        "After: dynamic_code={}, payload={}, child_block={}",
        after.disable_dynamic_code, after.restrict_payload, after.block_child_process_creation
    );

    Ok(())
}
