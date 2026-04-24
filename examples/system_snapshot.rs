use windows_erg::system;

fn main() {
    let snapshot = system::snapshot();

    println!("host: {}", snapshot.identity.hostname);
    println!(
        "os: {}.{}.{} ({})",
        snapshot.os.major_version,
        snapshot.os.minor_version,
        snapshot.os.build_number,
        snapshot
            .os
            .product_name
            .as_deref()
            .unwrap_or("unknown product")
    );

    if let Some(machine_guid) = snapshot.guids.machine_guid.as_ref() {
        println!("machine guid: {}", machine_guid.as_str());
    }

    if let Some(firmware_guid) = snapshot.guids.firmware_guid.as_deref() {
        println!("firmware guid: {}", firmware_guid);
    }

    println!("logical disks: {}", snapshot.logical_disks.len());
    println!("physical disks: {}", snapshot.physical_disks.len());
    println!("network adapters: {}", snapshot.networks.len());
    println!("users: {}", snapshot.users.len());

    if !snapshot.section_errors.is_empty() {
        println!("section errors:");
        for section_error in &snapshot.section_errors {
            println!("  {:?}: {}", section_error.section, section_error.message);
        }
    }
}
