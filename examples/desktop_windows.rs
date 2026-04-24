use windows_erg::desktop;

fn main() -> windows_erg::Result<()> {
    let mut windows = Vec::with_capacity(512);
    let count = desktop::enumerate_windows_with_buffer(&mut windows)?;

    println!("enumerated {} windows", count);

    for window in windows.iter().take(20) {
        println!(
            "hwnd={} pid={} visible={} cloaked={} class='{}' title='{}' rect=({}, {}, {}, {})",
            window.handle,
            window.process_id,
            window.is_visible,
            window.cloak_state.is_cloaked(),
            window.class_name,
            window.title,
            window.rect.left,
            window.rect.top,
            window.rect.right,
            window.rect.bottom
        );
    }

    Ok(())
}
