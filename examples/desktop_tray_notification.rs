use std::time::Duration;

use windows_erg::desktop::{BalloonIcon, TrayIcon, TrayIconId, TrayNotification};

fn main() -> windows_erg::Result<()> {
    let mut tray = TrayIcon::new(TrayIconId::new(1), "windows-erg demo")?;

    tray.show_notification(&TrayNotification::new(
        "windows-erg",
        "Tray notification from windows-erg",
        BalloonIcon::Info,
    ))?;

    std::thread::sleep(Duration::from_secs(5));

    tray.remove()?;
    Ok(())
}
