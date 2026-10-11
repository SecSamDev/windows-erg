//! A window with two tabs over a 200-row virtual list view, a status bar and
//! a tray icon whose menu can show the window or quit.

use std::cell::{Cell, RefCell};

use windows_erg::desktop::{
    self, ControlNotify, GuiFont, ListView, PopupMenu, StatusBar, TabControl, TrayEvent, TrayIcon,
    TrayIconId, WindowBuilder, WindowClass, WindowHandle, WindowHandler, WindowRect, msg,
};

const WM_TRAY: u32 = msg::WM_APP + 1;
const ID_TABS: u16 = 1;
const ID_LIST: u16 = 2;
const ID_STATUS: u16 = 3;
const CMD_OPEN: u32 = 1;
const CMD_EXIT: u32 = 2;

#[derive(Default)]
struct Demo {
    tabs: Cell<Option<TabControl>>,
    list: Cell<Option<ListView>>,
    status: Cell<Option<StatusBar>>,
    tray: RefCell<Option<TrayIcon>>,
    font: RefCell<Option<GuiFont>>,
}

impl Demo {
    fn create_children(&self, window: WindowHandle) -> windows_erg::Result<()> {
        let font = GuiFont::message_font(desktop::dpi_for_window(window))?;
        let tabs = TabControl::create(window, ID_TABS)?;
        tabs.add_tab("Rows")?;
        tabs.add_tab("Empty")?;
        let mut list = ListView::create(window, ID_LIST)?;
        list.add_column("#", 60)?;
        list.add_column("Square", 120)?;
        list.set_item_count(200);
        let status = StatusBar::create(window, ID_STATUS)?;
        status.set_text("200 rows");
        for handle in [tabs.handle(), list.handle(), status.handle()] {
            font.apply(handle);
        }
        let tray = TrayIcon::builder(TrayIconId::new(1), "windows-erg list demo")
            .owner_window(window)
            .callback_message(WM_TRAY)
            .create()?;
        self.tabs.set(Some(tabs));
        self.list.set(Some(list));
        self.status.set(Some(status));
        *self.tray.borrow_mut() = Some(tray);
        *self.font.borrow_mut() = Some(font);
        Ok(())
    }

    fn layout(&self, window: WindowHandle) {
        let (Some(tabs), Some(list), Some(status)) =
            (self.tabs.get(), self.list.get(), self.status.get())
        else {
            return;
        };
        let Ok(client) = window.client_rect() else {
            return;
        };
        status.parent_resized();
        let strip = WindowRect {
            bottom: client.bottom - status.height(),
            ..client
        };
        let _ = tabs.handle().set_bounds(strip);
        let _ = list.handle().set_bounds(tabs.display_rect(strip));
        if tabs.selected() == Some(0) {
            list.handle().show();
        } else {
            list.handle().hide();
        }
    }

    fn tray_menu(&self, window: WindowHandle) {
        let Ok(menu) = PopupMenu::new() else {
            return;
        };
        let _ = menu.append(CMD_OPEN, "Open");
        let _ = menu.separator();
        let _ = menu.append(CMD_EXIT, "Exit");
        let _ = menu.set_default(CMD_OPEN);
        match menu.track_at_cursor(window) {
            Some(CMD_OPEN) => {
                window.show();
                window.set_foreground();
            }
            Some(CMD_EXIT) => {
                let _ = window.destroy();
            }
            _ => {}
        }
    }
}

impl WindowHandler for Demo {
    fn handle(
        &self,
        window: WindowHandle,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> Option<isize> {
        match msg {
            msg::WM_CREATE => {
                if let Err(e) = self.create_children(window) {
                    eprintln!("create failed: {e}");
                    return Some(-1);
                }
                Some(0)
            }
            msg::WM_SIZE => {
                self.layout(window);
                Some(0)
            }
            msg::WM_NOTIFY => {
                // SAFETY: lparam belongs to the WM_NOTIFY being handled.
                match unsafe { desktop::decode_notify(lparam) } {
                    Some(ControlNotify::ListViewGetText(mut cell)) => {
                        let n = cell.row as u64;
                        let text = match cell.column {
                            0 => n.to_string(),
                            _ => (n * n).to_string(),
                        };
                        cell.set_text(&text);
                        Some(0)
                    }
                    Some(ControlNotify::TabChanged { .. }) => {
                        self.layout(window);
                        Some(0)
                    }
                    _ => None,
                }
            }
            WM_TRAY => {
                match TrayEvent::decode(wparam, lparam) {
                    TrayEvent::Select => {
                        window.show();
                        window.set_foreground();
                    }
                    TrayEvent::ContextMenu { .. } => self.tray_menu(window),
                    _ => {}
                }
                Some(0)
            }
            msg::WM_CLOSE => {
                // Close hides to the tray; Exit in the tray menu quits.
                window.hide();
                Some(0)
            }
            msg::WM_DESTROY => {
                self.tray.borrow_mut().take();
                desktop::post_quit(0);
                Some(0)
            }
            _ => None,
        }
    }
}

fn main() -> windows_erg::Result<()> {
    desktop::set_process_dpi_aware_per_monitor_v2();
    desktop::init_common_controls()?;
    let class = WindowClass::builder("windows_erg_listview_demo").register()?;
    let window = WindowBuilder::new(&class)
        .title("windows-erg list view")
        .size(520, 420)
        .create(Box::new(Demo::default()))?;
    window.handle().show();
    std::process::exit(desktop::run_message_loop(Some(window.handle())));
}
