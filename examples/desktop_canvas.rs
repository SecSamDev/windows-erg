//! Direct2D drawing in a window: a card, coloured pills and text, in the
//! system's light or dark theme. Click to switch themes.

use std::cell::{Cell, RefCell};

use windows_erg::desktop::{
    self, Align, Backdrop, Canvas, Color, PaintGuard, RectF, TextStyle, Weight, WindowBuilder,
    WindowClass, WindowHandle, WindowHandler, msg,
};

struct Demo {
    canvas: RefCell<Option<Canvas>>,
    dark: Cell<bool>,
    title: TextStyle,
    body: TextStyle,
}

impl Demo {
    fn apply_theme(&self, window: WindowHandle) {
        desktop::set_dark_title_bar(window, self.dark.get());
        desktop::set_backdrop(window, Backdrop::Mica);
        window.invalidate();
    }

    fn paint(&self, window: WindowHandle) {
        let _paint = PaintGuard::begin(window);
        let mut slot = self.canvas.borrow_mut();
        let canvas = slot.get_or_insert_with(|| Canvas::for_window(window));
        let dark = self.dark.get();
        let (background, card, stroke, text, secondary) = if dark {
            (0x202020, 0x2B2B2B, 0x1D1D1D, 0xFFFFFF, 0xC5C5C5)
        } else {
            (0xF3F3F3, 0xFFFFFF, 0xE5E5E5, 0x1A1A1A, 0x5D5D5D)
        };
        let (width, _) = canvas.size();
        let _ = canvas.draw(|frame| {
            frame.clear(Color::hex(background));
            let status = RectF::new(24.0, 24.0, width - 48.0, 88.0);
            frame.fill_rounded(status, 8.0, Color::hex(card));
            frame.stroke_rounded(status, 8.0, 1.0, Color::hex(stroke));
            frame.fill_circle(56.0, 68.0, 14.0, Color::hex(0x0F7B0F));
            frame.text(
                "You're protected",
                &self.title,
                RectF::new(84.0, 40.0, width - 120.0, 28.0),
                Color::hex(text),
                Align::Leading,
            );
            frame.text(
                "Agent 0.0.8 · up 2 h 14 m · click to switch theme",
                &self.body,
                RectF::new(84.0, 70.0, width - 120.0, 22.0),
                Color::hex(secondary),
                Align::Leading,
            );
            let pills = [
                ("Critical", 0xC42B1C),
                ("High", 0xF7630C),
                ("Medium", 0xFFB900),
                ("Info", 0x0078D4),
                ("Audit", 0x8A8A8A),
            ];
            for (i, (label, color)) in pills.iter().enumerate() {
                let pill = RectF::new(24.0 + i as f32 * 92.0, 136.0, 84.0, 24.0);
                frame.fill_rounded(pill, 12.0, Color::hex(*color));
                frame.text(label, &self.body, pill, Color::hex(0xFFFFFF), Align::Center);
            }
        });
    }
}

impl WindowHandler for Demo {
    fn handle(&self, window: WindowHandle, msg: u32, _: usize, _: isize) -> Option<isize> {
        match msg {
            msg::WM_CREATE => {
                self.apply_theme(window);
                Some(0)
            }
            msg::WM_ERASEBKGND => Some(1),
            msg::WM_PAINT => {
                self.paint(window);
                Some(0)
            }
            msg::WM_SIZE => {
                if let Some(canvas) = self.canvas.borrow_mut().as_mut() {
                    canvas.resize();
                }
                window.invalidate();
                Some(0)
            }
            msg::WM_LBUTTONDOWN => {
                self.dark.set(!self.dark.get());
                self.apply_theme(window);
                Some(0)
            }
            msg::WM_DESTROY => {
                desktop::post_quit(0);
                Some(0)
            }
            _ => None,
        }
    }
}

fn main() -> windows_erg::Result<()> {
    desktop::set_process_dpi_aware_per_monitor_v2();
    let class = WindowClass::builder("windows_erg_canvas_demo").register()?;
    let fonts = ["Segoe UI Variable Text", "Segoe UI"];
    let demo = Demo {
        canvas: RefCell::new(None),
        dark: Cell::new(desktop::system_prefers_dark()),
        title: TextStyle::new(
            &["Segoe UI Variable Display", "Segoe UI"],
            20.0,
            Weight::SemiBold,
        )?,
        body: TextStyle::new(&fonts, 13.0, Weight::Normal)?,
    };
    let window = WindowBuilder::new(&class)
        .title("windows-erg canvas")
        .size(560, 260)
        .create(Box::new(demo))?;
    window.handle().show();
    std::process::exit(desktop::run_message_loop(None));
}
