//! Window, handler and message-loop round trips on a message-only window.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_erg::desktop::{
    WindowBuilder, WindowClass, WindowHandle, WindowHandler, msg, post_quit, run_message_loop,
};

const WM_PING: u32 = msg::WM_APP + 1;

struct Recorder {
    seen: Rc<Cell<Option<(usize, isize)>>>,
    dropped: Arc<AtomicBool>,
}

impl WindowHandler for Recorder {
    fn handle(&self, _: WindowHandle, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
        if msg == WM_PING {
            self.seen.set(Some((wparam, lparam)));
            post_quit(7);
            return Some(0);
        }
        None
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn a_message_posted_from_another_thread_reaches_the_handler() {
    let class = WindowClass::builder("windows_erg_test_ping")
        .register()
        .expect("register");
    let seen = Rc::new(Cell::new(None));
    let dropped = Arc::new(AtomicBool::new(false));
    let window = WindowBuilder::new(&class)
        .message_only()
        .create(Box::new(Recorder {
            seen: Rc::clone(&seen),
            dropped: Arc::clone(&dropped),
        }))
        .expect("create");

    let poster = window.handle().poster();
    std::thread::spawn(move || poster.post(WM_PING, 42, -3).expect("post"))
        .join()
        .expect("join");

    assert_eq!(run_message_loop(None), 7);
    assert_eq!(seen.get(), Some((42, -3)));

    assert!(!dropped.load(Ordering::SeqCst));
    drop(window);
    assert!(
        dropped.load(Ordering::SeqCst),
        "the handler is freed with the window"
    );
}

#[test]
fn posting_to_a_destroyed_window_fails() {
    let class = WindowClass::builder("windows_erg_test_gone")
        .register()
        .expect("register");
    let window = WindowBuilder::new(&class)
        .message_only()
        .create(Box::new(Recorder {
            seen: Rc::new(Cell::new(None)),
            dropped: Arc::new(AtomicBool::new(false)),
        }))
        .expect("create");
    let poster = window.handle().poster();
    drop(window);
    assert!(poster.post(WM_PING, 0, 0).is_err());
}

struct Painter {
    drawn: Rc<Cell<bool>>,
    canvas: std::cell::RefCell<Option<windows_erg::desktop::Canvas>>,
}

impl WindowHandler for Painter {
    fn handle(&self, window: WindowHandle, msg: u32, _: usize, _: isize) -> Option<isize> {
        if msg == WM_PING {
            let mut slot = self.canvas.borrow_mut();
            let canvas =
                slot.get_or_insert_with(|| windows_erg::desktop::Canvas::for_window(window));
            let style = windows_erg::desktop::TextStyle::new(
                &["Segoe UI"],
                14.0,
                windows_erg::desktop::Weight::SemiBold,
            )
            .expect("style");
            let result = canvas.draw(|frame| {
                use windows_erg::desktop::{Align, Color, RectF};
                frame.clear(Color::hex(0xF3F3F3));
                let card = RectF::new(8.0, 8.0, 200.0, 60.0);
                frame.fill_rounded(card, 8.0, Color::hex(0xFFFFFF));
                frame.stroke_rounded(card, 8.0, 1.0, Color::hex(0xE5E5E5));
                frame.fill_circle(30.0, 38.0, 6.0, Color::hex(0xC42B1C));
                frame.text(
                    "Protected",
                    &style,
                    card.inset(44.0, 0.0),
                    Color::hex(0x1A1A1A),
                    Align::Leading,
                );
            });
            result.expect("draw");
            self.drawn.set(true);
            post_quit(0);
            return Some(0);
        }
        None
    }
}

#[test]
fn a_canvas_draws_on_a_hidden_window() {
    let class = WindowClass::builder("windows_erg_test_canvas")
        .register()
        .expect("register");
    let drawn = Rc::new(Cell::new(false));
    let window = WindowBuilder::new(&class)
        .size(240, 120)
        .create(Box::new(Painter {
            drawn: Rc::clone(&drawn),
            canvas: std::cell::RefCell::new(None),
        }))
        .expect("create");
    window.handle().poster().post(WM_PING, 0, 0).expect("post");
    run_message_loop(None);
    assert!(drawn.get());
}
