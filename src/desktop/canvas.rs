//! Direct2D drawing on a window, with DirectWrite text.
//!
//! Coordinates are device-independent pixels (DIPs, 1/96 inch): the render
//! target carries the window's DPI, so the same layout code is sharp at any
//! scale. Use [`Canvas::to_dip`] for mouse positions, which arrive in pixels.

use std::cell::RefCell;

use windows::Win32::Foundation::BOOL;
use windows::Win32::Foundation::{D2DERR_RECREATE_TARGET, HWND, RECT};
use windows::Win32::Graphics::Direct2D::Common::{
    D2D_POINT_2F, D2D_RECT_F, D2D_SIZE_U, D2D1_ALPHA_MODE_UNKNOWN, D2D1_COLOR_F, D2D1_PIXEL_FORMAT,
};
use windows::Win32::Graphics::Direct2D::{
    D2D1_ANTIALIAS_MODE_PER_PRIMITIVE, D2D1_DRAW_TEXT_OPTIONS_CLIP, D2D1_ELLIPSE,
    D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_HWND_RENDER_TARGET_PROPERTIES,
    D2D1_PRESENT_OPTIONS_NONE, D2D1_RENDER_TARGET_PROPERTIES, D2D1_ROUNDED_RECT, D2D1CreateFactory,
    ID2D1Factory, ID2D1HwndRenderTarget, ID2D1SolidColorBrush,
};
use windows::Win32::Graphics::DirectWrite::{
    DWRITE_FACTORY_TYPE_SHARED, DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL,
    DWRITE_FONT_WEIGHT, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_WEIGHT_NORMAL,
    DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_MEASURING_MODE_NATURAL, DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
    DWRITE_PARAGRAPH_ALIGNMENT_NEAR, DWRITE_TEXT_ALIGNMENT, DWRITE_TEXT_ALIGNMENT_CENTER,
    DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_TEXT_METRICS,
    DWRITE_TRIMMING, DWRITE_TRIMMING_GRANULARITY_CHARACTER, DWRITE_WORD_WRAPPING_NO_WRAP,
    DWRITE_WORD_WRAPPING_WRAP, DWriteCreateFactory, IDWriteFactory, IDWriteInlineObject,
    IDWriteTextFormat,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_UNKNOWN;
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;
use windows::core::PCWSTR;

use crate::Result;
use crate::utils::to_utf16_nul;

use super::dpi::{DEFAULT_DPI, dpi_for_window};
use super::types::WindowHandle;
use super::window::op_error;

/// An sRGB colour with alpha, each channel 0..=1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Color {
    /// Red.
    pub r: f32,
    /// Green.
    pub g: f32,
    /// Blue.
    pub b: f32,
    /// Alpha (1 is opaque).
    pub a: f32,
}

impl Color {
    /// An opaque colour from `0xRRGGBB`.
    pub const fn hex(rgb: u32) -> Self {
        Self {
            r: ((rgb >> 16) & 0xFF) as f32 / 255.0,
            g: ((rgb >> 8) & 0xFF) as f32 / 255.0,
            b: (rgb & 0xFF) as f32 / 255.0,
            a: 1.0,
        }
    }

    /// The same colour with alpha `a`.
    pub const fn alpha(self, a: f32) -> Self {
        Self { a, ..self }
    }

    /// As a GDI `COLORREF` (`0x00BBGGRR`), alpha dropped.
    pub fn to_colorref(self) -> u32 {
        let channel = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u32;
        channel(self.r) | (channel(self.g) << 8) | (channel(self.b) << 16)
    }

    fn d2d(self) -> D2D1_COLOR_F {
        D2D1_COLOR_F {
            r: self.r,
            g: self.g,
            b: self.b,
            a: self.a,
        }
    }
}

/// A rectangle in DIPs.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RectF {
    /// Left edge.
    pub left: f32,
    /// Top edge.
    pub top: f32,
    /// Right edge.
    pub right: f32,
    /// Bottom edge.
    pub bottom: f32,
}

impl RectF {
    /// A rectangle from its origin and size.
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            left: x,
            top: y,
            right: x + width,
            bottom: y + height,
        }
    }

    /// Width.
    pub fn width(self) -> f32 {
        self.right - self.left
    }

    /// Height.
    pub fn height(self) -> f32 {
        self.bottom - self.top
    }

    /// Shrunk by `dx` on the left and right and `dy` on the top and bottom.
    pub fn inset(self, dx: f32, dy: f32) -> Self {
        Self {
            left: self.left + dx,
            top: self.top + dy,
            right: self.right - dx,
            bottom: self.bottom - dy,
        }
    }

    /// Whether the point lies inside.
    pub fn contains(self, x: f32, y: f32) -> bool {
        x >= self.left && x < self.right && y >= self.top && y < self.bottom
    }

    fn d2d(self) -> D2D_RECT_F {
        D2D_RECT_F {
            left: self.left,
            top: self.top,
            right: self.right,
            bottom: self.bottom,
        }
    }
}

/// Horizontal text alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Left in left-to-right text.
    Leading,
    /// Centred.
    Center,
    /// Right in left-to-right text.
    Trailing,
}

impl Align {
    fn dwrite(self) -> DWRITE_TEXT_ALIGNMENT {
        match self {
            Align::Leading => DWRITE_TEXT_ALIGNMENT_LEADING,
            Align::Center => DWRITE_TEXT_ALIGNMENT_CENTER,
            Align::Trailing => DWRITE_TEXT_ALIGNMENT_TRAILING,
        }
    }
}

/// Font weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    /// Regular (400).
    Normal,
    /// Semibold (600).
    SemiBold,
    /// Bold (700).
    Bold,
}

impl Weight {
    fn dwrite(self) -> DWRITE_FONT_WEIGHT {
        match self {
            Weight::Normal => DWRITE_FONT_WEIGHT_NORMAL,
            Weight::SemiBold => DWRITE_FONT_WEIGHT_SEMI_BOLD,
            Weight::Bold => DWRITE_FONT_WEIGHT_BOLD,
        }
    }
}

struct Factories {
    d2d: ID2D1Factory,
    dwrite: IDWriteFactory,
}

thread_local! {
    // Single-threaded factories: every canvas and text style of a UI thread
    // shares them.
    static FACTORIES: RefCell<Option<std::rc::Rc<Factories>>> = const { RefCell::new(None) };
}

fn factories() -> Result<std::rc::Rc<Factories>> {
    FACTORIES.with(|cell| {
        if let Some(existing) = cell.borrow().as_ref() {
            return Ok(std::rc::Rc::clone(existing));
        }
        // SAFETY: plain factory creation; no options.
        let d2d: ID2D1Factory =
            unsafe { D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None) }
                .map_err(|e| op_error("D2D1CreateFactory", "canvas", e.code().0))?;
        // SAFETY: plain factory creation.
        let dwrite: IDWriteFactory = unsafe { DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED) }
            .map_err(|e| op_error("DWriteCreateFactory", "canvas", e.code().0))?;
        let created = std::rc::Rc::new(Factories { d2d, dwrite });
        *cell.borrow_mut() = Some(std::rc::Rc::clone(&created));
        Ok(created)
    })
}

/// A font, size and weight for drawing text.
#[derive(Debug, Clone)]
pub struct TextStyle {
    format: IDWriteTextFormat,
    ellipsis: Option<IDWriteInlineObject>,
    family: String,
    size: f32,
}

impl TextStyle {
    /// Use the first of `families` installed on this machine (DirectWrite
    /// falls back on its own if none is), at `size` DIPs.
    pub fn new(families: &[&str], size: f32, weight: Weight) -> Result<Self> {
        let factories = factories()?;
        let family = first_installed(&factories.dwrite, families)
            .or_else(|| families.first().map(|f| f.to_string()))
            .unwrap_or_else(|| "Segoe UI".to_string());
        let wide = to_utf16_nul(&family);
        let locale = to_utf16_nul("en-us");
        // SAFETY: both strings are NUL-terminated and outlive the call; the
        // system collection is selected with `None`.
        let format = unsafe {
            factories.dwrite.CreateTextFormat(
                PCWSTR(wide.as_ptr()),
                None,
                weight.dwrite(),
                DWRITE_FONT_STYLE_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL,
                size,
                PCWSTR(locale.as_ptr()),
            )
        }
        .map_err(|e| op_error("CreateTextFormat", family.clone(), e.code().0))?;
        // SAFETY: an ellipsis sign for this format; failure only loses the "…".
        let ellipsis = unsafe { factories.dwrite.CreateEllipsisTrimmingSign(&format) }.ok();
        Ok(Self {
            format,
            ellipsis,
            family,
            size,
        })
    }

    /// The family actually used.
    pub fn family(&self) -> &str {
        &self.family
    }

    /// The size in DIPs.
    pub fn size(&self) -> f32 {
        self.size
    }

    /// Width and height of `text` laid out within `max_width` (wrapping).
    pub fn measure(&self, text: &str, max_width: f32) -> (f32, f32) {
        let Ok(factories) = factories() else {
            return (0.0, 0.0);
        };
        let wide: Vec<u16> = text.encode_utf16().collect();
        self.set_layout(Align::Leading, true, true);
        // SAFETY: `wide` outlives the call.
        let Ok(layout) = (unsafe {
            factories
                .dwrite
                .CreateTextLayout(&wide, &self.format, max_width, f32::MAX)
        }) else {
            return (0.0, 0.0);
        };
        let mut metrics = DWRITE_TEXT_METRICS::default();
        // SAFETY: `metrics` is a valid out pointer.
        if unsafe { layout.GetMetrics(&mut metrics) }.is_err() {
            return (0.0, 0.0);
        }
        (metrics.widthIncludingTrailingWhitespace, metrics.height)
    }

    fn set_layout(&self, align: Align, wrap: bool, top: bool) {
        // SAFETY: plain setters on an owned format; failures keep the old value.
        unsafe {
            let _ = self.format.SetTextAlignment(align.dwrite());
            let _ = self.format.SetParagraphAlignment(if top {
                DWRITE_PARAGRAPH_ALIGNMENT_NEAR
            } else {
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER
            });
            let _ = self.format.SetWordWrapping(if wrap {
                DWRITE_WORD_WRAPPING_WRAP
            } else {
                DWRITE_WORD_WRAPPING_NO_WRAP
            });
            let trimming = DWRITE_TRIMMING {
                granularity: DWRITE_TRIMMING_GRANULARITY_CHARACTER,
                delimiter: 0,
                delimiterCount: 0,
            };
            let _ = self.format.SetTrimming(&trimming, self.ellipsis.as_ref());
        }
    }
}

fn first_installed(dwrite: &IDWriteFactory, families: &[&str]) -> Option<String> {
    let mut collection = None;
    // SAFETY: `collection` is a valid out pointer.
    unsafe { dwrite.GetSystemFontCollection(&mut collection, BOOL::from(false)) }.ok()?;
    let collection = collection?;
    families.iter().find_map(|family| {
        let wide = to_utf16_nul(family);
        let mut index = 0u32;
        let mut exists = BOOL(0);
        // SAFETY: `wide` is NUL-terminated; both out pointers are valid.
        unsafe { collection.FindFamilyName(PCWSTR(wide.as_ptr()), &mut index, &mut exists) }
            .ok()?;
        exists.as_bool().then(|| family.to_string())
    })
}

/// A Direct2D render target bound to one window. Draw only while handling
/// that window's `WM_PAINT`, inside a [`PaintGuard`](super::PaintGuard).
pub struct Canvas {
    hwnd: HWND,
    target: Option<ID2D1HwndRenderTarget>,
    brush: Option<ID2D1SolidColorBrush>,
    dpi: u32,
}

impl std::fmt::Debug for Canvas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Canvas")
            .field("dpi", &self.dpi)
            .field("has_target", &self.target.is_some())
            .finish()
    }
}

impl Canvas {
    /// A canvas for `window`. The device resources are made on first draw.
    pub fn for_window(window: WindowHandle) -> Self {
        Self {
            hwnd: window.into(),
            target: None,
            brush: None,
            dpi: dpi_for_window(window),
        }
    }

    /// The window's current DPI.
    pub fn dpi(&self) -> u32 {
        self.dpi
    }

    /// Convert a client position in pixels to DIPs.
    pub fn to_dip(&self, x: i32, y: i32) -> (f32, f32) {
        let scale = DEFAULT_DPI as f32 / self.dpi as f32;
        (x as f32 * scale, y as f32 * scale)
    }

    /// The client area's size in DIPs.
    pub fn size(&self) -> (f32, f32) {
        let (width, height) = client_pixels(self.hwnd);
        self.to_dip(width as i32, height as i32)
    }

    /// Follow a client-area resize (`WM_SIZE`).
    pub fn resize(&mut self) {
        if let Some(target) = &self.target {
            let (width, height) = client_pixels(self.hwnd);
            let size = D2D_SIZE_U { width, height };
            // SAFETY: `size` is valid for the call; failure recreates on draw.
            if unsafe { target.Resize(&size) }.is_err() {
                self.target = None;
            }
        }
    }

    /// Follow a DPI change (`WM_DPICHANGED`).
    pub fn set_dpi(&mut self, dpi: u32) {
        self.dpi = dpi.max(1);
        if let Some(target) = &self.target {
            // SAFETY: plain setter.
            unsafe { target.SetDpi(self.dpi as f32, self.dpi as f32) };
        }
    }

    /// Draw one frame. A lost device is recreated on the next call.
    pub fn draw(&mut self, paint: impl FnOnce(&Frame<'_>)) -> Result<()> {
        let (target, brush) = self.ensure_target()?;
        // SAFETY: a frame on an owned render target, ended below.
        unsafe { target.BeginDraw() };
        let frame = Frame {
            target: &target,
            brush: &brush,
        };
        paint(&frame);
        // SAFETY: ends the frame begun above.
        match unsafe { target.EndDraw(None, None) } {
            Ok(()) => Ok(()),
            Err(e) if e.code() == D2DERR_RECREATE_TARGET => {
                self.target = None;
                self.brush = None;
                Ok(())
            }
            Err(e) => Err(op_error("EndDraw", "canvas", e.code().0)),
        }
    }

    fn ensure_target(&mut self) -> Result<(ID2D1HwndRenderTarget, ID2D1SolidColorBrush)> {
        if let (Some(target), Some(brush)) = (&self.target, &self.brush) {
            return Ok((target.clone(), brush.clone()));
        }
        let factories = factories()?;
        let (width, height) = client_pixels(self.hwnd);
        let properties = D2D1_RENDER_TARGET_PROPERTIES {
            pixelFormat: D2D1_PIXEL_FORMAT {
                format: DXGI_FORMAT_UNKNOWN,
                alphaMode: D2D1_ALPHA_MODE_UNKNOWN,
            },
            dpiX: self.dpi as f32,
            dpiY: self.dpi as f32,
            ..Default::default()
        };
        let hwnd_properties = D2D1_HWND_RENDER_TARGET_PROPERTIES {
            hwnd: self.hwnd,
            pixelSize: D2D_SIZE_U { width, height },
            presentOptions: D2D1_PRESENT_OPTIONS_NONE,
        };
        // SAFETY: both property structs are valid for the call.
        let target = unsafe {
            factories
                .d2d
                .CreateHwndRenderTarget(&properties, &hwnd_properties)
        }
        .map_err(|e| op_error("CreateHwndRenderTarget", "canvas", e.code().0))?;
        // SAFETY: a brush on the target just made; its colour is set per use.
        let brush = unsafe { target.CreateSolidColorBrush(&Color::hex(0).d2d(), None) }
            .map_err(|e| op_error("CreateSolidColorBrush", "canvas", e.code().0))?;
        self.target = Some(target.clone());
        self.brush = Some(brush.clone());
        Ok((target, brush))
    }
}

fn client_pixels(hwnd: HWND) -> (u32, u32) {
    let mut rect = RECT::default();
    // SAFETY: `rect` is a valid out pointer; failure leaves it empty.
    let _ = unsafe { GetClientRect(hwnd, &mut rect) };
    (
        (rect.right - rect.left).max(1) as u32,
        (rect.bottom - rect.top).max(1) as u32,
    )
}

/// The drawing operations of one frame, in DIPs.
pub struct Frame<'a> {
    target: &'a ID2D1HwndRenderTarget,
    brush: &'a ID2D1SolidColorBrush,
}

impl Frame<'_> {
    fn with(&self, color: Color) -> &ID2D1SolidColorBrush {
        // SAFETY: plain setter on the frame's brush.
        unsafe { self.brush.SetColor(&color.d2d()) };
        self.brush
    }

    /// Fill the whole target.
    pub fn clear(&self, color: Color) {
        // SAFETY: inside BeginDraw/EndDraw.
        unsafe { self.target.Clear(Some(&color.d2d())) };
    }

    /// Fill a rectangle.
    pub fn fill_rect(&self, rect: RectF, color: Color) {
        // SAFETY: inside BeginDraw/EndDraw; `rect` lives for the call.
        unsafe { self.target.FillRectangle(&rect.d2d(), self.with(color)) };
    }

    /// Fill a rectangle with rounded corners.
    pub fn fill_rounded(&self, rect: RectF, radius: f32, color: Color) {
        let rounded = D2D1_ROUNDED_RECT {
            rect: rect.d2d(),
            radiusX: radius,
            radiusY: radius,
        };
        // SAFETY: inside BeginDraw/EndDraw.
        unsafe { self.target.FillRoundedRectangle(&rounded, self.with(color)) };
    }

    /// Outline a rectangle with rounded corners.
    pub fn stroke_rounded(&self, rect: RectF, radius: f32, width: f32, color: Color) {
        let rounded = D2D1_ROUNDED_RECT {
            rect: rect.d2d(),
            radiusX: radius,
            radiusY: radius,
        };
        // SAFETY: inside BeginDraw/EndDraw; no stroke style.
        unsafe {
            self.target
                .DrawRoundedRectangle(&rounded, self.with(color), width, None)
        };
    }

    /// Fill a circle.
    pub fn fill_circle(&self, cx: f32, cy: f32, radius: f32, color: Color) {
        let ellipse = D2D1_ELLIPSE {
            point: D2D_POINT_2F { x: cx, y: cy },
            radiusX: radius,
            radiusY: radius,
        };
        // SAFETY: inside BeginDraw/EndDraw.
        unsafe { self.target.FillEllipse(&ellipse, self.with(color)) };
    }

    /// Draw a straight line.
    pub fn line(&self, from: (f32, f32), to: (f32, f32), width: f32, color: Color) {
        // SAFETY: inside BeginDraw/EndDraw; no stroke style.
        unsafe {
            self.target.DrawLine(
                D2D_POINT_2F {
                    x: from.0,
                    y: from.1,
                },
                D2D_POINT_2F { x: to.0, y: to.1 },
                self.with(color),
                width,
                None,
            )
        };
    }

    /// One line of text, vertically centred in `rect`, cut with "…" when
    /// it does not fit.
    pub fn text(&self, text: &str, style: &TextStyle, rect: RectF, color: Color, align: Align) {
        style.set_layout(align, false, false);
        self.draw_text(text, style, rect, color);
    }

    /// Wrapping text from the top of `rect`.
    pub fn paragraph(&self, text: &str, style: &TextStyle, rect: RectF, color: Color) {
        style.set_layout(Align::Leading, true, true);
        self.draw_text(text, style, rect, color);
    }

    fn draw_text(&self, text: &str, style: &TextStyle, rect: RectF, color: Color) {
        let wide: Vec<u16> = text.encode_utf16().collect();
        // SAFETY: inside BeginDraw/EndDraw; `wide` and the rect outlive the call.
        unsafe {
            self.target.DrawText(
                &wide,
                &style.format,
                &rect.d2d(),
                self.with(color),
                D2D1_DRAW_TEXT_OPTIONS_CLIP,
                DWRITE_MEASURING_MODE_NATURAL,
            )
        };
    }

    /// Restrict drawing to `rect` until [`Self::pop_clip`].
    pub fn push_clip(&self, rect: RectF) {
        // SAFETY: inside BeginDraw/EndDraw; paired with `pop_clip`.
        unsafe {
            self.target
                .PushAxisAlignedClip(&rect.d2d(), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE)
        };
    }

    /// End the innermost [`Self::push_clip`].
    pub fn pop_clip(&self) {
        // SAFETY: paired with a preceding `push_clip`.
        unsafe { self.target.PopAxisAlignedClip() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_convert() {
        let c = Color::hex(0x0067C0);
        assert_eq!(c.to_colorref(), 0x00C0_6700);
        assert_eq!(c.alpha(0.5).a, 0.5);
    }

    #[test]
    fn rects_inset_and_hit_test() {
        let r = RectF::new(10.0, 20.0, 100.0, 50.0);
        assert_eq!((r.width(), r.height()), (100.0, 50.0));
        let inner = r.inset(5.0, 10.0);
        assert_eq!(
            (inner.left, inner.top, inner.right, inner.bottom),
            (15.0, 30.0, 105.0, 60.0)
        );
        assert!(r.contains(10.0, 20.0));
        assert!(!r.contains(110.0, 20.0));
    }

    #[test]
    fn a_missing_family_falls_back_to_the_next() {
        let style = TextStyle::new(&["No Such Font 12345", "Segoe UI"], 14.0, Weight::Normal)
            .expect("text style");
        assert_eq!(style.family(), "Segoe UI");
        let (width, height) = style.measure("BattleGuard", 1000.0);
        assert!(width > 10.0 && height > 5.0, "{width} x {height}");
    }
}
