//! The images link previews show (Open Graph, Twitter): a paper label on
//! the warehouse wall, with an app's icon, name, summary, and a stamp for
//! each kind of repository it has. Drawn here, so a new app or release
//! gets its own card with nothing to run but the gateway, and the same app
//! always gives the same bytes.

use ab_glyph::{Font, FontRef, PxScale, ScaleFont};
use image::{Rgb, RgbImage, imageops};

pub const WIDTH: u32 = 1200;
pub const HEIGHT: u32 = 630;

const BACKGROUND: &[u8] = include_bytes!("og-background.jpg");
const BOLD: &[u8] = include_bytes!("fonts/ZillaSlab-Bold.ttf");
const MEDIUM: &[u8] = include_bytes!("fonts/ZillaSlab-Medium.ttf");

/// The widest and tallest icon read, so a hostile one can't take the memory.
const MAX_ICON_SIDE: u32 = 4096;

const INK: [u8; 3] = [0x2a, 0x1c, 0x10];
const INK_SOFT: [u8; 3] = [0x5b, 0x44, 0x30];
const BRASS: [u8; 3] = [0x8a, 0x6a, 0x22];

/// What a card says.
pub struct Card<'a> {
    /// Small capitals above the title, such as the gateway's host.
    pub eyebrow: &'a str,
    pub title: &'a str,
    pub summary: &'a str,
    /// A PNG, JPEG or WebP; an unreadable one is left out.
    pub icon: Option<&'a [u8]>,
    /// Each stamp's text and ink.
    pub stamps: &'a [(&'a str, [u8; 3])],
}

/// The card, as a JPEG.
pub fn render(card: &Card) -> anyhow::Result<Vec<u8>> {
    let mut canvas = image::load_from_memory_with_format(BACKGROUND, image::ImageFormat::Jpeg)?.to_rgb8();
    let (bold, medium) = (FontRef::try_from_slice(BOLD)?, FontRef::try_from_slice(MEDIUM)?);

    // The label, with its shadow on the wall, and a nail at each corner.
    let (x0, y0, x1, y1) = (56.0, 78.0, 800.0, 552.0);
    shadow(&mut canvas, (x0 + 4.0, y0 + 16.0, x1 + 4.0, y1 + 16.0), 6.0, 30.0, 0.6);
    paper(&mut canvas, (x0, y0, x1, y1), 6.0);
    for (x, y) in [(x0 + 16.0, y0 + 16.0), (x1 - 16.0, y0 + 16.0), (x0 + 16.0, y1 - 16.0), (x1 - 16.0, y1 - 16.0)] {
        fill(&mut canvas, (x - 6.0, y - 6.0, x + 6.0, y + 6.0), 6.0, [0x4b, 0x41, 0x35], 1.0);
        fill(&mut canvas, (x - 3.5, y - 4.5, x + 2.5, y + 1.5), 3.0, [0xd8, 0xd2, 0xc4], 0.9);
    }

    let left = 100.0;
    text(&mut canvas, &bold, 24.0, 4.0, (left, 140.0), BRASS, &card.eyebrow.to_uppercase());

    let icon = card.icon.and_then(|bytes| decode_icon(bytes, 150));
    let title_left = if let Some(icon) = &icon {
        let (ix, iy) = (left, 170.0);
        shadow(&mut canvas, (ix, iy + 6.0, ix + 150.0, iy + 156.0), 32.0, 14.0, 0.45);
        paste_rounded(&mut canvas, icon, (ix as i64, iy as i64), 32.0);
        left + 150.0 + 36.0
    } else {
        left
    };
    let title_width = x1 - 44.0 - title_left;
    let size = fit(&bold, card.title, 84.0, 44.0, title_width);
    let title = truncate(&bold, size, card.title, title_width);
    let title_y = if icon.is_some() { 170.0 + 75.0 + size * 0.34 } else { 240.0 };
    text(&mut canvas, &bold, size, 0.0, (title_left, title_y), INK, &title);

    let summary_top = if icon.is_some() { 380.0 } else { 300.0 };
    let lines = if icon.is_some() { 2 } else { 3 };
    for (i, line) in wrap(&medium, 34.0, card.summary, x1 - 44.0 - left, lines).iter().enumerate() {
        text(&mut canvas, &medium, 34.0, 0.0, (left, summary_top + i as f32 * 44.0), INK_SOFT, line);
    }

    let mut x = left;
    for (label, ink) in card.stamps {
        let label = label.to_uppercase();
        let width = advance(&bold, 24.0, 3.0, &label) + 36.0;
        let (sx, sy) = (x, 470.0);
        outline(&mut canvas, (sx, sy, sx + width, sy + 50.0), 6.0, 3.0, *ink, 0.85);
        outline(&mut canvas, (sx + 6.0, sy + 6.0, sx + width - 6.0, sy + 44.0), 3.0, 1.5, *ink, 0.7);
        text(&mut canvas, &bold, 24.0, 3.0, (sx + 18.0, sy + 34.0), *ink, &label);
        x += width + 16.0;
    }

    let mut jpeg = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 86).encode_image(&canvas)?;
    Ok(jpeg)
}

/// How far `(px, py)` is outside a rectangle with rounded corners: negative
/// inside.
fn distance((x0, y0, x1, y1): (f32, f32, f32, f32), radius: f32, px: f32, py: f32) -> f32 {
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    let (hx, hy) = ((x1 - x0) / 2.0 - radius, (y1 - y0) / 2.0 - radius);
    let (dx, dy) = ((px - cx).abs() - hx, (py - cy).abs() - hy);
    let outside = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
    outside + dx.max(dy).min(0.0) - radius
}

fn blend(pixel: &mut Rgb<u8>, color: [u8; 3], alpha: f32) {
    let alpha = alpha.clamp(0.0, 1.0);
    for (channel, target) in pixel.0.iter_mut().zip(color) {
        *channel = (*channel as f32 * (1.0 - alpha) + target as f32 * alpha).round() as u8;
    }
}

/// Visit every pixel within `margin` of the rectangle.
fn around(canvas: &mut RgbImage, (x0, y0, x1, y1): (f32, f32, f32, f32), margin: f32, mut f: impl FnMut(&mut Rgb<u8>, f32, f32)) {
    let clamp = |v: f32, max: u32| (v.max(0.0) as u32).min(max);
    for y in clamp(y0 - margin, HEIGHT)..clamp(y1 + margin + 1.0, HEIGHT) {
        for x in clamp(x0 - margin, WIDTH)..clamp(x1 + margin + 1.0, WIDTH) {
            f(canvas.get_pixel_mut(x, y), x as f32 + 0.5, y as f32 + 0.5);
        }
    }
}

fn fill(canvas: &mut RgbImage, rect: (f32, f32, f32, f32), radius: f32, color: [u8; 3], opacity: f32) {
    around(canvas, rect, 1.0, |pixel, x, y| blend(pixel, color, (0.5 - distance(rect, radius, x, y)) * opacity));
}

fn outline(canvas: &mut RgbImage, rect: (f32, f32, f32, f32), radius: f32, width: f32, color: [u8; 3], opacity: f32) {
    around(canvas, rect, 1.0, |pixel, x, y| {
        let d = distance(rect, radius, x, y);
        let coverage = (0.5 - d).min(d + width + 0.5).clamp(0.0, 1.0);
        blend(pixel, color, coverage * opacity);
    });
}

fn shadow(canvas: &mut RgbImage, rect: (f32, f32, f32, f32), radius: f32, blur: f32, opacity: f32) {
    around(canvas, rect, blur, |pixel, x, y| {
        let t = (distance(rect, radius, x, y) / blur).clamp(0.0, 1.0);
        let falloff = 1.0 - t * t * (3.0 - 2.0 * t);
        blend(pixel, [0x0c, 0x06, 0x02], falloff * opacity);
    });
}

/// Paper: lighter at the top, with a little grain.
fn paper(canvas: &mut RgbImage, rect: (f32, f32, f32, f32), radius: f32) {
    let (top, bottom) = ([0xfb, 0xf3, 0xdf], [0xec, 0xdc, 0xb6]);
    around(canvas, rect, 1.0, |pixel, x, y| {
        let t = ((y - rect.1) / (rect.3 - rect.1)).clamp(0.0, 1.0);
        let hash = ((x as u32).wrapping_mul(374_761_393) ^ (y as u32).wrapping_mul(668_265_263)).wrapping_mul(1_274_126_177) >> 28;
        let grain = hash as f32 - 7.5;
        let color = std::array::from_fn(|i| (top[i] as f32 * (1.0 - t) + bottom[i] as f32 * t + grain * 0.8).clamp(0.0, 255.0) as u8);
        blend(pixel, color, 0.5 - distance(rect, radius, x, y));
    });
}

fn decode_icon(bytes: &[u8], side: u32) -> Option<image::RgbaImage> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_ICON_SIDE);
    limits.max_image_height = Some(MAX_ICON_SIDE);
    limits.max_alloc = Some(u64::from(MAX_ICON_SIDE).pow(2) * 8);
    reader.limits(limits);
    let icon = reader.decode().ok()?.to_rgba8();
    Some(imageops::resize(&icon, side, side, imageops::FilterType::Lanczos3))
}

/// `icon` at `(x, y)`, its corners rounded, on white where it's clear.
fn paste_rounded(canvas: &mut RgbImage, icon: &image::RgbaImage, (x, y): (i64, i64), radius: f32) {
    let side = icon.width() as f32;
    for (ix, iy, pixel) in icon.enumerate_pixels() {
        let (cx, cy) = (x + ix as i64, y + iy as i64);
        if !(0..WIDTH as i64).contains(&cx) || !(0..HEIGHT as i64).contains(&cy) {
            continue;
        }
        let shape = (0.5 - distance((0.0, 0.0, side, side), radius, ix as f32 + 0.5, iy as f32 + 0.5)).clamp(0.0, 1.0);
        let target = canvas.get_pixel_mut(cx as u32, cy as u32);
        blend(target, [0xff, 0xff, 0xff], shape);
        blend(target, [pixel[0], pixel[1], pixel[2]], shape * pixel[3] as f32 / 255.0);
    }
}

/// How wide `line` is at `size`, with `spacing` between letters.
fn advance(font: &FontRef, size: f32, spacing: f32, line: &str) -> f32 {
    let scaled = font.as_scaled(PxScale::from(size));
    let mut width = 0.0;
    let mut previous = None;
    for c in line.chars() {
        let id = scaled.glyph_id(c);
        if let Some(previous) = previous {
            width += scaled.kern(previous, id) + spacing;
        }
        width += scaled.h_advance(id);
        previous = Some(id);
    }
    width
}

/// Draw `line` with its baseline starting at `(x, y)`.
fn text(canvas: &mut RgbImage, font: &FontRef, size: f32, spacing: f32, (mut x, y): (f32, f32), color: [u8; 3], line: &str) {
    let scaled = font.as_scaled(PxScale::from(size));
    let mut previous = None;
    for c in line.chars() {
        let id = scaled.glyph_id(c);
        if let Some(previous) = previous {
            x += scaled.kern(previous, id) + spacing;
        }
        let glyph = id.with_scale_and_position(size, ab_glyph::point(x, y));
        if let Some(outlined) = font.outline_glyph(glyph) {
            let bounds = outlined.px_bounds();
            outlined.draw(|gx, gy, coverage| {
                let (px, py) = (bounds.min.x as i64 + gx as i64, bounds.min.y as i64 + gy as i64);
                if (0..WIDTH as i64).contains(&px) && (0..HEIGHT as i64).contains(&py) {
                    blend(canvas.get_pixel_mut(px as u32, py as u32), color, coverage);
                }
            });
        }
        x += scaled.h_advance(id);
        previous = Some(id);
    }
}

/// The largest size from `max` down to `min` at which `line` fits `width`.
fn fit(font: &FontRef, line: &str, max: f32, min: f32, width: f32) -> f32 {
    let mut size = max;
    while size > min && advance(font, size, 0.0, line) > width {
        size -= 2.0;
    }
    size
}

/// `line`, cut short with an ellipsis if it's wider than `width`.
fn truncate(font: &FontRef, size: f32, line: &str, width: f32) -> String {
    if advance(font, size, 0.0, line) <= width {
        return line.to_string();
    }
    let mut cut: String = line.to_string();
    while !cut.is_empty() && advance(font, size, 0.0, &format!("{}…", cut.trim_end())) > width {
        cut.pop();
    }
    format!("{}…", cut.trim_end())
}

/// `text` in at most `max` lines of `width`, the last cut short if need be.
fn wrap(font: &FontRef, size: f32, text: &str, width: f32, max: usize) -> Vec<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut lines: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if lines.len() + 1 == max {
            lines.push(truncate(font, size, &words[i..].join(" "), width));
            break;
        }
        let mut line = words[i].to_string();
        i += 1;
        while i < words.len() && advance(font, size, 0.0, &format!("{line} {}", words[i])) <= width {
            line = format!("{line} {}", words[i]);
            i += 1;
        }
        lines.push(truncate(font, size, &line, width));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_the_same_card_twice() {
        let icon = {
            let mut png = Vec::new();
            let image = image::ImageBuffer::from_pixel(64, 64, image::Rgba([200u8, 40, 120, 255]));
            image.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
            png
        };
        let card = Card {
            eyebrow: "pkg.example.com",
            title: "A rather long application name that has to shrink",
            summary: &"Words that wrap onto more than one line. ".repeat(10),
            icon: Some(&icon),
            stamps: &[("deb", [0xa8, 0x28, 0x1d]), ("F-Droid", [0x6b, 0x3d, 0x8c])],
        };
        let jpeg = render(&card).unwrap();
        let decoded = image::load_from_memory(&jpeg).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (WIDTH, HEIGHT));
        assert_eq!(render(&card).unwrap(), jpeg);
        // An icon that isn't one is left out, not an error.
        assert!(render(&Card { icon: Some(b"not an image"), ..card }).is_ok());
    }

    #[test]
    fn wraps_and_cuts_short() {
        let font = FontRef::try_from_slice(MEDIUM).unwrap();
        let lines = wrap(&font, 34.0, &"word ".repeat(100), 300.0, 2);
        assert_eq!(lines.len(), 2);
        assert!(lines[1].ends_with('…'));
        assert!(lines.iter().all(|line| advance(&font, 34.0, 0.0, line) <= 300.0));
    }
}
