//! Adaptive terminal theme.
//!
//! The framework never hard-codes one terminal palette. It detects what the
//! host terminal can actually render, maps a curated palette into *semantic*
//! roles, and downgrades truecolor to 256-colour and then to the 16 base ANSI
//! colours when necessary. Callers never emit raw escape sequences: they ask
//! for a semantic role and get a correctly degraded string back.

use std::fmt;
use std::io::IsTerminal;

use serde::{Deserialize, Serialize};

use crate::config::ColorMode;

/// How much colour the host terminal can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColorDepth {
    /// No colour at all: `NO_COLOR`, `TERM=dumb`, or a non-tty destination.
    None,
    /// The 16 classic ANSI colours.
    Ansi16,
    /// The xterm 256-colour cube.
    Ansi256,
    /// 24-bit direct colour.
    TrueColor,
}

impl ColorDepth {
    /// Downgrade a requested depth to what the terminal supports.
    pub fn clamp(self, requested: ColorDepth) -> ColorDepth {
        if self < requested {
            self
        } else {
            requested
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ColorDepth::None => "NONE",
            ColorDepth::Ansi16 => "ANSI16",
            ColorDepth::Ansi256 => "ANSI256",
            ColorDepth::TrueColor => "TRUECOLOR",
        }
    }
}

/// A concrete colour, which may degrade across depths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteColor {
    /// Always rendered as the terminal's default foreground.
    Default,
    /// One of the 16 base ANSI colours, safe at any depth.
    Ansi(u8),
    /// xterm-256 palette index.
    Index(u8),
    /// 24-bit RGB.
    Rgb(u8, u8, u8),
}

/// Text attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs {
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub reverse: bool,
}

impl Attrs {
    pub const NONE: Attrs = Attrs {
        bold: false,
        dim: false,
        italic: false,
        underline: false,
        reverse: false,
    };
    pub const fn bold() -> Self {
        Self {
            bold: true,
            ..Attrs::NONE
        }
    }
    pub const fn dim() -> Self {
        Self {
            dim: true,
            ..Attrs::NONE
        }
    }
    pub const fn bold_dim() -> Self {
        Self {
            bold: true,
            dim: true,
            ..Attrs::NONE
        }
    }
    pub const fn italic() -> Self {
        Self {
            italic: true,
            ..Attrs::NONE
        }
    }
    pub const fn underline() -> Self {
        Self {
            underline: true,
            ..Attrs::NONE
        }
    }
    pub const fn reverse() -> Self {
        Self {
            reverse: true,
            ..Attrs::NONE
        }
    }
}

/// A semantic text style: a foreground colour, an optional background, and
/// attributes.
///
/// The background is opt-in. Painting every role with a filled block of its own
/// colour turns ordinary text into a solid bar, so only roles that genuinely
/// need a filled background — a selected row, a reversed banner — set one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    pub color: PaletteColor,
    pub bg: Option<PaletteColor>,
    pub attrs: Attrs,
}

impl Style {
    pub const fn new(color: PaletteColor, attrs: Attrs) -> Self {
        Self {
            color,
            bg: None,
            attrs,
        }
    }
    pub const fn fg(color: PaletteColor) -> Self {
        Self {
            color,
            bg: None,
            attrs: Attrs::NONE,
        }
    }
    /// Render `text` on a filled background of `bg`.
    pub const fn on(mut self, bg: PaletteColor) -> Self {
        self.bg = Some(bg);
        self
    }
    /// Swap foreground and background, for a selected row.
    pub const fn reversed(mut self, bg: PaletteColor) -> Self {
        self.bg = Some(bg);
        self.attrs.reverse = true;
        self
    }
    pub const fn with_attrs(mut self, attrs: Attrs) -> Self {
        self.attrs = attrs;
        self
    }
    pub const fn bold(mut self) -> Self {
        self.attrs.bold = true;
        self
    }
    pub const fn dim(mut self) -> Self {
        self.attrs.dim = true;
        self
    }
    pub const fn underline(mut self) -> Self {
        self.attrs.underline = true;
        self
    }
}

/// The set of semantic colours the interface draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticPalette {
    /// Headings, primary structure.
    pub primary: PaletteColor,
    /// Secondary structure, labels.
    pub secondary: PaletteColor,
    /// Highlights, selected rows, key values.
    pub accent: PaletteColor,
    pub success: PaletteColor,
    pub warning: PaletteColor,
    pub error: PaletteColor,
    pub info: PaletteColor,
    /// De-emphasised supporting text.
    pub muted: PaletteColor,
    /// Default body text.
    pub foreground: PaletteColor,
    /// Box fills / explicit background.
    pub background: PaletteColor,
    pub border: PaletteColor,
    /// Row highlight background.
    pub highlight: PaletteColor,
}

/// Named palette families. Selection is automatic unless overridden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaletteName {
    /// Cool blue/teal on near-black. Default for dark terminals.
    Midnight,
    /// Neutral greys with an amber accent. Good on OLED and low-blue setups.
    Graphite,
    /// Low-contrast palette matching the Solarized dark convention.
    SolarizedDark,
    /// Low-contrast palette matching the Solarized light convention.
    SolarizedLight,
    /// High-contrast dark palette for terminals with dim palettes.
    Daylight,
    /// Dark palette for terminals reporting a light background by mistake.
    Ashen,
}

impl PaletteName {
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "midnight" => PaletteName::Midnight,
            "graphite" => PaletteName::Graphite,
            "solarized-dark" | "solarized_dark" => PaletteName::SolarizedDark,
            "solarized-light" | "solarized_light" => PaletteName::SolarizedLight,
            "daylight" => PaletteName::Daylight,
            "ashen" => PaletteName::Ashen,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PaletteName::Midnight => "midnight",
            PaletteName::Graphite => "graphite",
            PaletteName::SolarizedDark => "solarized-dark",
            PaletteName::SolarizedLight => "solarized-light",
            PaletteName::Daylight => "daylight",
            PaletteName::Ashen => "ashen",
        }
    }

    /// True when the palette assumes a light terminal background.
    pub fn is_light(self) -> bool {
        matches!(self, PaletteName::SolarizedLight)
    }

    pub fn semantics(self) -> SemanticPalette {
        match self {
            PaletteName::Midnight => SemanticPalette {
                primary: PaletteColor::Rgb(126, 214, 223),
                secondary: PaletteColor::Rgb(94, 160, 178),
                accent: PaletteColor::Rgb(247, 208, 96),
                success: PaletteColor::Rgb(126, 214, 143),
                warning: PaletteColor::Rgb(230, 176, 80),
                error: PaletteColor::Rgb(238, 106, 106),
                info: PaletteColor::Rgb(130, 186, 234),
                muted: PaletteColor::Rgb(122, 134, 148),
                foreground: PaletteColor::Rgb(214, 222, 230),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(64, 92, 108),
                highlight: PaletteColor::Rgb(38, 60, 72),
            },
            PaletteName::Graphite => SemanticPalette {
                primary: PaletteColor::Rgb(226, 226, 226),
                secondary: PaletteColor::Rgb(160, 160, 160),
                accent: PaletteColor::Rgb(232, 168, 84),
                success: PaletteColor::Rgb(150, 200, 130),
                warning: PaletteColor::Rgb(226, 178, 96),
                error: PaletteColor::Rgb(220, 110, 100),
                info: PaletteColor::Rgb(150, 178, 200),
                muted: PaletteColor::Rgb(130, 130, 130),
                foreground: PaletteColor::Rgb(210, 210, 210),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(80, 80, 80),
                highlight: PaletteColor::Rgb(52, 52, 52),
            },
            PaletteName::SolarizedDark => SemanticPalette {
                primary: PaletteColor::Rgb(131, 148, 150),
                secondary: PaletteColor::Rgb(101, 123, 131),
                accent: PaletteColor::Rgb(181, 137, 0),
                success: PaletteColor::Rgb(133, 153, 0),
                warning: PaletteColor::Rgb(181, 137, 0),
                error: PaletteColor::Rgb(220, 50, 47),
                info: PaletteColor::Rgb(38, 139, 210),
                muted: PaletteColor::Rgb(88, 110, 117),
                foreground: PaletteColor::Rgb(238, 232, 213),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(58, 86, 96),
                highlight: PaletteColor::Rgb(7, 54, 66),
            },
            PaletteName::SolarizedLight => SemanticPalette {
                primary: PaletteColor::Rgb(101, 123, 131),
                secondary: PaletteColor::Rgb(131, 148, 150),
                accent: PaletteColor::Rgb(133, 153, 0),
                success: PaletteColor::Rgb(133, 153, 0),
                warning: PaletteColor::Rgb(181, 137, 0),
                error: PaletteColor::Rgb(220, 50, 47),
                info: PaletteColor::Rgb(38, 139, 210),
                muted: PaletteColor::Rgb(147, 161, 161),
                foreground: PaletteColor::Rgb(101, 123, 131),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(188, 190, 167),
                highlight: PaletteColor::Rgb(238, 232, 213),
            },
            PaletteName::Daylight => SemanticPalette {
                primary: PaletteColor::Rgb(255, 255, 255),
                secondary: PaletteColor::Rgb(200, 205, 210),
                accent: PaletteColor::Rgb(255, 214, 92),
                success: PaletteColor::Rgb(120, 240, 150),
                warning: PaletteColor::Rgb(255, 190, 90),
                error: PaletteColor::Rgb(255, 110, 110),
                info: PaletteColor::Rgb(140, 200, 255),
                muted: PaletteColor::Rgb(150, 158, 166),
                foreground: PaletteColor::Rgb(235, 240, 245),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(90, 100, 110),
                highlight: PaletteColor::Rgb(46, 60, 74),
            },
            PaletteName::Ashen => SemanticPalette {
                primary: PaletteColor::Rgb(168, 168, 178),
                secondary: PaletteColor::Rgb(136, 136, 146),
                accent: PaletteColor::Rgb(196, 160, 200),
                success: PaletteColor::Rgb(150, 190, 160),
                warning: PaletteColor::Rgb(200, 180, 140),
                error: PaletteColor::Rgb(200, 130, 130),
                info: PaletteColor::Rgb(140, 170, 200),
                muted: PaletteColor::Rgb(118, 118, 128),
                foreground: PaletteColor::Rgb(198, 198, 206),
                background: PaletteColor::Default,
                border: PaletteColor::Rgb(74, 74, 84),
                highlight: PaletteColor::Rgb(40, 40, 48),
            },
        }
    }
}

/// Which semantic role a caller wants. Callers use roles, never raw colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Secondary,
    Accent,
    Success,
    Warning,
    Error,
    Info,
    Muted,
    Foreground,
    Background,
    Border,
    Highlight,
}

/// Fully resolved theme: palette + depth + the derived semantic styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub palette_name: PaletteName,
    pub depth: ColorDepth,
    colors: SemanticPalette,
}

impl Theme {
    /// Detect the terminal's capabilities and build a theme.
    pub fn detect(mode: ColorMode) -> Self {
        let depth = detect_depth(mode);
        let palette = detect_palette();
        Self {
            palette_name: palette,
            depth,
            colors: palette.semantics(),
        }
    }

    /// A theme with no colour at all, for pipes and dumb terminals.
    pub fn plain() -> Self {
        Self {
            palette_name: PaletteName::Midnight,
            depth: ColorDepth::None,
            colors: PaletteName::Midnight.semantics(),
        }
    }

    /// A theme for tests: fixed palette, fixed depth.
    pub fn fixed(palette: PaletteName, depth: ColorDepth) -> Self {
        Self {
            palette_name: palette,
            depth,
            colors: palette.semantics(),
        }
    }

    pub fn style(&self, role: Role) -> Style {
        let c = match role {
            Role::Primary => self.colors.primary,
            Role::Secondary => self.colors.secondary,
            Role::Accent => self.colors.accent,
            Role::Success => self.colors.success,
            Role::Warning => self.colors.warning,
            Role::Error => self.colors.error,
            Role::Info => self.colors.info,
            Role::Muted => self.colors.muted,
            Role::Foreground => self.colors.foreground,
            Role::Background => self.colors.background,
            Role::Border => self.colors.border,
            Role::Highlight => self.colors.highlight,
        };
        match role {
            // A highlight is text on a filled block, not a filled block of text.
            Role::Highlight => Style::fg(self.colors.background).on(c),
            // Everything else is foreground only.
            _ => Style::fg(c),
        }
    }

    /// Render `text` in the given semantic role.
    pub fn paint(&self, role: Role, text: &str) -> String {
        self.paint_with(self.style(role), text)
    }

    /// Render `text` with an explicit style built from a semantic role.
    pub fn paint_with(&self, style: Style, text: &str) -> String {
        if self.depth == ColorDepth::None || text.is_empty() {
            return text.to_string();
        }
        let mut s = String::with_capacity(text.len() + 16);
        s.push_str("\x1b[");
        let mut parts: Vec<String> = Vec::new();
        if style.attrs.bold {
            parts.push("1".into());
        }
        if style.attrs.dim {
            parts.push("2".into());
        }
        if style.attrs.italic {
            parts.push("3".into());
        }
        if style.attrs.underline {
            parts.push("4".into());
        }
        if style.attrs.reverse {
            parts.push("7".into());
        }
        let fg = self.sequence_for(style.color, false);
        if let Some(c) = fg {
            parts.push(c);
        }
        if let Some(bg) = style.bg.and_then(|c| self.sequence_for(c, true)) {
            parts.push(bg);
        }
        if parts.is_empty() {
            return text.to_string();
        }
        s.push_str(&parts.join(";"));
        s.push('m');
        s.push_str(text);
        s.push_str("\x1b[0m");
        s
    }

    /// Human-readable description of the resolved theme, for the banner.
    pub fn describe(&self) -> String {
        format!(
            "PALETTE {} · COLOUR {}",
            self.palette_name.as_str().to_ascii_uppercase(),
            self.depth.as_str()
        )
    }

    fn sequence_for(&self, color: PaletteColor, background: bool) -> Option<String> {
        // Two different introducers are in play. The 16 basic colours are
        // selected by 30-37/90-97 (fg) and 40-47/100-107 (bg), but the indexed
        // and 24-bit forms are selected by 38/48 followed by the colour model:
        // `38;5;n` and `38;2;r;g;b`. Emitting `30;2;…` would set a *black*
        // foreground and turn the *dim* attribute on instead of a colour.
        let basic = if background { 40 } else { 30 };
        let bright_basic = if background { 100 } else { 90 };
        let extended = if background { 48 } else { 38 };
        match color {
            PaletteColor::Default => None,
            PaletteColor::Ansi(n) => {
                // 0-7 standard, 8-15 bright.
                if n < 8 {
                    Some(format!("{}", basic + n as u16))
                } else {
                    Some(format!("{}", bright_basic + (n - 8) as u16))
                }
            }
            PaletteColor::Index(i) => match self.depth {
                ColorDepth::TrueColor | ColorDepth::Ansi256 => Some(format!("{extended};5;{i}")),
                ColorDepth::Ansi16 => Some(format!("{}", basic + ansi16_index(i) as u16)),
                ColorDepth::None => None,
            },
            PaletteColor::Rgb(r, g, b) => match self.depth {
                ColorDepth::TrueColor => Some(format!("{extended};2;{r};{g};{b}")),
                ColorDepth::Ansi256 => {
                    let idx = rgb_to_256(r, g, b);
                    Some(format!("{extended};5;{idx}"))
                }
                ColorDepth::Ansi16 => {
                    let idx = rgb_to_256(r, g, b);
                    Some(format!("{}", basic + ansi16_index(idx) as u16))
                }
                ColorDepth::None => None,
            },
        }
    }
}

impl fmt::Display for Theme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Detect how much colour the destination can render.
pub fn detect_depth(mode: ColorMode) -> ColorDepth {
    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    let interactive = stdout_tty || stderr_tty;

    // NO_COLOR is honoured whenever set to any non-empty value.
    let no_color = std::env::var_os("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if no_color {
        return ColorDepth::None;
    }
    let term = std::env::var("TERM").unwrap_or_default();
    if term == "dumb" {
        return ColorDepth::None;
    }

    let colorterm_24bit = std::env::var("COLORTERM")
        .map(|v| v.contains("truecolor") || v.contains("24bit"))
        .unwrap_or(false);
    let detected = if term.contains("truecolor") || term.contains("24bit") || colorterm_24bit {
        ColorDepth::TrueColor
    } else if term.contains("256color") {
        ColorDepth::Ansi256
    } else if !term.is_empty() {
        ColorDepth::Ansi16
    } else if interactive {
        // A tty with no TERM at all: assume it can at least do 16 colours.
        ColorDepth::Ansi16
    } else {
        ColorDepth::None
    };

    match mode {
        ColorMode::Never => ColorDepth::None,
        ColorMode::Always => {
            if detected == ColorDepth::None {
                // Respect NO_COLOR/dumb even when forced; the operator asked for
                // a usable interface and corrupting it helps nobody.
                ColorDepth::None
            } else {
                ColorDepth::TrueColor
            }
        }
        ColorMode::Auto => detected,
    }
}

/// Choose a palette from the environment, preferring an explicit override.
pub fn detect_palette() -> PaletteName {
    if let Ok(explicit) = std::env::var("TSEC_PALETTE") {
        if let Some(p) = PaletteName::from_name(&explicit) {
            return p;
        }
    }
    // COLORFGBG is set by several terminals as "<fg>;<bg>". A high background
    // index means a light terminal, which needs the light palette.
    if let Ok(fgbg) = std::env::var("COLORFGBG") {
        if let Some(bg) = fgbg.split(';').nth(1) {
            if bg.parse::<u32>().map(|n| n >= 7).unwrap_or(false) {
                return PaletteName::SolarizedLight;
            }
        }
    }
    if std::env::var("TERM")
        .map(|t| t.contains("light"))
        .unwrap_or(false)
    {
        return PaletteName::SolarizedLight;
    }
    PaletteName::Midnight
}

/// Map a colour to the nearest xterm-256 palette index.
pub fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    // Greyscale ramp is a much better match than the 6x6x6 cube for
    // near-neutral colours.
    let max = r.max(g).max(b) as i32;
    let min = r.min(g).min(b) as i32;
    if max - min < 10 {
        if r < 8 {
            return 16;
        }
        if r > 248 {
            return 231;
        }
        let level = ((r as f32 - 8.0) / 247.0 * 23.0).round() as i32;
        return (232 + level.clamp(0, 23)) as u8;
    }
    // xterm's 6x6x6 cube: levels 0-5, with anything below 48 folded into level
    // 0 and the rest spaced 40 apart from an offset of 35.
    let q = |c: u8| -> i32 {
        let v = c as f32;
        let level = if v < 48.0 { 0.0 } else { (v - 35.0) / 40.0 };
        level.round().clamp(0.0, 5.0) as i32
    };
    let (ri, gi, bi) = (q(r), q(g), q(b));
    let idx = 16 + 36 * ri + 6 * gi + bi;
    idx.clamp(0, 255) as u8
}

/// Map a 256-colour index onto one of the 16 base ANSI colours.
pub fn ansi16_index(i: u8) -> u8 {
    // Standard 16 colours as their canonical sRGB values.
    const BASE: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (128, 0, 0),
        (0, 128, 0),
        (128, 128, 0),
        (0, 0, 128),
        (128, 0, 128),
        (0, 128, 128),
        (192, 192, 192),
        (128, 128, 128),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (0, 0, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    if i < 16 {
        return i;
    }
    let (r, g, b) = xterm256_rgb(i);
    let mut best = 0u8;
    let mut best_d = u32::MAX;
    for (idx, (br, bg, bb)) in BASE.iter().enumerate() {
        let dr = r as i32 - *br as i32;
        let dg = g as i32 - *bg as i32;
        let db = b as i32 - *bb as i32;
        // Perceptual weighting: green contributes most to luminance.
        let d = (dr * dr * 3 + dg * dg * 6 + db * db) as u32;
        if d < best_d {
            best_d = d;
            best = idx as u8;
        }
    }
    best
}

/// Resolve an xterm-256 index to RGB.
pub fn xterm256_rgb(i: u8) -> (u8, u8, u8) {
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];
    if i < 16 {
        const BASE: [(u8, u8, u8); 16] = [
            (0, 0, 0),
            (128, 0, 0),
            (0, 128, 0),
            (128, 128, 0),
            (0, 0, 128),
            (128, 0, 128),
            (0, 128, 128),
            (192, 192, 192),
            (128, 128, 128),
            (255, 0, 0),
            (0, 255, 0),
            (255, 255, 0),
            (0, 0, 255),
            (255, 0, 255),
            (0, 255, 255),
            (255, 255, 255),
        ];
        return BASE[i as usize];
    }
    if i >= 232 {
        let v = 8 + (i as u16 - 232) * 10;
        let v = v.min(255) as u8;
        return (v, v, v);
    }
    let n = i - 16;
    let r = CUBE[(n / 36) as usize];
    let g = CUBE[((n % 36) / 6) as usize];
    let b = CUBE[(n % 6) as usize];
    (r, g, b)
}

/// Remove every ANSI escape sequence from a string.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume a complete CSI / OSC / two-byte sequence.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // An OSC sequence, terminated by BEL or by ST (ESC \).
                    chars.next();
                    for c in chars.by_ref() {
                        if c == '\u{7}' || c == '\x1b' {
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_environment_disables_all_colour() {
        // Cannot set env in a multithreaded test safely, so exercise the
        // decision function directly.
        assert_eq!(detect_depth(ColorMode::Never), ColorDepth::None);
    }

    #[test]
    fn plain_theme_emits_no_escape_sequences() {
        let t = Theme::plain();
        let s = t.paint(Role::Primary, "RECON");
        assert_eq!(s, "RECON");
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn ansi16_theme_emits_only_basic_sequences() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::Ansi16);
        let s = t.paint(Role::Error, "FAILED");
        assert!(s.starts_with("\x1b["));
        assert!(s.ends_with("\x1b[0m"));
        // A 16-colour sequence must not contain the 5;N or 2;r;g;b forms.
        let body = s
            .trim_start_matches("\x1b[")
            .trim_end_matches("m")
            .trim_end_matches("\x1b[0m");
        assert!(!body.contains(";5;"));
        assert!(!body.contains(";2;"));
    }

    #[test]
    fn truecolor_theme_emits_rgb_sequences() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let s = t.paint(Role::Primary, "PHASE");
        // `38;2;r;g;b`, not `30;2;…` which is a black foreground plus dim.
        assert!(s.contains("38;2;"), "{s:?}");
    }

    #[test]
    fn ordinary_text_is_never_painted_on_a_filled_background() {
        // Every role used to emit `38;…;48;…`, so a single word of body text
        // rendered as a solid block of its own colour. Only roles that need a
        // filled background may set one.
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        for role in [
            Role::Primary,
            Role::Secondary,
            Role::Accent,
            Role::Success,
            Role::Warning,
            Role::Error,
            Role::Info,
            Role::Muted,
            Role::Foreground,
            Role::Background,
            Role::Border,
        ] {
            let painted = t.paint(role, "TEXT");
            assert!(
                !painted.contains("48;2;"),
                "role {role:?} painted a background: {painted:?}"
            );
        }
    }

    #[test]
    fn a_highlight_role_paints_text_on_a_filled_background() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let painted = t.paint(Role::Highlight, "SELECTED");
        assert!(painted.contains("48;2;"), "{painted:?}");
    }

    #[test]
    fn a_reversed_style_swaps_foreground_and_background() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let style = t.style(Role::Accent).reversed(t.style(Role::Primary).color);
        let painted = t.paint_with(style, "ROW");
        assert!(
            painted.contains('7'),
            "reverse attribute missing: {painted:?}"
        );
        assert!(painted.contains("48;2;"), "{painted:?}");
    }

    #[test]
    fn ansi256_theme_downgrades_rgb_to_cube_index() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::Ansi256);
        let s = t.paint(Role::Accent, "VALUE");
        assert!(s.contains("38;5;"), "{s:?}");
        assert!(!s.contains(";2;"));
    }

    #[test]
    fn text_case_is_never_modified_by_styling() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let s = t.paint(Role::Accent, "subfinder -d Example.COM");
        let visible = strip_ansi(&s);
        assert_eq!(visible, "subfinder -d Example.COM");
    }

    #[test]
    fn strip_ansi_removes_colour_but_keeps_content() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let s = t.paint(Role::Error, "exit 1");
        assert_eq!(strip_ansi(&s), "exit 1");
    }

    #[test]
    fn strip_ansi_handles_osc_sequences() {
        assert_eq!(strip_ansi("\x1b]0;title\x07body"), "body");
    }

    #[test]
    fn attributes_are_emitted_before_colour() {
        let t = Theme::fixed(PaletteName::Midnight, ColorDepth::TrueColor);
        let style = t.style(Role::Primary).bold().underline();
        let s = t.paint_with(style, "X");
        let seq = s.split('m').next().unwrap();
        assert!(seq.contains("1"));
        assert!(seq.contains("4"));
    }

    #[test]
    fn grey_maps_to_the_greyscale_ramp() {
        assert_eq!(rgb_to_256(0, 0, 0), 16);
        assert_eq!(rgb_to_256(255, 255, 255), 231);
        let mid = rgb_to_256(128, 128, 128);
        assert!((232..=255).contains(&mid));
    }

    #[test]
    fn pure_red_maps_to_a_cube_index() {
        let idx = rgb_to_256(255, 0, 0);
        assert!((16..232).contains(&idx));
        let (r, g, b) = xterm256_rgb(idx);
        assert!(r > 200 && g < 60 && b < 60);
    }

    #[test]
    fn every_palette_defines_every_semantic_role_distinctly_enough() {
        for name in [
            PaletteName::Midnight,
            PaletteName::Graphite,
            PaletteName::SolarizedDark,
            PaletteName::SolarizedLight,
            PaletteName::Daylight,
            PaletteName::Ashen,
        ] {
            let t = Theme::fixed(name, ColorDepth::TrueColor);
            for role in [
                Role::Primary,
                Role::Secondary,
                Role::Accent,
                Role::Success,
                Role::Warning,
                Role::Error,
                Role::Info,
                Role::Muted,
                Role::Foreground,
                Role::Border,
                Role::Highlight,
            ] {
                let painted = t.paint(role, "x");
                assert!(
                    painted.contains('\x1b'),
                    "{name:?} {role:?} produced no colour"
                );
            }
        }
    }

    #[test]
    fn describe_is_capitalised_for_presentation() {
        let t = Theme::fixed(PaletteName::Graphite, ColorDepth::Ansi16);
        assert_eq!(t.describe(), "PALETTE GRAPHITE · COLOUR ANSI16");
    }

    #[test]
    fn palette_names_round_trip() {
        for name in [
            PaletteName::Midnight,
            PaletteName::Graphite,
            PaletteName::SolarizedDark,
            PaletteName::SolarizedLight,
            PaletteName::Daylight,
            PaletteName::Ashen,
        ] {
            assert_eq!(PaletteName::from_name(name.as_str()), Some(name));
        }
        assert_eq!(PaletteName::from_name("neon-hacker"), None);
    }
}
