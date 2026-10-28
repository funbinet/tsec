//! Theme *source* detection: where the palette actually comes from.
//!
//! The Bash Universal Theme Adapter's behaviour is recreated here as a Rust
//! detection pipeline. The detector walks a fixed priority of sources, reads
//! the first one that really exists on this host, and reports which one fired
//! (and why a lower one did not) through [`ThemeSource`] so the STATUS screen
//! shows a truthful diagnostic instead of guessing:
//!
//! 1. `TSEC_PALETTE` — explicit operator override of a built-in family.
//! 2. Omarchy's active theme (`~/.local/state/omarchy/current`, then the
//!    `omarchy theme current` / `omarchy theme dir` CLI).
//! 3. Catppuccin palette data under the config directory.
//! 4. Base16/Base24 palette data under the config directory.
//! 5. Pywal's colours cache.
//! 6. A generic palette file at `~/.config/tsec/palette.{toml,json}`.
//! 7. Terminal environment hints (`COLORFGBG`, `TERM`).
//! 8. The curated built-in fallback.
//!
//! Nothing here is hard-coded to one desktop: every step is a probe that
//! either finds real palette data or falls through, and the semantic roles
//! (`primary`, `success`, `error`, …) are filled from whatever the source
//! actually provides — with explicit per-source fallbacks for keys it lacks.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::install::{run_capture, which};
use crate::ui::theme::{PaletteColor, PaletteName, SemanticPalette};

/// Which theme source won the detection pipeline, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThemeSource {
    /// `TSEC_PALETTE` named one of the built-in families.
    Override(PaletteName),
    /// One of the curated built-in families (used when no source exists).
    Builtin(PaletteName),
    /// Omarchy's active theme, by theme name.
    Omarchy(String),
    /// Catppuccin palette file, by flavour/file name.
    Catppuccin(String),
    /// Base16/Base24 palette file, by theme/file name.
    Base16(String),
    /// Pywal's colours cache.
    Pywal,
    /// A generic palette file at `~/.config/tsec/palette.{toml,json}`.
    Generic(String),
    /// Terminal environment hints.
    Environment(&'static str),
    /// Nothing was found at all.
    Fallback(&'static str),
}

impl ThemeSource {
    /// One-line label for the STATUS diagnostics box.
    pub fn label(&self) -> String {
        match self {
            ThemeSource::Override(p) => format!("PALETTE {} (override)", upper(p.as_str())),
            ThemeSource::Builtin(p) => format!("PALETTE {}", upper(p.as_str())),
            ThemeSource::Omarchy(name) => format!("OMARCHY {}", upper(name)),
            ThemeSource::Catppuccin(name) => format!("CATPPUCCIN {}", upper(name)),
            ThemeSource::Base16(name) => format!("BASE16 {}", upper(name)),
            ThemeSource::Pywal => "PYWAL".to_string(),
            ThemeSource::Generic(path) => format!("GENERIC PALETTE {path}"),
            ThemeSource::Environment(what) => format!("ENVIRONMENT {what}"),
            ThemeSource::Fallback(why) => format!("FALLBACK ({why})"),
        }
    }

    /// Why the pipeline stopped where it did, when that is not self-evident.
    pub fn reason(&self) -> Option<String> {
        match self {
            ThemeSource::Environment(_) => {
                Some("no theme palette file found; using terminal hints".to_string())
            }
            ThemeSource::Fallback(why) => Some(why.to_string()),
            ThemeSource::Override(_) => Some("TSEC_PALETTE override in effect".to_string()),
            _ => None,
        }
    }
}

fn upper(s: &str) -> String {
    s.to_uppercase()
}

/// Result of a successful detection: source, external palette, and the
/// built-in family closest to it (kept for display and as a colour fallback).
#[derive(Debug, Clone)]
pub struct Detected {
    pub source: ThemeSource,
    pub palette: Option<SemanticPalette>,
    pub closest: PaletteName,
}

/// Run the whole detection chain once.
pub fn detect() -> Detected {
    // 1. Explicit override.
    if let Ok(value) = std::env::var("TSEC_PALETTE") {
        if let Some(p) = PaletteName::from_name(&value) {
            return Detected {
                source: ThemeSource::Override(p),
                palette: None,
                closest: p,
            };
        }
    }

    // 2. Omarchy — the active desktop on the development host.
    if let Some((name, palette)) = omarchy_palette() {
        let closest = closest_builtin(&palette);
        return Detected {
            source: ThemeSource::Omarchy(name),
            palette: Some(palette),
            closest,
        };
    }

    // 3. Catppuccin palette data.
    if let Some((name, palette)) = first_palette_file(&catppuccin_dirs(), &["toml", "json"]) {
        let closest = closest_builtin(&palette);
        return Detected {
            source: ThemeSource::Catppuccin(name),
            palette: Some(palette),
            closest,
        };
    }

    // 4. Base16/Base24 palette data.
    if let Some((name, palette)) = base16_palette() {
        let closest = closest_builtin(&palette);
        return Detected {
            source: ThemeSource::Base16(name),
            palette: Some(palette),
            closest,
        };
    }

    // 5. Pywal cache.
    if let Some(palette) = pywal_palette() {
        let closest = closest_builtin(&palette);
        return Detected {
            source: ThemeSource::Pywal,
            palette: Some(palette),
            closest,
        };
    }

    // 6. Generic operator palette file.
    let generic_dirs = vec![config_home().join("tsec")];
    if let Some((name, palette)) = first_palette_file(&generic_dirs, &["toml", "json"]) {
        let closest = closest_builtin(&palette);
        return Detected {
            source: ThemeSource::Generic(name),
            palette: Some(palette),
            closest,
        };
    }

    // 7. Terminal environment hints, when they actually say something.
    if let Ok(fgbg) = std::env::var("COLORFGBG") {
        if let Some(bg) = fgbg.split(';').nth(1) {
            if bg.parse::<u32>().map(|n| n >= 7).unwrap_or(false) {
                return Detected {
                    source: ThemeSource::Environment("COLORFGBG"),
                    palette: None,
                    closest: PaletteName::SolarizedLight,
                };
            }
        }
    }
    if std::env::var("TERM")
        .map(|t| t.contains("light"))
        .unwrap_or(false)
    {
        return Detected {
            source: ThemeSource::Environment("TERM"),
            palette: None,
            closest: PaletteName::SolarizedLight,
        };
    }

    // 8. Curated fallback.
    Detected {
        source: ThemeSource::Fallback("no palette source found"),
        palette: None,
        closest: PaletteName::Midnight,
    }
}

/// The built-in family whose background brightness matches an external palette.
fn closest_builtin(palette: &SemanticPalette) -> PaletteName {
    if is_light(palette.background) {
        PaletteName::SolarizedLight
    } else {
        PaletteName::Midnight
    }
}

/// True when a colour is a light background (perceptual luminance).
pub fn is_light(color: PaletteColor) -> bool {
    match color {
        PaletteColor::Rgb(r, g, b) => {
            // Rec. 601 luma; good enough to tell a light theme from a dark one.
            (0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32) > 128.0
        }
        PaletteColor::Index(i) => {
            let (r, g, b) = crate::ui::theme::xterm256_rgb(i);
            is_light(PaletteColor::Rgb(r, g, b))
        }
        PaletteColor::Ansi(i) => i == 7 || i >= 15,
        PaletteColor::Default => false,
    }
}

// ── paths ──────────────────────────────────────────────────────────────────

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn config_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    home().join(".config")
}

fn state_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    home().join(".local/state")
}

fn cache_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    home().join(".cache")
}

fn catppuccin_dirs() -> Vec<PathBuf> {
    vec![config_home().join("catppuccin")]
}

// ── Omarchy ────────────────────────────────────────────────────────────────

/// Read the active Omarchy theme's `colors.toml`.
///
/// Fast path: Omarchy renders the active theme into
/// `~/.local/state/omarchy/current/` (with `theme.name` beside it), which is
/// what the terminal itself imports. Slow path: ask the `omarchy` CLI, which
/// is the documented `omarchy theme current` / `omarchy theme dir <name>`
/// behaviour. Both are verified on the development host.
fn omarchy_palette() -> Option<(String, SemanticPalette)> {
    let state = state_home().join("omarchy/current");
    let name = std::fs::read_to_string(state.join("theme.name"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if let Some(palette) = parse_palette_file(&state.join("theme/colors.toml")) {
        let name = if name.is_empty() {
            "active".to_string()
        } else {
            name
        };
        return Some((name, palette));
    }

    which("omarchy")?;
    let (_, current) = run_capture("omarchy", &["theme", "current"], 3)?;
    let current = current.trim().to_string();
    if current.is_empty() || current.contains(' ') {
        return None;
    }
    let (_, dir) = run_capture("omarchy", &["theme", "dir", &current], 3)?;
    let dir = dir.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    parse_palette_file(Path::new(&dir).join("colors.toml").as_path())
        .map(|palette| (current, palette))
}

// ── Base16 ─────────────────────────────────────────────────────────────────

fn base16_palette() -> Option<(String, SemanticPalette)> {
    let dir = config_home().join("base16");
    let explicit = std::env::var("BASE16_THEME").ok();
    first_palette_file(&[dir], &["toml", "json"])
        .map(|(name, palette)| (explicit.unwrap_or(name), palette))
}

// ── Pywal ──────────────────────────────────────────────────────────────────

fn pywal_palette() -> Option<SemanticPalette> {
    let dir = cache_home().join("wal");
    if let Some(map) = hex_map_from_file(&dir.join("colors.json")) {
        return palette_from_hex_map(&map);
    }
    // `~/.cache/wal/colors`: sixteen hex lines, colour0 first.
    let text = std::fs::read_to_string(dir.join("colors")).ok()?;
    let mut map = BTreeMap::new();
    for (index, line) in text.lines().enumerate().take(16) {
        let line = line.trim();
        if parse_hex(line).is_some() {
            map.insert(format!("color{index}"), line.to_string());
        }
    }
    palette_from_hex_map(&map)
}

// ── generic file probing ───────────────────────────────────────────────────

/// First `*.ext` file in `dirs` whose hex palette parses.
fn first_palette_file(dirs: &[PathBuf], exts: &[&str]) -> Option<(String, SemanticPalette)> {
    for dir in dirs {
        let entries = std::fs::read_dir(dir).ok()?;
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| exts.contains(&e))
                        .unwrap_or(false)
            })
            .collect();
        paths.sort();
        for path in paths {
            if let Some(palette) = parse_palette_file(&path) {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "palette".to_string());
                return Some((name, palette));
            }
        }
    }
    None
}

fn parse_palette_file(path: &Path) -> Option<SemanticPalette> {
    let map = hex_map_from_file(path)?;
    palette_from_hex_map(&map)
}

/// Parse a TOML or JSON file into a lowercase `key → #rrggbb` map.
fn hex_map_from_file(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let ext = path.extension()?.to_str()?;
    match ext {
        "toml" => hex_map_from_toml(&text),
        "json" => hex_map_from_json(&text),
        _ => None,
    }
}

fn hex_map_from_toml(text: &str) -> Option<BTreeMap<String, String>> {
    let value: toml::Value = toml::from_str(text).ok()?;
    let mut map = BTreeMap::new();
    collect_toml(&value, None, &mut map);
    (!map.is_empty()).then_some(map)
}

fn collect_toml(value: &toml::Value, table_key: Option<&str>, out: &mut BTreeMap<String, String>) {
    match value {
        toml::Value::String(s) if parse_hex(s).is_some() => {
            let key = table_key.unwrap_or_default().to_string();
            if !key.is_empty() {
                out.insert(key.to_lowercase(), s.clone());
            }
        }
        toml::Value::Table(table) => {
            for (key, inner) in table {
                match inner {
                    toml::Value::String(s) if parse_hex(s).is_some() => {
                        out.insert(key.to_lowercase(), s.clone());
                    }
                    toml::Value::Table(_) => {
                        // Catppuccin-style `[rosewater] hex = "#…"`.
                        let nested = match key.as_str() {
                            "hex" | "color" | "colour" | "value" => table_key.map(String::from),
                            _ => Some(key.clone()),
                        };
                        if let toml::Value::Table(t) = inner {
                            for (ik, iv) in t {
                                if let toml::Value::String(s) = iv {
                                    if parse_hex(s).is_some() {
                                        let name = match nested.as_deref() {
                                            Some(n) => n.to_string(),
                                            None => ik.clone(),
                                        };
                                        out.insert(name.to_lowercase(), s.clone());
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn hex_map_from_json(text: &str) -> Option<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut map = BTreeMap::new();
    collect_json(&value, None, &mut map);
    (!map.is_empty()).then_some(map)
}

fn collect_json(
    value: &serde_json::Value,
    key_hint: Option<&str>,
    out: &mut BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                match inner {
                    serde_json::Value::String(s) if parse_hex(s).is_some() => {
                        out.insert(key.to_lowercase(), s.clone());
                    }
                    serde_json::Value::Object(_) => collect_json(inner, Some(key), out),
                    _ => {}
                }
            }
        }
        serde_json::Value::String(s) if parse_hex(s).is_some() => {
            if let Some(key) = key_hint {
                out.insert(key.to_lowercase(), s.clone());
            }
        }
        _ => {}
    }
}

// ── palette shapes ─────────────────────────────────────────────────────────

/// Map a hex key/value map onto semantic roles, whichever convention it uses.
///
/// Four shapes are understood, and anything else is rejected rather than
/// half-applied: Omarchy's named colours (`background`, `accent`, …),
/// Catppuccin's flavour palette (`base`, `text`, `mauve`, …), Base16's
/// numbered stages (`base00`…`base0F`), and pywal/16-colour sets
/// (`color0`…`color15`).
pub fn palette_from_hex_map(map: &BTreeMap<String, String>) -> Option<SemanticPalette> {
    if map.contains_key("color0") || map.contains_key("special.background") {
        return sixteen_shape(map);
    }
    if map.contains_key("base00") || map.contains_key("base0f") {
        return base16_shape(map);
    }
    if map.contains_key("base") && map.contains_key("text") {
        return catppuccin_shape(map);
    }
    if map.contains_key("background") && map.contains_key("foreground") {
        return omarchy_shape(map);
    }
    None
}

fn hex_of(map: &BTreeMap<String, String>, keys: &[&str]) -> Option<PaletteColor> {
    keys.iter()
        .find_map(|k| map.get(*k))
        .and_then(|v| parse_hex(v))
}

fn omarchy_shape(map: &BTreeMap<String, String>) -> Option<SemanticPalette> {
    let background = hex_of(map, &["background"])?;
    let foreground = hex_of(map, &["foreground"])?;
    let muted = hex_of(map, &["muted", "dark_foreground"]).unwrap_or(foreground);
    Some(SemanticPalette {
        primary: hex_of(map, &["bright_foreground", "foreground"]).unwrap_or(foreground),
        secondary: hex_of(map, &["dark_foreground", "muted"]).unwrap_or(muted),
        accent: hex_of(map, &["accent", "blue"]).unwrap_or(foreground),
        success: hex_of(map, &["green"]).unwrap_or(foreground),
        warning: hex_of(map, &["orange", "yellow"]).unwrap_or(foreground),
        error: hex_of(map, &["red"]).unwrap_or(foreground),
        info: hex_of(map, &["blue", "cyan"]).unwrap_or(foreground),
        muted,
        foreground,
        background,
        border: hex_of(map, &["muted", "dark_foreground", "lighter_background"]).unwrap_or(muted),
        highlight: hex_of(map, &["selection", "lighter_background"]).unwrap_or(muted),
    })
}

fn catppuccin_shape(map: &BTreeMap<String, String>) -> Option<SemanticPalette> {
    let background = hex_of(map, &["base"])?;
    let foreground = hex_of(map, &["text"])?;
    let muted = hex_of(map, &["overlay1", "overlay0", "subtext0"]).unwrap_or(foreground);
    Some(SemanticPalette {
        primary: foreground,
        secondary: hex_of(map, &["subtext1", "subtext0"]).unwrap_or(foreground),
        accent: hex_of(map, &["mauve", "lavender", "blue"]).unwrap_or(foreground),
        success: hex_of(map, &["green"]).unwrap_or(foreground),
        warning: hex_of(map, &["peach", "yellow"]).unwrap_or(foreground),
        error: hex_of(map, &["red", "maroon"]).unwrap_or(foreground),
        info: hex_of(map, &["blue", "sapphire", "sky"]).unwrap_or(foreground),
        muted,
        foreground,
        background,
        border: hex_of(map, &["surface0", "surface1", "overlay0"]).unwrap_or(muted),
        highlight: hex_of(map, &["surface2", "surface1"]).unwrap_or(muted),
    })
}

fn base16_shape(map: &BTreeMap<String, String>) -> Option<SemanticPalette> {
    let background = hex_of(map, &["base00"])?;
    let foreground = hex_of(map, &["base05"])?;
    let muted = hex_of(map, &["base03"])?;
    Some(SemanticPalette {
        primary: foreground,
        secondary: hex_of(map, &["base04"]).unwrap_or(foreground),
        accent: hex_of(map, &["base0d", "base0e"]).unwrap_or(foreground),
        success: hex_of(map, &["base0b"]).unwrap_or(foreground),
        warning: hex_of(map, &["base0a", "base09"]).unwrap_or(foreground),
        error: hex_of(map, &["base08"]).unwrap_or(foreground),
        info: hex_of(map, &["base0c", "base0d"]).unwrap_or(foreground),
        muted,
        foreground,
        background,
        border: hex_of(map, &["base01", "base02"]).unwrap_or(muted),
        highlight: hex_of(map, &["base02", "base0d"]).unwrap_or(muted),
    })
}

fn sixteen_shape(map: &BTreeMap<String, String>) -> Option<SemanticPalette> {
    let background = hex_of(map, &["special.background", "color0"])?;
    let foreground = hex_of(map, &["special.foreground", "color7"])?;
    let muted = hex_of(map, &["color8"]).unwrap_or(foreground);
    let light = is_light(background);
    Some(SemanticPalette {
        primary: foreground,
        secondary: hex_of(map, &["color7"]).unwrap_or(foreground),
        accent: hex_of(map, &["color6", "color4"]).unwrap_or(foreground),
        success: hex_of(map, &["color2"]).unwrap_or(foreground),
        warning: hex_of(map, &["color3"]).unwrap_or(foreground),
        error: hex_of(map, &["color1"]).unwrap_or(foreground),
        info: hex_of(map, &["color4"]).unwrap_or(foreground),
        muted,
        foreground,
        background,
        border: muted,
        highlight: if light {
            hex_of(map, &["color7"]).unwrap_or(muted)
        } else {
            hex_of(map, &["color4", "color2"]).unwrap_or(muted)
        },
    })
}

/// Parse `#rgb` or `#rrggbb` (either case, optional leading `#`).
pub fn parse_hex(text: &str) -> Option<PaletteColor> {
    let hex = text.trim().trim_start_matches('#');
    if hex.len() == 3 {
        let expanded: String = hex.chars().flat_map(|c| [c, c]).collect();
        return parse_hex(&expanded);
    }
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(PaletteColor::Rgb(r, g, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn hex_parsing_accepts_both_shorthands() {
        assert_eq!(
            parse_hex("#123456"),
            Some(PaletteColor::Rgb(0x12, 0x34, 0x56))
        );
        assert_eq!(parse_hex("abc"), Some(PaletteColor::Rgb(0xaa, 0xbb, 0xcc)));
        assert_eq!(parse_hex("nope"), None);
        assert_eq!(parse_hex("#12345"), None);
    }

    #[test]
    fn omarchy_colors_toml_maps_to_semantic_roles() {
        // The real shape of `~/.local/state/omarchy/current/theme/colors.toml`.
        let text = r##"
mode = "dark"
accent = "#626262"
selection = "#0d0d0d"
muted = "#5a5a5a"
background = "#121212"
foreground = "#e0e0e0"
dark_foreground = "#adadad"
bright_foreground = "#fafafa"
red = "#8a8a8a"
yellow = "#9e9e9e"
orange = "#949494"
green = "#767676"
cyan = "#767676"
blue = "#626262"
"##;
        let map = hex_map_from_toml(text).unwrap();
        let palette = palette_from_hex_map(&map).unwrap();
        assert_eq!(palette.background, PaletteColor::Rgb(0x12, 0x12, 0x12));
        assert_eq!(palette.foreground, PaletteColor::Rgb(0xe0, 0xe0, 0xe0));
        assert_eq!(palette.accent, PaletteColor::Rgb(0x62, 0x62, 0x62));
        assert_eq!(palette.warning, PaletteColor::Rgb(0x94, 0x94, 0x94));
        assert_eq!(palette.highlight, PaletteColor::Rgb(0x0d, 0x0d, 0x0d));
        assert!(!is_light(palette.background));
    }

    #[test]
    fn catppuccin_shape_recognises_section_hex_entries() {
        let text = r##"
flavour = "mocha"
[rosewater]
name = "Rosewater"
hex = "#f5e0dc"
[base]
name = "Base"
hex = "#1e1e2e"
[text]
name = "Text"
hex = "#cdd6f4"
[green]
name = "Green"
hex = "#a6e3a1"
[red]
name = "Red"
hex = "#f38ba8"
[mauve]
name = "Mauve"
hex = "#cba6f7"
[surface0]
name = "Surface0"
hex = "#313244"
[overlay1]
name = "Overlay1"
hex = "#7f849c"
"##;
        let map = hex_map_from_toml(text).unwrap();
        assert!(map.contains_key("rosewater"), "{map:?}");
        assert!(
            map.contains_key("base") && map.contains_key("text"),
            "{map:?}"
        );
        let palette = palette_from_hex_map(&map).unwrap();
        assert_eq!(palette.background, PaletteColor::Rgb(0x1e, 0x1e, 0x2e));
        assert_eq!(palette.error, PaletteColor::Rgb(0xf3, 0x8b, 0xa8));
        assert_eq!(palette.success, PaletteColor::Rgb(0xa6, 0xe3, 0xa1));
    }

    #[test]
    fn base16_shape_uses_the_numbered_stages() {
        let mut m = BTreeMap::new();
        for (i, hex) in [
            "#181818", "#282828", "#383838", "#585858", "#b8b8b8", "#d8d8d8", "#e8e8e8", "#f8f8f8",
            "#ab4642", "#dc9656", "#f7ca88", "#a1b56c", "#86c1b9", "#7cafc2", "#ba8baf", "#a1694f",
        ]
        .iter()
        .enumerate()
        {
            m.insert(format!("base{i:02x}"), hex.to_string());
        }
        let palette = palette_from_hex_map(&m).unwrap();
        assert_eq!(palette.background, PaletteColor::Rgb(0x18, 0x18, 0x18));
        assert_eq!(palette.error, PaletteColor::Rgb(0xab, 0x46, 0x42));
        assert_eq!(palette.success, PaletteColor::Rgb(0xa1, 0xb5, 0x6c));
    }

    #[test]
    fn pywal_json_shape_maps_sixteen_colours() {
        let text = r##"{
            "special": {"background": "#1a1a1a", "foreground": "#f0f0f0", "cursor": "#f0f0f0"},
            "colors": {"color0": "#1a1a1a", "color1": "#cc0403", "color2": "#19cb00",
                       "color3": "#f8ca00", "color4": "#1793d1", "color5": "#a23cf0",
                       "color6": "#0f9e9e", "color7": "#f0f0f0", "color8": "#767676",
                       "color9": "#e3191c", "color10": "#2fe022", "color11": "#ffdd33",
                       "color12": "#3fa9f5", "color13": "#c977e5", "color14": "#20d5d5",
                       "color15": "#ffffff"}
        }"##;
        let map = hex_map_from_json(text).unwrap();
        let palette = palette_from_hex_map(&map).unwrap();
        assert_eq!(palette.background, PaletteColor::Rgb(0x1a, 0x1a, 0x1a));
        assert_eq!(palette.error, PaletteColor::Rgb(0xcc, 0x04, 0x03));
        assert_eq!(palette.success, PaletteColor::Rgb(0x19, 0xcb, 0x00));
        assert_eq!(palette.highlight, PaletteColor::Rgb(0x17, 0x93, 0xd1));
    }

    #[test]
    fn an_unrecognised_palette_shape_is_rejected() {
        let m = map(&[("brand", "#123456")]);
        assert!(palette_from_hex_map(&m).is_none());
    }

    #[test]
    fn builtin_source_labels_are_uppercase_for_display() {
        assert_eq!(
            ThemeSource::Omarchy("ash".into()).label(),
            "OMARCHY ASH".to_string()
        );
        assert_eq!(
            ThemeSource::Builtin(PaletteName::Graphite).label(),
            "PALETTE GRAPHITE".to_string()
        );
        assert!(ThemeSource::Fallback("no palette source found")
            .reason()
            .is_some());
    }

    #[test]
    fn light_backgrounds_are_detected_by_luminance() {
        assert!(is_light(PaletteColor::Rgb(240, 240, 240)));
        assert!(!is_light(PaletteColor::Rgb(18, 18, 18)));
    }
}
