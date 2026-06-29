//! Terminal theme: colours, box drawing, banner, helpers.

use crossterm::{
    event::{read, Event},
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::io::{self, Write};
use unicode_width::UnicodeWidthStr;

// ── Colour helpers ─────────────────────────────────────────────────────────

#[inline] pub fn green()  -> Color { Color::Rgb { r: 0,   g: 220, b: 100 } }
#[inline] pub fn bright_green() -> Color { Color::Rgb { r: 0, g: 255, b: 80 } }
#[inline] pub fn aqua()   -> Color { Color::Rgb { r: 0,   g: 200, b: 200 } }
#[inline] pub fn red()    -> Color { Color::Red }
#[inline] pub fn white()  -> Color { Color::Rgb { r: 0, g: 255, b: 80 } } // Replaced with bright green for pure green/black look
#[inline] pub fn grey()   -> Color { Color::DarkGrey }
#[inline] pub fn yellow() -> Color { Color::Rgb { r: 230, g: 200, b: 0   } }

/// Write `text` in `colour` then reset (no newline).
pub fn cprint(colour: Color, text: &str) {
    let mut out = io::stdout();
    let _ = execute!(out, SetForegroundColor(colour), Print(text), ResetColor);
}

/// Write `text` in `colour` then reset with a newline.
pub fn cprintln(colour: Color, text: &str) {
    cprint(colour, text);
    println!();
}

/// Return the current terminal column width (fallback: 80).
pub fn terminal_width() -> usize {
    crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(80)
}

// ── Banner ─────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn draw_banner() {
    draw_banner_with_anon(&crate::config::settings::Anonymity::default());
}

/// Draw the startup banner with anonymity status indicators.
/// Adapts to terminal width and uses the same box-drawing style as
/// every other panel in the UI.
pub fn draw_banner_with_anon(anon: &crate::config::settings::Anonymity) {
    let inner = terminal_width().saturating_sub(2).max(40);

    let top    = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));
    let mid    = format!("╠{}╣", "═".repeat(inner));

    // ── Helper: centre a string inside ║...║ ───────────────────────────
    let centre_row = |text: &str, colour: Color| {
        let tw = UnicodeWidthStr::width(text);
        let pad = inner.saturating_sub(tw);
        let lp = pad / 2;
        let rp = pad - lp;
        cprint(green(), "║");
        cprint(colour, &format!("{}{}{}", " ".repeat(lp), text, " ".repeat(rp)));
        cprintln(green(), "║");
    };

    // ── Helper: left-aligned status row inside ║...║ ──────────────────
    let status_row = |text: &str, colour: Color| {
        let tw = UnicodeWidthStr::width(text);
        let pad = inner.saturating_sub(tw + 2); // 2 = leading "  "
        cprint(green(), "║");
        cprint(colour, &format!("  {}{}", text, " ".repeat(pad)));
        cprintln(green(), "║");
    };

    // Title centred
    let title = "TSEC";

    // Subtitle centred
    let sub = "Framework";

    cprintln(green(), &top);
    centre_row(title, bright_green());
    centre_row(sub, aqua());
    cprintln(green(), &mid);

    // ── Anonymity status block ─────────────────────────────────────────
    if anon.enabled {
        let shield = "ANONYMITY: ON";
        centre_row(shield, bright_green());
        cprintln(green(), &mid);

        // Tor status
        if anon.tor_enabled {
            let tor = crate::anonymity::tor::TorManager::new(&anon.tor_socks_addr);
            if tor.is_running() {
                status_row("Tor: Connected", bright_green());
                let ip_text = format!("IP: {}", crate::anonymity::tor::TorManager::get_cached_ip());
                status_row(&ip_text, bright_green());
            } else {
                status_row("Tor: NOT RUNNING", red());
            }
        } else {
            status_row("Tor: Disabled", grey());
        }

        // Proxy status
        if !anon.proxy_pool.is_empty() {
            let proxy_text = format!("Proxies: {} configured", anon.proxy_pool.len());
            status_row(&proxy_text, bright_green());
        } else {
            status_row("Proxies: None", grey());
        }

        // ProxyChains
        if anon.use_proxychains {
            if crate::anonymity::stealth::proxychains_available() {
                status_row("ProxyChains: Active", bright_green());
            } else {
                status_row("ProxyChains: NOT INSTALLED", red());
            }
        }

        // DNS-over-HTTPS
        if anon.dns_over_https {
            status_row("DNS-over-HTTPS: Active", bright_green());
        }

        // MAC spoofing
        if anon.mac_spoofing {
            status_row("MAC Spoofing: Enabled", bright_green());
        }

        // Hostname spoofing
        if anon.hostname_spoofing {
            status_row("Hostname Spoofing: Enabled", bright_green());
        }

        // Kill switch
        if anon.kill_switch {
            status_row("Kill Switch: Armed", bright_green());
        }

        cprintln(green(), &mid);
    } else {
        let shield = "OFF";
        centre_row(shield, grey());
        cprintln(green(), &mid);
    }

    // Tip bar
    let tip = "  ↑↓ or j,k ⇒ navigate   Enter ⇒ select   q ⇒ back   x ⇒ exit  ";
    centre_row(tip, grey());
    cprintln(green(), &bottom);
    println!();
}

// ── Generic info/result box ────────────────────────────────────────────────

/// Full-width green box with an optional centred title.
pub fn print_box(title: &str, lines: &[&str]) {
    let inner = terminal_width().saturating_sub(2).max(40);

    let top = format!("╔{}╗", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));

    cprintln(green(), &top);

    if !title.is_empty() {
        let tw = UnicodeWidthStr::width(title);
        let pad = inner.saturating_sub(tw);
        let lpad = pad / 2;
        let rpad = pad - lpad;
        let mid = format!("╠{}╣", "═".repeat(inner));
        cprint(green(), "║");
        cprint(aqua(),  &format!("{}{}{}", " ".repeat(lpad), title, " ".repeat(rpad)));
        cprintln(green(), "║");
        cprintln(green(), &mid);
    }

    // text_cols: inner - 2 (for "║ " and " ║")
    let text_cols = inner.saturating_sub(2);
    for l in lines {
        let lw = UnicodeWidthStr::width(*l);
        let padding = if lw < text_cols { text_cols - lw } else { 0 };
        cprint(green(), "║ ");
        cprint(white(), l);
        cprint(white(), &" ".repeat(padding));
        cprintln(green(), " ║");
    }

    cprintln(green(), &bot);
}

// ── Status helpers ─────────────────────────────────────────────────────────

pub fn print_error(msg: &str) {
    println!();
    let inner = terminal_width().saturating_sub(2).max(40);
    let text_cols = inner.saturating_sub(2);
    let top = format!("╔{}╗", "═".repeat(inner));
    let mid = format!("╠{}╣", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));

    let _ = execute!(io::stdout(), SetForegroundColor(red()));
    println!("{}", top);
    let hdr = " ERROR ";
    let hw = UnicodeWidthStr::width(hdr);
    let hpad = inner.saturating_sub(hw);
    println!("║{}{}{}║", " ".repeat(hpad / 2), hdr, " ".repeat(hpad - hpad / 2));
    println!("{}", mid);
    for l in msg.lines() {
        let lw = UnicodeWidthStr::width(l);
        let pad = if lw < text_cols { text_cols - lw } else { 0 };
        println!("║ {}{} ║", l, " ".repeat(pad));
    }
    println!("{}", bot);
    let _ = execute!(io::stdout(), ResetColor);
    println!();
}

pub fn print_success(msg: &str) {
    println!();
    cprint(green(), "  [OK]  ");
    cprintln(white(), msg);
}

pub fn print_info(msg: &str) {
    cprint(aqua(), "  [i]  ");
    cprintln(white(), msg);
}

pub fn print_warn(msg: &str) {
    cprint(yellow(), "  [!]  ");
    cprintln(white(), msg);
}

/// Boxed coloured section header spanning the terminal width.
pub fn section_header(label: &str) {
    println!();
    let inner = terminal_width().saturating_sub(2).max(40);
    
    let top = format!("╔{}╗", "═".repeat(inner));
    let bot = format!("╚{}╝", "═".repeat(inner));
    
    let lw = UnicodeWidthStr::width(label);
    let pad = inner.saturating_sub(lw);
    let lpad = pad / 2;
    let rpad = pad - lpad;
    
    cprintln(green(), &top);
    cprint(green(), "║");
    cprint(aqua(), &format!("{}{}{}", " ".repeat(lpad), label, " ".repeat(rpad)));
    cprintln(green(), "║");
    cprintln(green(), &bot);
}

/// Strip ANSI escape sequences from a string.
pub fn strip_ansi(s: &str) -> String {
    thread_local! {
        static ANSI_RE: regex::Regex = regex::Regex::new(r"\x1B\[[0-9;?]*[a-zA-Z]|\x1B\(B").unwrap();
    }
    ANSI_RE.with(|re| re.replace_all(s, "").into_owned())
}

/// Strip ANSI escape sequences, expand tabs to spaces, truncate/ellipsize, and pad to target_cols.
pub fn pad_to(s: &str, target_cols: usize) -> String {
    let clean = strip_ansi(s).replace('\t', "    ");
    let w = UnicodeWidthStr::width(clean.as_str());
    if w >= target_cols {
        let mut out = String::new();
        let mut cols = 0usize;
        for c in clean.chars() {
            let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
            if cols + cw > target_cols.saturating_sub(1) {
                out.push('…');
                break;
            }
            out.push(c);
            cols += cw;
        }
        let cur_w = UnicodeWidthStr::width(out.as_str());
        if cur_w < target_cols {
            out.push_str(&" ".repeat(target_cols - cur_w));
        }
        out
    } else {
        format!("{}{}", clean, " ".repeat(target_cols - w))
    }
}


// ── Wait-for-key ───────────────────────────────────────────────────────────

pub fn wait_key() {
    println!();
    cprint(grey(), "  [?] Press any key to continue…");
    let _ = io::stdout().flush();
    let _ = enable_raw_mode();
    loop {
        if matches!(read(), Ok(Event::Key(_))) { break; }
    }
    let _ = disable_raw_mode();
    println!();
}
