//! Spinner glyphs for running tasks.
//!
//! The animation has no thread of its own: the execution monitor owns the
//! frame clock, asks for a glyph for the tasks that are genuinely running, and
//! writes exactly one frame per tick. A glyph is only ever drawn for a task
//! whose child process is alive — the moment it exits, the task's terminal
//! status (tick, cross, timeout) takes its place.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::time::Duration;

/// Braille spinner frames, in animation order.
pub const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

/// One animation step. ~12 frames per second: alive, but never flickering.
pub const TICK: Duration = Duration::from_millis(80);

/// The glyph for animation step `tick`.
pub fn frame(tick: usize) -> &'static str {
    FRAMES[tick % FRAMES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_cycle_without_panicking() {
        for tick in 0..100 {
            assert!(!frame(tick).is_empty());
        }
        assert_eq!(frame(0), frame(8));
    }

    #[test]
    fn tick_is_a_sane_refresh_rate() {
        // Between 8 and 20 frames per second.
        let fps = 1_000.0 / TICK.as_millis() as f64;
        assert!((8.0..=20.0).contains(&fps), "{fps}");
    }
}
