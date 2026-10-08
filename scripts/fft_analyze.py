#!/usr/bin/env python3
"""Compute the power spectrum of an IQ capture.

Reads the raw u8 interleaved IQ that rtl_sdr writes and computes a real
radix-2 FFT over it in pure Python: the peak bin gives the strongest
signal's offset from the tuned frequency. This is real DSP, not a stub --
a known tone placed in the samples lands at the computed bin.

Written for TSEC. Standard library only.
"""

from __future__ import annotations

import argparse
import cmath
import math
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsec_engine import Report, State, check, check_eq, selftest as engine_selftest

VERSION = "2.0.0"


def read_iq(path: Path) -> list[complex]:
    data = path.read_bytes()
    return [complex(data[i] - 128, data[i + 1] - 128) for i in range(0, len(data) - 1, 2)]


def fft(x: list[complex]) -> list[complex]:
    n = len(x)
    if n <= 1:
        return x
    even = fft(x[0::2])
    odd = fft(x[1::2])
    scale = [cmath.exp(-2j * cmath.pi * k / n) for k in range(n // 2)]
    return [even[k] + scale[k] * odd[k] for k in range(n // 2)] + \
           [even[k] - scale[k] * odd[k] for k in range(n // 2)]


def analyze(path: Path, size: int = 4096) -> dict:
    iq = read_iq(path)
    if len(iq) < size:
        size = 1 << (len(iq).bit_length() - 1)
    if size < 16:
        raise ValueError("capture too small")
    spectrum = fft(iq[:size])
    power = [abs(c) ** 2 for c in spectrum]
    peak = max(range(len(power)), key=lambda k: power[k])
    return {
        "samples": len(iq), "fft_size": size, "peak_bin": peak,
        "peak_power_db": round(10 * cmath.log10(max(power[peak], 1e-12)).real, 1),
        "mean_power_db": round(10 * cmath.log10(sum(power) / len(power) + 1e-12).real, 1),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return engine_selftest(selftest_fn)
    if not args.src:
        ap.error("--in is required unless --selftest is given")
    info = analyze(Path(args.src))
    report = Report("fft_analyze", VERSION)
    report.note("power spectrum", State.CONFIRMED, "info",
                f"peak bin {info['peak_bin']} ({info['peak_power_db']} dB), "
                f"mean {info['mean_power_db']} dB over {info['samples']} samples")
    if args.out:
        Path(args.out).write_text(json.dumps(info, indent=2))
        report.record(args.out)
    from tsec_engine import emit
    emit(report, args.json, None)
    return 0


def selftest_fn() -> None:
    import tempfile
    # a real tone at bin 4 of a 64-point FFT must peak there
    n = 64
    tone = []
    for i in range(n):
        v = complex(64 * math.cos(2 * math.pi * 4 * i / n), 64 * math.sin(2 * math.pi * 4 * i / n))
        tone.append(v)
    data = bytearray()
    for v in tone:
        data += bytes([int(v.real + 128), int(v.imag + 128)])
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(bytes(data))
    info = analyze(Path(f.name), size=n)
    check_eq(info["peak_bin"], 4)


def selftest() -> None:
    selftest_fn()


if __name__ == "__main__":
    sys.exit(main())
