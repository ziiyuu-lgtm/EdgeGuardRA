"""Repeat the paper workload in fresh interpreters and retain every raw result."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

from . import __version__
from .environment import collect_environment
from .worked_example import run_worked_example


def summarize_runs(values: list[float], *, seed: int = 20261031,
                   resamples: int = 10000) -> dict:
    """Percentile bootstrap of the mean, resampling whole independent runs."""
    if (not isinstance(values, list) or len(values) < 2 or
        any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values)):
        raise ValueError("at least two finite, non-negative run measurements are required")
    if type(resamples) is not int or not 100 <= resamples <= 100000:
        raise ValueError("bootstrap resamples must be 100..100000")
    rng = random.Random(seed)
    boot = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(resamples))
    return {"runs": len(values), "mean": statistics.mean(values),
            "median": statistics.median(values), "sample_sd": statistics.stdev(values),
            "min": min(values), "max": max(values),
            "bootstrap_mean_ci95": [boot[int(.025 * (resamples - 1))],
                                    boot[int(.975 * (resamples - 1))]],
            "bootstrap_resamples": resamples, "bootstrap_seed": seed}


def _write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def run_reproduction(out_path: str | Path, *, repeats: int = 10,
                     latency_samples: int = 200, figures: bool = False) -> dict:
    """Create a new directory; existing and incomplete output is never overwritten."""
    if type(repeats) is not int or not 2 <= repeats <= 30:
        raise ValueError("repeats must be 2..30")
    if type(latency_samples) is not int or not 10 <= latency_samples <= 5000:
        raise ValueError("latency samples must be 10..5000")
    if type(figures) is not bool:
        raise ValueError("figures must be a boolean")
    if figures:
        try:
            import matplotlib  # noqa: F401; fail before creating output if absent
        except ImportError as exc:
            raise ValueError("install requirements-reproduce.txt to regenerate figures") from exc
    out = Path(out_path).absolute()
    out.mkdir(parents=True, exist_ok=False)
    environment = collect_environment()
    _write_json(out / "environment.json", environment)
    records, summaries = [], []
    package_root = str(Path(__file__).resolve().parent.parent)
    child_env = os.environ.copy()
    # Use this exact installed/source package rather than an unrelated installation.
    child_env["PYTHONPATH"] = package_root + os.pathsep + child_env.get("PYTHONPATH", "")
    for index in range(1, repeats + 1):
        name = f"run-{index:02d}"
        started = time.perf_counter_ns()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "edgeguardra", "evaluate", "--out", str(out / name),
                 "--variants", "3", "--latency-samples", str(latency_samples)],
                env=child_env, capture_output=True, text=True, timeout=900, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"reproduction stopped at {name}; incomplete output retained") from exc
        if result.returncode:
            raise ValueError(f"reproduction stopped at {name}; incomplete output retained")
        summary = json.loads((out / name / "summary.json").read_text(encoding="utf-8"))
        if summary["version"] != __version__:
            raise ValueError("reproduction used a different software version")
        if summaries and any(summary[k] != summaries[0][k] for k in
                             ("source_sha256", "results", "review_evaluation", "cases_per_mode")):
            raise ValueError("source or functional results changed between runs")
        summaries.append(summary)
        row = {"run": index, "elapsed_seconds": (time.perf_counter_ns() - started) / 1e9}
        for key in ("combined_median_us", "combined_p95_us", "combined_p99_us"):
            row[key] = summary["latency"][key]
        for size in ("10", "100", "500"):
            for mode in ("unguarded", "checkpoint"):
                row[f"read_{size}_{mode}_median_us"] = summary["checkpoint_read_latency"]["by_size"][size][mode]["median_us"]
        records.append(row)
    with (out / "repeat_summary.csv").open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    first = summaries[0]
    report = {"version": __version__, "repeats": repeats,
              "latency_samples_per_run": latency_samples,
              "latency_samples_total": repeats * latency_samples,
              "checkpoint_samples_total": repeats * 120,
              "cases_per_mode_per_run": first["cases_per_mode"],
              "functional_results_identical": True,
              "results": first["results"], "review_evaluation": first["review_evaluation"],
              "source_sha256": first["source_sha256"], "environment": environment,
              "statistics_us": {key: summarize_runs([r[key] for r in records])
                                for key in records[0] if key not in ("run", "elapsed_seconds")},
              "method": "Sequential fresh Python processes; fresh temporary databases and keys; 17 archetypes x 3 variants per condition in each run. No timing samples discarded. Percentile bootstrap resamples whole-run summaries, not individual operations.",
              "limits": "One shared Linux host. Intervals describe run-to-run variation conditional on this workload and host; they do not establish population security accuracy, edge-device performance, hard real-time bounds or independence from shared-host interference."}
    _write_json(out / "worked_example.json", run_worked_example())
    if figures:
        from .figures import make_figures
        make_figures(out / "run-01" / "summary.json", out / "figures")
    _write_json(out / "report.json", report)
    # The manifest appears only after every requested output has been generated.
    _write_json(out / "manifest.json", {
        "version": __version__, "complete": True,
        "sha256": {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(out.rglob("*")) if p.is_file()}})
    return report
