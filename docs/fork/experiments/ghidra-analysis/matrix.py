"""Run the Ghidra startup/analysis experiment matrix and summarize it.

Usage: python3 -I matrix.py MODE...
  modes: base t1 t2 floor cds-dump cds-jdk cds-app jit
Env:   GHIDRA_INSTALL_DIR, JAVA_HOME (required)
       EXP_GAME_DIR  directory holding INFO.EXE, INSTALL.EXE, SC2K.EXE
       EXP_OUT_DIR   private output directory (default: $TMPDIR/rea-ghidra-exp)
       REPEATS       runs per cell (default 3)
Writes one JSON line per run to $EXP_OUT_DIR/results.jsonl and prints a summary.
Target bytes are read in place and never copied into the output directory.
"""

import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAME = Path(os.environ.get("EXP_GAME_DIR", "/Applications/SimCity™ 2000 Special Edition.app/Contents/Resources/game"))
TARGETS = {"INFO": GAME / "INFO.EXE", "INSTALL": GAME / "INSTALL.EXE", "SC2K-stub": GAME / "SC2K.EXE"}
REPEATS = int(os.environ.get("REPEATS", "3"))
OUT = Path(os.environ.get("EXP_OUT_DIR", Path(os.environ.get("TMPDIR", "/tmp")) / "rea-ghidra-exp"))
CDS_ARCHIVE = OUT / "ghidra-app.jsa"

T1 = ["Decompiler Switch Analysis"]
T2 = T1 + ["Apply Data Archives", "Stack", "Embedded Media", "Demangler GNU", "Function ID",
           "Non-Returning Functions - Discovered", "Shared Return Calls"]


def env_for(mode):
    env = dict(os.environ)
    env["PATH"] = env["JAVA_HOME"] + "/bin:" + env["PATH"]
    env.pop("JAVA_TOOL_OPTIONS", None)
    env.pop("GHIDRA_HEADLESS_JAVA_OPTIONS", None)
    # analyzeHeadless appends GHIDRA_HEADLESS_JAVA_OPTIONS after its own
    # "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2"; later JVM flags win.
    # Ghidra's launch.properties passes -Xshare:off; these re-enable sharing.
    if mode == "cds-dump":
        env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"-Xshare:auto -XX:ArchiveClassesAtExit={CDS_ARCHIVE} -Xlog:cds=warning"
    elif mode == "cds-jdk":
        env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = "-Xshare:auto"
    elif mode == "cds-app":
        env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"-Xshare:auto -XX:SharedArchiveFile={CDS_ARCHIVE}"
    elif mode == "jit":
        cpus = os.cpu_count() or 8
        env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"-XX:ParallelGCThreads={cpus} -XX:CICompilerCount={max(2, cpus // 2)}"
    return env


def run(mode, name, target, index):
    env = env_for(mode)
    label = f"{mode}-{name}-{index}"
    out = OUT
    out.mkdir(parents=True, exist_ok=True)
    project = OUT / f"proj-{label}-{os.getpid()}-{time.time_ns()}"
    project.mkdir()
    args = [env["GHIDRA_INSTALL_DIR"] + "/support/analyzeHeadless", str(project), "p",
            "-import", str(target), "-loader", "MzLoader", "-processor", "x86:LE:16:Real Mode",
            "-cspec", "default", "-deleteProject", "-log", str(out / f"{label}.log"),
            "-scriptPath", str(HERE)]
    if mode == "floor":
        args.append("-noanalysis")
    if mode in ("t1", "t2"):
        args += ["-preScript", "ExpDisableAnalyzers.java", *(T1 if mode == "t1" else T2)]
    args += ["-postScript", "ExpQualityCounts.java"]
    start = time.monotonic()
    proc = subprocess.run(args, env=env, capture_output=True, text=True)
    wall = time.monotonic() - start
    text = proc.stdout + proc.stderr + (out / f"{label}.log").read_text(errors="replace")
    (out / f"{label}.stdout").write_text(proc.stdout + proc.stderr)
    startup = re.search(r"Headless startup complete \((\d+) ms\)", text)
    total = re.search(r"Total Time\s+(\d+) secs", text)
    counts = re.search(r"EXPCOUNTS (.*)", text)
    analyzers = {m.group(1).strip(): float(m.group(2))
                 for m in re.finditer(r"^\s{4}(\S.*?)\s{2,}([\d.]+) secs", text, re.M)}
    row = {
        "mode": mode, "target": name, "run": index, "exit": proc.returncode,
        "wall_s": round(wall, 2),
        "startup_ms": int(startup.group(1)) if startup else None,
        "analysis_total_s": int(total.group(1)) if total else None,
        "decompiler_switch_s": analyzers.get("Decompiler Switch Analysis"),
        "analyzers_sum_s": round(sum(analyzers.values()), 3) if analyzers else None,
        "exceptions": len(re.findall(r"Unexpected Exception", text)),
        "counts": dict(kv.split("=", 1) for kv in counts.group(1).split() if "=" in kv) if counts else None,
        "cds_warning": bool(re.search(r"(?i)sharing.*(disabled|mismatch|error)|could not .*archive", text)),
    }
    with (out / "results.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")
    return row


def main():
    modes = sys.argv[1:]
    for mode in modes:
        if mode == "cds-dump":
            print(json.dumps(run(mode, "INSTALL", TARGETS["INSTALL"], 0)))
            continue
        for name, target in TARGETS.items():
            rows = [run(mode, name, target, i) for i in range(REPEATS)]
            walls = [r["wall_s"] for r in rows]
            print(f"{mode:6} {name:10} wall median={statistics.median(walls):6.2f}s "
                  f"min={min(walls):6.2f} max={max(walls):6.2f} "
                  f"startup_ms={[r['startup_ms'] for r in rows]} "
                  f"switch_s={rows[-1]['decompiler_switch_s']} exc={rows[-1]['exceptions']} "
                  f"counts={rows[-1]['counts']} exit={[r['exit'] for r in rows]}", flush=True)


if __name__ == "__main__":
    main()
