#!/usr/bin/env python3
"""
IFIRE AI Engine — Anomaly Detection for Network Traffic
=======================================================
Uses Isolation Forest (unsupervised) to detect anomalous source IPs
from the JSON event log produced by the IFIRE sensor.

Sub-commands
------------
  train  <log>   Train a baseline model on known-good traffic
  infer  <log>   Score a log file and print anomalous IPs
  watch  <log>   Continuously monitor a live log file

Usage
-----
  pip install -r requirements.txt
  python3 ifire_ai.py train  /var/log/ifire/baseline.jsonl
  python3 ifire_ai.py infer  /var/log/ifire/ifire.jsonl
  python3 ifire_ai.py watch  /var/log/ifire/ifire.jsonl --interval 30
"""

import argparse
import json
import math
import os
import pickle
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    sys.exit(
        "[IFIRE-AI] Missing packages. Run:  pip install -r requirements.txt"
    )

FEATURE_NAMES = [
    "packets_total",      # raw volume
    "unique_dst_ports",   # port diversity
    "syn_count",          # SYN-only packets
    "rst_count",          # RST packets
    "icmp_count",         # ICMP packets
    "alert_count",        # ALERT-level events
    "block_count",        # BLOCK-level events
    "avg_src_port",       # mean source port (low → scanner)
    "port_entropy",       # Shannon entropy of dst-port distribution
]


# ── feature extraction ────────────────────────────────────────────────────────

def _port_entropy(ports: list) -> float:
    if not ports:
        return 0.0
    counts = Counter(ports)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_features(events_by_ip: dict) -> tuple:
    """Return (list_of_ips, 2D feature array)."""
    ips, rows = [], []
    for ip, events in events_by_ip.items():
        dst_ports, src_ports = [], []
        syn = rst = icmp = alerts = blocks = 0

        for ev in events:
            level = ev.get("level", "INFO")
            etype = ev.get("type", "")

            dst_raw = ev.get("dst", "")
            src_raw = ev.get("src", "")

            parts = dst_raw.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    dst_ports.append(int(parts[1]))
                except ValueError:
                    pass

            parts = src_raw.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    src_ports.append(int(parts[1]))
                except ValueError:
                    pass

            if level == "ALERT":
                alerts += 1
            if level == "BLOCK":
                blocks += 1
            if "SYN" in etype:
                syn += 1
            if "RST" in etype:
                rst += 1
            if "ICMP" in etype or "PING" in etype:
                icmp += 1

        rows.append([
            len(events),
            len(set(dst_ports)),
            syn,
            rst,
            icmp,
            alerts,
            blocks,
            sum(src_ports) / len(src_ports) if src_ports else 0.0,
            _port_entropy(dst_ports),
        ])
        ips.append(ip)

    return ips, rows


def load_log(path: str) -> dict:
    """Read a JSON-lines IFIRE log; group events by source IP."""
    events_by_ip: dict = defaultdict(list)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                src = ev.get("src", "")
                ip = src.rsplit(":", 1)[0] if ":" in src else src
                if ip:
                    events_by_ip[ip].append(ev)
            except json.JSONDecodeError:
                pass
    return dict(events_by_ip)


# ── sub-commands ──────────────────────────────────────────────────────────────

def cmd_train(log_path: str, model_dir: str) -> None:
    print(f"[IFIRE-AI] Training on: {log_path}")
    events = load_log(log_path)
    if not events:
        sys.exit("[IFIRE-AI] No events found in log — cannot train.")

    ips, rows = extract_features(events)
    X = np.array(rows, dtype=float)
    print(f"[IFIRE-AI] {len(ips)} source IPs · {X.shape[1]} features")

    scaler = StandardScaler()
    X_sc = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=300,
        contamination=0.05,   # expect ~5 % of training data to be anomalous
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_sc)

    os.makedirs(model_dir, exist_ok=True)
    out = os.path.join(model_dir, "ifire_model.pkl")
    with open(out, "wb") as fh:
        pickle.dump({"model": model, "scaler": scaler,
                     "features": FEATURE_NAMES}, fh)
    print(f"[IFIRE-AI] Model saved → {out}")


def _run_inference(log_path: str, model_dir: str) -> list:
    model_path = os.path.join(model_dir, "ifire_model.pkl")
    if not os.path.exists(model_path):
        sys.exit(f"[IFIRE-AI] No model at {model_path}. Run 'train' first.")

    with open(model_path, "rb") as fh:
        bundle = pickle.load(fh)
    model: IsolationForest = bundle["model"]
    scaler: StandardScaler = bundle["scaler"]

    events = load_log(log_path)
    if not events:
        print("[IFIRE-AI] No events found.")
        return []

    ips, rows = extract_features(events)
    X = np.array(rows, dtype=float)
    X_sc = scaler.transform(X)
    scores = model.decision_function(X_sc)
    preds = model.predict(X_sc)  # -1 = anomaly, 1 = normal

    header = f"\n{'IP Address':<20} {'Score':>8}  {'Status':<10}  {'Packets':>8}"
    print(header)
    print("-" * len(header))

    flagged = []
    for ip, score, pred, x in sorted(
        zip(ips, scores, preds, X), key=lambda t: t[1]
    ):
        status = "!! ANOMALY" if pred == -1 else "normal"
        if pred == -1:
            flagged.append(ip)
        print(f"{ip:<20} {score:>8.4f}  {status:<10}  {int(x[0]):>8}")

    if flagged:
        print(f"\n[IFIRE-AI] {len(flagged)} anomalous IP(s) detected:")
        for ip in flagged:
            print(f"  >> {ip}")
    else:
        print("\n[IFIRE-AI] No anomalies detected.")

    return flagged


def cmd_infer(log_path: str, model_dir: str) -> None:
    _run_inference(log_path, model_dir)


def cmd_watch(log_path: str, model_dir: str, interval: int) -> None:
    print(f"[IFIRE-AI] Watching {log_path} every {interval}s … (Ctrl+C to stop)")
    last_size = 0
    while True:
        try:
            size = os.path.getsize(log_path)
            if size != last_size:
                last_size = size
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                print(f"\n[IFIRE-AI] {ts} — log updated, running inference …")
                flagged = _run_inference(log_path, model_dir)
                if flagged:
                    print(f"[IFIRE-AI] ACTION: consider blocking {', '.join(flagged)}")
            time.sleep(interval)
        except FileNotFoundError:
            print(f"[IFIRE-AI] Waiting for log file: {log_path}")
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[IFIRE-AI] Stopped.")
            break


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IFIRE AI Anomaly Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # train
    p_train = sub.add_parser("train", help="Train baseline model")
    p_train.add_argument("log", help="Path to IFIRE JSON log (baseline traffic)")
    p_train.add_argument("--model-dir", default="models",
                         help="Directory to save the trained model")

    # infer
    p_infer = sub.add_parser("infer", help="Detect anomalies in log file")
    p_infer.add_argument("log", help="Path to IFIRE JSON log")
    p_infer.add_argument("--model-dir", default="models")

    # watch
    p_watch = sub.add_parser("watch", help="Monitor a live log file")
    p_watch.add_argument("log", help="Path to IFIRE JSON log")
    p_watch.add_argument("--model-dir", default="models")
    p_watch.add_argument("--interval", type=int, default=30,
                         help="Seconds between checks (default 30)")

    args = parser.parse_args()

    if args.cmd == "train":
        cmd_train(args.log, args.model_dir)
    elif args.cmd == "infer":
        cmd_infer(args.log, args.model_dir)
    elif args.cmd == "watch":
        cmd_watch(args.log, args.model_dir, args.interval)


if __name__ == "__main__":
    main()
