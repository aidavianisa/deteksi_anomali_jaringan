# realtime_analyzer.py
import subprocess
import pandas as pd
import numpy as np
import re

def list_tshark_interfaces():
    """
    Kembalikan list baris output 'tshark -D' seperti:
    ['1. \\Device\\NPF_{...} (Ethernet)', '2. ...']
    """
    try:
        out = subprocess.check_output(["tshark", "-D"], text=True, stderr=subprocess.STDOUT)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return lines
    except Exception as e:
        return []

def _parse_interface_index(interface_str):
    """
    Terima string pilihan dari UI (baris dari tshark -D),
    kembalikan index integer (sebagai string) yang dapat dipakai tshark -i.
    Jika interface_str adalah angka saja, kembalikan itu.
    """
    if not interface_str:
        return None
    # coba ambil angka di awal "1." atau "1"
    m = re.match(r"\s*([0-9]+)", interface_str)
    if m:
        return m.group(1)
    # kalau pengguna memasukkan nama device, tshark bisa menerima name; return as-is
    return interface_str

def capture_live_packets(interface_selection, duration=5, max_packets=200):
    """
    Tangkap paket pakai tshark CLI (stabil di Windows).
    interface_selection: baris string dari tshark -D (mis. "1. \\Device... (Ethernet)")
    duration: durasi capture (detik)
    max_packets: batas paket
    Return: DataFrame dengan kolom:
      time, packet_length, src, dst, protocol, inter_arrival_time, throughput, jitter
    Jika gagal, return empty DataFrame.
    """
    idx = _parse_interface_index(interface_selection)
    if not idx:
        return pd.DataFrame()

    # gunakan tshark fields; header=Y akan menyertakan header line
    cmd = [
        "tshark",
        "-i", idx,
        "-a", f"duration:{duration}",
        "-c", str(max_packets),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=duration + 5)
    except subprocess.CalledProcessError as e:
        # tshark returned non-zero exit code (can still have output)
        out = e.output if hasattr(e, "output") else ""
    except Exception:
        return pd.DataFrame()

    lines = [ln for ln in out.splitlines() if ln.strip()]
    if not lines:
        return pd.DataFrame()

    # If header present, skip first line if it contains "frame.time_epoch"
    if "frame.time_epoch" in lines[0].lower():
        lines = lines[1:]

    records = []
    for ln in lines:
        parts = ln.split(",", maxsplit=4)
        # ensure length 5
        while len(parts) < 5:
            parts.append("")
        try:
            t = float(parts[0]) if parts[0] else np.nan
        except:
            t = np.nan
        try:
            length = int(parts[1]) if parts[1] else 0
        except:
            length = 0
        src = parts[2].strip() if parts[2] else ""
        dst = parts[3].strip() if parts[3] else ""
        proto = parts[4].strip() if parts[4] else ""
        records.append((t, length, src, dst, proto))

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records, columns=["time", "packet_length", "src", "dst", "protocol"])
    df = df.dropna(subset=["time"])
    df = df.sort_values("time").reset_index(drop=True)

    # features
    df["inter_arrival_time"] = df["time"].diff().fillna(0)
    # throughput: bytes per second using rolling window 5 (safe)
    df["throughput"] = df["packet_length"].rolling(window=5, min_periods=1).sum() / (
        df["inter_arrival_time"].replace(0, np.nan).rolling(window=5, min_periods=1).sum().replace(0, np.nan)
    )
    df["throughput"] = df["throughput"].fillna(0)
    df["jitter"] = df["inter_arrival_time"].diff().abs().fillna(0)
    df["jitter"] = df["jitter"].fillna(0)

    return df
