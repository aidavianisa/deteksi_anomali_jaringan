import streamlit as st
import pandas as pd
import plotly.express as px
import asyncio, sys, time, base64, os
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import MinMaxScaler
from realtime_analyzer import capture_live_packets, list_tshark_interfaces
import pyshark
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.metrics import silhouette_score, silhouette_samples
import math
import subprocess
import csv
import io

# ===== Konfigurasi awal =====
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

st.set_page_config(page_title="Network Anomaly Detector", layout="wide")
st.title("🌐 Sistem Deteksi Anomali Trafik Jaringan Dengan Metode K-Means Clustering")
st.markdown("**Aida Vianisa** 240401020009")
st.markdown("---")

# ===== Fungsi-fungsi global =====

def shannon_entropy(series):
    """Menghitung entropi Shannon dari suatu series."""
    probs = series.value_counts(normalize=True)
    return -sum(p * math.log2(p) for p in probs if p > 0)

def apply_rolling_throughput(df, window_size=5):
    """
    Menghaluskan throughput dengan moving average (rolling window).
    Digunakan baik pada mode real-time maupun PCAP.
    """
    if df.empty or "throughput_raw" not in df.columns:
        df["throughput"] = 0.0
        return df

    if "time" in df.columns:
        df = df.sort_values("time").reset_index(drop=True)

    # rolling mean
    df["throughput_smooth"] = (
        df["throughput_raw"]
        .rolling(window=window_size, min_periods=1)
        .mean()
    )

    # gunakan smooth sebagai fitur final (ditransformasi log1p)
    df["throughput"] = np.log1p(df["throughput_smooth"])

    return df

def map_clusters_to_labels(df):
    """
    Memberi label pada setiap cluster berdasarkan karakteristiknya.
    Prioritas: Protocol Flood > Port Scan > Traffic Spike > Silence / Drop > Normal.
    """
    if df.empty or "cluster" not in df.columns:
        return {}

    clusters = sorted(df["cluster"].unique())

    # ===== statistik global =====
    pkt_mean = df["packet_length"].mean()
    pkt_std = df["packet_length"].std()

    # ===== statistik per cluster =====
    stats = (
        df.groupby("cluster")
        .agg({
            "throughput": "mean",
            "inter_arrival_time": "mean",
            "jitter_rfc": "mean",
            "packet_length": "mean",
            "dst": "nunique"
        })
    )

    thr_mean = stats["throughput"].mean()
    thr_std = stats["throughput"].std()

    iat_mean = stats["inter_arrival_time"].mean()
    iat_std = stats["inter_arrival_time"].std()

    jit_mean = stats["jitter_rfc"].mean()
    jit_std = stats["jitter_rfc"].std()

    mapping = {c: "Normal" for c in clusters}

    # ================= PRIORITY RULE =================
    for c in clusters:
        sub = df[df["cluster"] == c]
        if sub.empty:
            continue

        label = "Normal"

        # 1️⃣ Protocol Flood
        if "protocol" in sub.columns:
            proto_ratio = sub["protocol"].value_counts(normalize=True).max()
            entropy = shannon_entropy(sub["protocol"])
            avg_pkt_len = stats.loc[c, "packet_length"]
            cluster_iat = stats.loc[c, "inter_arrival_time"]
            
            if proto_ratio > 0.75 and entropy < 1.0 and len(sub) > 20:
                if cluster_iat < iat_mean * 0.6: 
                    if avg_pkt_len < pkt_mean * 1.5:
                        label = "Protocol Flood"

        # 2️⃣ Port Scan
        if label == "Normal" and "dst_port" in sub.columns:
            src_port_counts = sub.groupby("src")["dst_port"].nunique()
            if not src_port_counts.empty:
                # packet length relatif kecil (di bawah rata-rata global)
                if src_port_counts.max() >= max(10, int(0.3 * len(sub))) and stats.loc[c, "packet_length"] < pkt_mean:
                    label = "Port Scan"

        # 3️⃣ Traffic Spike
        if label == "Normal":
            # throughput tinggi (di atas rata-rata + std) dan packet length tinggi (di atas rata-rata)
            if stats.loc[c, "throughput"] > thr_mean + thr_std and stats.loc[c, "packet_length"] > pkt_mean:
                label = "Traffic Spike"

        # 4️⃣ Silence / Drop
        if label == "Normal":
            cond_iat = stats.loc[c, "inter_arrival_time"] > iat_mean + iat_std
            cond_thr = stats.loc[c, "throughput"] < thr_mean - thr_std
            cond_jit = stats.loc[c, "jitter_rfc"] > jit_mean + jit_std
            cond_pkt = stats.loc[c, "packet_length"] < pkt_mean  # packet length kecil
            if cond_iat and cond_thr and cond_jit and cond_pkt:
                label = "Silence / Drop"

        mapping[c] = label

    return mapping

def find_best_k(X_scaled, k_min=2, k_max=6):
    """Menentukan jumlah cluster terbaik berdasarkan silhouette score."""
    best_k = 2
    best_score = -1

    max_k = min(k_max, len(X_scaled) - 1)
    if max_k < 2:
        return 1

    for k in range(k_min, max_k + 1):
        try:
            km = KMeans(n_clusters=k, random_state=42, n_init="auto")
            labels = km.fit_predict(X_scaled)
            if len(set(labels)) < 2:
                continue
            score = silhouette_score(X_scaled, labels)
            if score > best_score:
                best_score = score
                best_k = k
        except:
            continue

    return best_k

def detect_protocol_flood_cluster(df):
    """Deteksi protocol flood tingkat lanjut berdasarkan karakteristik cluster."""
    flagged_clusters = []
    for c in df['cluster'].unique():
        sub = df[df['cluster'] == c]
        if len(sub) < 10:
            continue
        duration = sub["time"].iloc[-1] - sub["time"].iloc[0]
        duration = max(duration, 0.001)
        packet_rate = len(sub) / duration
        proto_counts = sub["protocol"].value_counts()
        if proto_counts.empty:
            continue
        dominance_ratio = proto_counts.max() / len(sub)
        entropy = shannon_entropy(sub["protocol"])
        if packet_rate > 200 and dominance_ratio > 0.7 and entropy < 1.0:
            flagged_clusters.append(c)
    return flagged_clusters

def detect_silence_cluster(df):
    """Deteksi silence/drop tingkat lanjut berdasarkan karakteristik cluster."""
    flagged_clusters = []
    thr_mean = df["throughput"].mean()
    thr_std = df["throughput"].std()
    iat_mean = df["inter_arrival_time"].mean()
    iat_std = df["inter_arrival_time"].std()
    for c in df['cluster'].unique():
        sub = df[df['cluster'] == c]
        if sub.empty:
            continue
        cluster_thr = sub["throughput"].mean()
        cluster_iat = sub["inter_arrival_time"].mean()
        if cluster_thr < (thr_mean - thr_std) and cluster_iat > (iat_mean + iat_std):
            flagged_clusters.append(c)
    return flagged_clusters

def init_adaptive_state(alpha=0.2, z_threshold=3.0, min_history=3):
    """Inisialisasi state untuk deteksi anomali adaptif (EWMA + z-score)."""
    if "adaptive" not in st.session_state:
        st.session_state.adaptive = {
            "alpha": alpha,
            "z_threshold": z_threshold,
            "min_history": min_history,
            "metrics": {
                "throughput": {"mean": 0.0, "var": 0.0, "count": 0},
                "jitter": {"mean": 0.0, "var": 0.0, "count": 0},
                "packet_count": {"mean": 0.0, "var": 0.0, "count": 0},
            },
            "ip_stats": {}
        }

def update_ewma(metric_state, value, alpha):
    """Update rata-rata dan varian secara eksponensial (EWMA), kembalikan z-score."""
    eps = 1e-9
    count = metric_state.get("count", 0)
    mu = metric_state.get("mean", 0.0)
    var = metric_state.get("var", 0.0)

    std = (var ** 0.5) if var > 0 else 0.0
    z = (value - mu) / (std + eps) if count >= 1 else 0.0

    if count == 0:
        mu_new = value
        var_new = 0.0
        count_new = 1
    else:
        mu_new = alpha * value + (1 - alpha) * mu
        diff = value - mu_new
        var_new = alpha * (diff ** 2) + (1 - alpha) * var
        count_new = count + 1

    metric_state["mean"] = float(mu_new)
    metric_state["var"] = float(var_new)
    metric_state["count"] = int(count_new)

    return z

def detect_adaptive_anomaly(batch_metrics, df_packets, history_df):
    """Deteksi anomali adaptif berdasarkan EWMA dan z-score."""
    anomalies = []
    now = time.strftime("%H:%M:%S")
    st_adapt = st.session_state.get("adaptive", None)
    if not st_adapt:
        init_adaptive_state()
        st_adapt = st.session_state["adaptive"]

    alpha = st_adapt["alpha"]
    z_threshold = st_adapt["z_threshold"]
    min_hist = st_adapt["min_history"]

    packet_count = batch_metrics.get("packet_count", 0)
    throughput = batch_metrics.get("throughput", 0.0)   # throughput agregat (bps)
    jitter = batch_metrics.get("jitter", 0.0)           # jitter agregat (nilai terakhir batch) (ms)
    src_counts = batch_metrics.get("src_counts", None)

    z_thr = update_ewma(st_adapt["metrics"]["throughput"], throughput, alpha)
    if st_adapt["metrics"]["throughput"]["count"] >= min_hist and abs(z_thr) >= z_threshold:
        suspect_ip = src_counts.idxmax() if src_counts is not None and not src_counts.empty else "Unknown"
        anomalies.append({
            "time": now,
            "jenis": "Adaptive Traffic Spike",
            "ip": suspect_ip,
            "alasan": f"Throughput z={z_thr:.2f}",
            "nilai": f"{throughput:.2f} bps",
            "score": float(abs(z_thr))
        })

    z_jit = update_ewma(st_adapt["metrics"]["jitter"], jitter, alpha)
    if st_adapt["metrics"]["jitter"]["count"] >= min_hist and abs(z_jit) >= z_threshold:
        suspect_ip = src_counts.idxmax() if src_counts is not None and not src_counts.empty else "Unknown"
        anomalies.append({
            "time": now,
            "jenis": "Adaptive High Jitter",
            "ip": suspect_ip,
            "alasan": f"Jitter z={z_jit:.2f}",
            "nilai": f"{jitter:.4f} ms",
            "score": float(abs(z_jit))
        })

    z_pkt = update_ewma(st_adapt["metrics"]["packet_count"], float(packet_count), alpha)
    if st_adapt["metrics"]["packet_count"]["count"] >= min_hist and abs(z_pkt) >= z_threshold:
        suspect_ip = src_counts.idxmax() if src_counts is not None and not src_counts.empty else "Unknown"
        anomalies.append({
            "time": now,
            "jenis": "Adaptive Packet Count Spike",
            "ip": suspect_ip,
            "alasan": f"Packet count z={z_pkt:.2f}",
            "nilai": f"{packet_count} pkt",
            "score": float(abs(z_pkt))
        })

    proto_counts = df_packets["protocol"].value_counts() if "protocol" in df_packets.columns else pd.Series()
    for proto, cnt in proto_counts.items():
        if cnt >= max(50, int(st_adapt.get("protocol_flood_threshold", 50))):
            suspect_ip = df_packets[df_packets["protocol"] == proto]["src"].value_counts().idxmax() if not df_packets[df_packets["protocol"] == proto].empty else "Unknown"
            anomalies.append({
                "time": now,
                "jenis": "Protocol Flood",
                "ip": suspect_ip,
                "alasan": f"{cnt} paket {proto}",
                "nilai": f"{cnt} pkt",
                "score": float(cnt)
            })

    return anomalies

def analyze_anomalies(df, history, spike_factor=2.0, delay_threshold_ms=100.0, protocol_flood_count=50, portscan_ports=10):
    """Deteksi anomali dasar berdasarkan aturan sederhana."""
    anomalies = []
    now = time.strftime("%H:%M:%S")

    if df.empty:
        return anomalies

    duration = df["time"].iloc[-1] - df["time"].iloc[0] if len(df) > 1 else 0.001
    batch_throughput = df["packet_length"].sum() * 8 / (duration + 1e-9)  # throughput agregat (bps)

    prev_thr = history["throughput_avg"].mean() if not history.empty else 0.0  # throughput agregat history (bps)
    if prev_thr > 0 and batch_throughput > prev_thr * spike_factor:
        src_bytes = df.groupby("src")["packet_length"].sum().sort_values(ascending=False)
        suspect_ip = src_bytes.index[0] if not src_bytes.empty else "Unknown"
        anomalies.append({
            "time": now,
            "jenis": "Traffic Spike",
            "ip": suspect_ip,
            "alasan": f"Throughput naik >{spike_factor}x (sebelum {prev_thr:.1f} bps, sekarang {batch_throughput:.1f} bps)",
            "nilai": f"{batch_throughput:.1f} bps"
        })

    avg_delay = df["inter_arrival_time"].mean()  # IAT rata-rata (ms)
    if avg_delay > delay_threshold_ms:
        grouped = df.groupby("src")["inter_arrival_time"].mean().sort_values(ascending=False)
        suspect_ip = grouped.index[0] if not grouped.empty else "Unknown"
        anomalies.append({
            "time": now,
            "jenis": "High Delay",
            "ip": suspect_ip,
            "alasan": f"Delay rata-rata > {delay_threshold_ms} ms ({avg_delay:.3f} ms)",
            "nilai": f"{avg_delay:.3f} ms"
        })

    proto_counts = df["protocol"].value_counts()
    for proto, cnt in proto_counts.items():
        if cnt >= protocol_flood_count:
            df_proto = df[df["protocol"] == proto]
            src_counts = df_proto["src"].value_counts()
            suspect_ip = src_counts.index[0] if not src_counts.empty else "Unknown"
            anomalies.append({
                "time": now,
                "jenis": "Protocol Flood",
                "ip": suspect_ip,
                "alasan": f"{cnt} paket {proto}",
                "nilai": f"{cnt} pkt"
            })

    src_dst_counts = df.groupby("src")["dst_port"].nunique().sort_values(ascending=False)
    if not src_dst_counts.empty and src_dst_counts.iloc[0] >= portscan_ports:
        suspect_ip = src_dst_counts.index[0]
        anomalies.append({
            "time": now,
            "jenis": "Port Scan Suspect",
            "ip": suspect_ip,
            "alasan": f"Menghubungi {src_dst_counts.iloc[0]} tujuan berbeda",
            "nilai": f"{src_dst_counts.iloc[0]} tujuan"
        })

    return anomalies

def get_tshark_interfaces():
    """Mendapatkan daftar interface jaringan melalui tshark -D."""
    try:
        out = subprocess.check_output(["tshark", "-D"], text=True, stderr=subprocess.STDOUT)
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    except:
        try:
            return [i.interface for i in pyshark.tshark.tshark.get_tshark_interfaces()]
        except:
            return []

def should_play_alarm():
    """Cek apakah alarm boleh diputar (interval minimal 3 detik)."""
    last = st.session_state.get("last_alarm_time", 0)
    if time.time() - last > 3:
        st.session_state["last_alarm_time"] = time.time()
        return True
    return False

def interpret_silhouette(score):
    """Memberi interpretasi kualitatif dari silhouette score."""
    if score is None:
        return "Tidak dapat dievaluasi"
    elif score >= 0.70:
        return "Sangat Baik"
    elif score >= 0.50:
        return "Baik"
    elif score >= 0.25:
        return "Cukup"
    else:
        return "Buruk"

def detect_protocol_flood_advanced(df, history, current_time):
    """Deteksi protocol flood tingkat lanjut berdasarkan metrik agregat."""
    anomalies = []
    if df.empty:
        return anomalies
    duration = df["time"].iloc[-1] - df["time"].iloc[0]
    duration = max(duration, 0.001)
    packet_rate = len(df) / duration
    proto_counts = df["protocol"].value_counts()
    dominant_proto = proto_counts.idxmax()
    dominance_ratio = proto_counts.max() / len(df)
    entropy = shannon_entropy(df["protocol"])
    if packet_rate > 200 and dominance_ratio > 0.7 and entropy < 1.0:
        anomalies.append({
            "time": current_time,
            "jenis": "Protocol Flood (Advanced)",
            "ip": "N/A",
            "alasan": f"Packet rate={packet_rate:.2f}, dominance={dominance_ratio:.2f}, entropy={entropy:.2f}",
            "nilai": f"{packet_rate:.2f} pkt/s",
            "score": packet_rate
        })
    return anomalies

def detect_silence_drop_advanced(df, history, current_time):
    """Deteksi silence/drop tingkat lanjut berdasarkan metrik agregat."""
    anomalies = []
    if df.empty or history.empty:
        return anomalies
    duration = df["time"].iloc[-1] - df["time"].iloc[0]
    duration = max(duration, 0.001)
    current_throughput = df["packet_length"].sum() * 8 / duration  # throughput agregat (bps)
    current_iat = df["inter_arrival_time"].mean()                  # IAT rata-rata (ms)
    packet_rate = len(df) / duration
    baseline_thr = history["throughput_avg"].mean()   # throughput agregat history (bps)
    baseline_iat = history["iat_avg"].mean()           # IAT rata-rata history (ms)
    thr_std = history["throughput_avg"].std()
    iat_std = history["iat_avg"].std()
    z_thr = (current_throughput - baseline_thr) / (thr_std + 1e-9)
    z_iat = (current_iat - baseline_iat) / (iat_std + 1e-9)
    if current_throughput < baseline_thr * 0.3 and z_iat > 2 and packet_rate < 10:
        anomalies.append({
            "time": current_time,
            "jenis": "Silence / Drop (Advanced)",
            "ip": "N/A",
            "alasan": f"Throughput turun drastis, z_iat={z_iat:.2f}",
            "nilai": f"{current_throughput:.2f} bps",
            "score": abs(z_iat)
        })
    return anomalies

def epoch_to_human(ts):
    """Konversi timestamp epoch ke format datetime string."""
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except:
        return str(ts)

def play_alarm_html_once(file_path="alarm.wav"):
    """Putar alarm dengan menyematkan audio base64 di HTML."""
    if not os.path.isfile(file_path):
        st.warning("File alarm.wav tidak ditemukan.")
        return
    key = f"alarm_{int(time.time())}"
    data = open(file_path, "rb").read()
    b64 = base64.b64encode(data).decode("utf-8")
    html = f'<audio id="{key}" autoplay><source src="data:audio/wav;base64,{b64}" type="audio/wav"></audio>'
    st.session_state["last_alarm_html"] = key
    st.markdown(html, unsafe_allow_html=True)

# ===== Inisialisasi Session State =====

# State untuk silhouette score
if "sil_score" not in st.session_state:
    st.session_state.sil_score = None

# History jenis trafik (line chart)
if "traffic_type_history" not in st.session_state:
    st.session_state.traffic_type_history = pd.DataFrame(
        columns=["time", "Normal", "Traffic Spike", "Silence / Drop", "Protocol Flood", "Port Scan"]
    )

# History ringkasan cluster
if "cluster_summary_history" not in st.session_state:
    st.session_state.cluster_summary_history = pd.DataFrame()

# History silhouette score per batch
if "silhouette_history" not in st.session_state:
    st.session_state.silhouette_history = pd.DataFrame(
        columns=["batch", "silhouette"]
    )

# Indeks batch untuk plotting silhouette
if "batch_idx" not in st.session_state:
    st.session_state.batch_idx = 0

# State untuk jitter kontinu (RFC 3550)
if "jitter_state" not in st.session_state:
    st.session_state.jitter_state = {
        'last_jitter': 0.0,
        'last_inter_arrival': 0.0,
        'last_timestamp': None
    }

# State untuk deteksi adaptif (EWMA)
init_adaptive_state()

# History agregat (throughput dan iat rata-rata per batch)
if "history" not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=["time", "normal", "anomali", "throughput_avg", "iat_avg"])

# Log anomali
if "anomaly_log" not in st.session_state:
    st.session_state.anomaly_log = []

# ===== Sidebar dan Mode =====
st.sidebar.header("Pengaturan Deteksi")
spike_factor = st.sidebar.slider("Spike factor (x prior avg)", 1.5, 5.0, 2.0, step=0.5)
delay_threshold_ms = st.sidebar.number_input("Delay threshold (ms)", min_value=0.0, value=100.0, step=10.0)
protocol_flood_count = st.sidebar.number_input("Protocol flood count threshold", min_value=10, value=50, step=5)
portscan_ports = st.sidebar.number_input("Port-scan distinct dst threshold", min_value=3, value=20, step=1)

mode = st.radio("Mode:", ["Real-Time Capture", "Upload File PCAP"])

# =================================================================
# MODE REAL-TIME CAPTURE
# =================================================================
if mode == "Real-Time Capture":
    # Pilih interface
    interfaces = get_tshark_interfaces()
    interface = st.selectbox("Pilih Interface (tshark -D):", interfaces)
    interval = st.slider("Interval (detik)", 3, 10, 5)
    max_packets = st.slider("Max paket per batch", 50, 1000, 200)
    alert = st.checkbox("Aktifkan alarm (alarm.wav)", True)

    col1, col2 = st.columns(2)
    start = col1.button("Mulai")
    stop = col2.button("Stop")

    if start:
        st.session_state.running = True
    if stop:
        st.session_state.running = False

    # Tempat-tempat untuk menampilkan output (placeholder)
    ph_metrics = st.empty()
    ph_table = st.empty()
    ph_extra_table = st.empty()
    ph_chart = st.empty()
    ph_kmeans_title = st.empty()
    ph_kmeans_table = st.empty()
    ph_traffic_types = st.empty()
    ph_cluster_history = st.empty()
    ph_silhouette = st.empty()
    ph_line = st.empty()
    ph_anom_title = st.empty()
    ph_anom_table = st.empty()

    # Loop utama real-time
    while st.session_state.get("running", False):
        if not interface:
            st.warning("Pilih interface yang valid.")
            break

        # Tangkap paket
        df = capture_live_packets(interface, interval, max_packets)

        if df.empty:
            st.warning("Tidak ada paket. Pastikan interface benar.")
            time.sleep(interval)
            continue

        # Pastikan kolom dasar ada
        for c in ["time", "packet_length", "src", "dst", "protocol", "dst_port"]:
            if c not in df.columns:
                df[c] = 0 if c != "protocol" else ""

        # ===== URUTKAN BERDASARKAN WAKTU =====
        df = df.sort_values("time").reset_index(drop=True)
        times = df['time'].values
        n = len(times)

        # ===== HITUNG INTER-ARRIVAL TIME DAN JITTER RFC 3550 (KONTINU) =====
        jstate = st.session_state.jitter_state
        last_ts = jstate['last_timestamp']
        last_ia = jstate['last_inter_arrival']
        last_j = jstate['last_jitter']

        inter_arrivals = []
        jitters = []
        for i, ts in enumerate(times):
            if last_ts is None:
                # paket pertama sesi
                ia = 0.0
                j = last_j          # 0
            else:
                ia = (ts - last_ts) * 1000.0          # milidetik
                D = abs(ia - last_ia)
                j = last_j + (D - last_j) / 16.0
            inter_arrivals.append(ia)
            jitters.append(j)
            last_ts = ts
            last_ia = ia
            last_j = j

        df['inter_arrival_time'] = inter_arrivals
        df['jitter_rfc'] = jitters

        # Update state untuk batch berikutnya
        st.session_state.jitter_state = {
            'last_jitter': last_j,
            'last_inter_arrival': last_ia,
            'last_timestamp': last_ts
        }

        # ===== HITUNG THROUGHPUT INSTAN PER PAKET =====
        df['throughput_raw'] = (
            df['packet_length'] * 8 * 1000
        ) / df['inter_arrival_time'].replace(0, np.nan)

        df['throughput_raw'] = df['throughput_raw'].fillna(0)

        df = apply_rolling_throughput(df, window_size=5)

        # ===== HITUNG NILAI AGREGAT UNTUK BATCH =====
        if n > 1:
            durasi_batch = times[-1] - times[0]          # detik
            throughput_batch = df['packet_length'].sum() * 8 / durasi_batch   # bps
            jitter_batch = jitters[-1]                    # nilai jitter terakhir (ms)
            iat_avg = df['inter_arrival_time'].mean()     # ms
        else:
            durasi_batch = 0.001
            throughput_batch = 0.0
            jitter_batch = 0.0
            iat_avg = 0.0

        # ===== CLUSTERING (menggunakan nilai instan per paket) =====
        features = ['packet_length', 'throughput', 'inter_arrival_time', 'jitter_rfc']
        X = df[features].fillna(0)

        n_samples = X.shape[0]
        if n_samples < 2:
            df['cluster'] = 0
            df['cluster_str'] = '0'
            st.session_state.sil_score = None
            df['silhouette_sample'] = np.nan
        else:
            scaler = MinMaxScaler()
            X_scaled = scaler.fit_transform(X)
            best_k = find_best_k(X_scaled)
            st.session_state.best_k = best_k 
            kmeans = KMeans(n_clusters=best_k, random_state=42, n_init="auto")
            df['cluster'] = kmeans.fit_predict(X_scaled)
            df['cluster_str'] = df['cluster'].astype(str)

            # ===== Hitung Silhouette Score =====
            if df['cluster'].nunique() > 1:
                st.session_state.sil_score = silhouette_score(X_scaled, df['cluster'])
                df['silhouette_sample'] = silhouette_samples(X_scaled, df['cluster'])
            else:
                st.session_state.sil_score = None
                df['silhouette_sample'] = np.nan

        # Simpan histori silhouette score
        cluster_summary = []

        if st.session_state.sil_score is not None:
            st.session_state.batch_idx += 1
            new_sil = {"batch": st.session_state.batch_idx, "silhouette": st.session_state.sil_score}
            st.session_state.silhouette_history = pd.concat(
                [st.session_state.silhouette_history, pd.DataFrame([new_sil])], ignore_index=True
            ).tail(50)

        # ===== RINGKASAN CLUSTER DENGAN NILAI AGREGAT PER CLUSTER =====
        for cluster_id in df["cluster"].unique():
            sub = df[df["cluster"] == cluster_id].sort_values("time")
            n_clu = len(sub)
            if n_clu == 0:
                continue
            durasi = sub["time"].iloc[-1] - sub["time"].iloc[0] if n_clu > 1 else 0.001
            total_bytes = sub["packet_length"].sum()
            throughput_cluster = total_bytes * 8 / durasi                     # bps
            avg_jitter = sub['jitter_rfc'].mean()                              # ms
            avg_len = sub["packet_length"].mean()
            avg_iat = sub["inter_arrival_time"].mean()
            avg_sil = sub['silhouette_sample'].mean() if not sub['silhouette_sample'].isna().all() else np.nan
            cluster_summary.append({
                "cluster": cluster_id,
                "Jumlah Data": n_clu,
                "Rata-rata Packet Length (Byte)": avg_len,
                "Throughput (bps)": throughput_cluster,
                "Rata-rata Inter-Arrival Time (ms)": avg_iat,
                "Jitter (ms)": avg_jitter,
                "Rata-rata Silhouette": avg_sil,
            })

        cluster_summary = pd.DataFrame(cluster_summary)

        # ===== Mapping label =====
        cluster_label_map = map_clusters_to_labels(df)
        cluster_summary["Jenis Trafik"] = cluster_summary["cluster"].map(cluster_label_map)

        # ===== SIMPAN HISTORY CLUSTER =====
        if not cluster_summary.empty:
            ts_now = time.strftime("%H:%M:%S")

            cs_copy = cluster_summary.copy()

            # safety guard
            if "Jenis Trafik" not in cs_copy.columns:
                cs_copy["Jenis Trafik"] = "Unknown"

            cs_copy["timestamp"] = ts_now

            st.session_state.cluster_summary_history = pd.concat(
                [st.session_state.cluster_summary_history, cs_copy],
                ignore_index=True
            ).tail(300)

        # Hitung jumlah normal dan anomali berdasarkan label
        df['label'] = df['cluster'].map(cluster_label_map).fillna("Normal")

        # ===== Update statistik jenis trafik =====
        traffic_counts = df['label'].value_counts()

        now_clock = time.strftime("%H:%M:%S")

        new_row_types = {
            "time": now_clock,
            "Normal": int(traffic_counts.get("Normal", 0)),
            "Traffic Spike": int(traffic_counts.get("Traffic Spike", 0)),
            "Silence / Drop": int(traffic_counts.get("Silence / Drop", 0)),
            "Protocol Flood": int(traffic_counts.get("Protocol Flood", 0)),
            "Port Scan": int(traffic_counts.get("Port Scan", 0)),
        }

        st.session_state.traffic_type_history = pd.concat(
            [st.session_state.traffic_type_history, pd.DataFrame([new_row_types])],
            ignore_index=True
        ).tail(60)

        total_anomali = int((df['label'] != 'Normal').sum())
        total_normal = int((df['label'] == 'Normal').sum())

        # History menyimpan throughput agregat dan IAT rata-rata
        now_time = time.strftime("%H:%M:%S")
        new_row = {"time": now_time, "normal": total_normal, "anomali": total_anomali,
                   "throughput_avg": throughput_batch, "iat_avg": iat_avg}
        st.session_state.history = pd.concat([st.session_state.history, pd.DataFrame([new_row])]).tail(60)

        # ===== TAMPILAN METRIK (ph_metrics) =====
        with ph_metrics.container():
            cc1, cc2, cc3, cc4, cc5 = st.columns(5)

            cc1.metric("Normal Traffic", total_normal)
            cc2.metric("Anomaly Detected", total_anomali)
            cc3.metric("Throughput (bps)", f"{throughput_batch:.1f}")

            if st.session_state.sil_score is not None:
                cc4.metric(
                    "Silhouette Score",
                    f"{st.session_state.sil_score:.3f}",
                    interpret_silhouette(st.session_state.sil_score)
                )
            else:
                cc4.metric("Silhouette Score", "N/A")

            # Best k
            if st.session_state.best_k is not None:
                cc5.metric("Best k", st.session_state.best_k)
            else:
                cc5.metric("Best k", "N/A")

        # ===== SCATTER PLOT 3D (ph_chart) =====
        cluster_colors = {
            "0": "#1f77b4", "1": "#ff7f0e", "2": "#2ca02c", "3": "#d62728", "4": "#9467bd"
        }
        try:
            unique_key = f"scatter_{st.session_state.batch_idx}_{int(time.time()*1000)}"
            fig = px.scatter_3d(
                df, x='packet_length', y='throughput', z='inter_arrival_time',
                color='cluster_str', title='Real-Time Traffic Clustering (K-Means)',
                height=750, color_discrete_map=cluster_colors,
                labels={'packet_length': 'Packet Length (Byte)', 'throughput': 'Throughput (bps)', 'inter_arrival_time': 'Inter-Arrival Time (ms)'}
            )
            fig.update_layout(legend_title_text="Cluster")
            ph_chart.plotly_chart(fig, use_container_width=True, key=unique_key)
        except Exception as e:
            ph_chart.error(f"Scatter error: {e}")

        # ===== TABEL PAKET DASAR (ph_table) =====
        display_table = df[['time', 'packet_length', 'src', 'dst', 'protocol']].tail(100).copy()
        display_table['time'] = display_table['time'].apply(epoch_to_human)
        ph_table.dataframe(display_table, use_container_width=True)

        # ===== TABEL EKSTRAKSI FITUR (ph_extra_table) =====
        with ph_extra_table.container():
            st.subheader("📊 Tabel Hasil Ekstraksi Fitur Trafik Jaringan (Real-Time)")
            df_extra = df[['time', 'src', 'dst', 'protocol', 'packet_length', 'throughput', 
                           'inter_arrival_time', 'jitter_rfc', 'cluster', 'silhouette_sample']].copy()
            df_extra['time'] = df_extra['time'].apply(epoch_to_human)
            df_extra['packet_length'] = df_extra['packet_length'].astype(int)
            df_extra['throughput'] = df_extra['throughput'].round(1)
            df_extra['inter_arrival_time'] = df_extra['inter_arrival_time'].round(3)
            df_extra['jitter_rfc'] = df_extra['jitter_rfc'].round(3)
            df_extra['silhouette_sample'] = df_extra['silhouette_sample'].round(4)
            df_extra.columns = ["Waktu", "Src IP", "Dst IP", "Protocol", "Packet Length (Byte)", 
                                "Throughput (bps)", "Inter-Arrival Time (ms)", "Jitter (ms)", 
                                "Cluster", "Silhouette Score"]
            st.dataframe(df_extra, use_container_width=True, height=420)

        # ===== GRAFIK JENIS TRAFIK (ph_traffic_types) =====
        hist_types = st.session_state.traffic_type_history.copy()
        if not hist_types.empty:
            hist_melt_types = hist_types.melt(
                id_vars=["time"],
                var_name="Jenis Trafik",
                value_name="Jumlah"
            )
            fig_types = px.line(
                hist_melt_types,
                x="time",
                y="Jumlah",
                color="Jenis Trafik",
                markers=True,
                title="📈 Tren Jenis Trafik Real-Time"
            )
            ph_traffic_types.plotly_chart(fig_types, use_container_width=True)

        # ===== GRAFIK SILHOUETTE HISTORY (ph_silhouette) =====
        if not st.session_state.silhouette_history.empty:
            unique_key_sil = f"silhouette_{st.session_state.batch_idx}_{int(time.time()*1000)}"
            fig_sil = px.line(st.session_state.silhouette_history, x="batch", y="silhouette", markers=True,
                              title="Histori Silhouette Score (Real-Time)")
            fig_sil.update_yaxes(range=[-1, 1])
            with ph_silhouette.container():
                st.plotly_chart(fig_sil, use_container_width=True, key=unique_key_sil)

        # ===== HISTORY RINGKASAN CLUSTER (ph_cluster_history) =====
        with ph_cluster_history.container():
            st.markdown("### 🧠 History Ringkasan Cluster")
            hist_cs = st.session_state.cluster_summary_history.copy()
            if not hist_cs.empty:
                st.dataframe(
                    hist_cs.sort_values("timestamp", ascending=False),
                    use_container_width=True,
                    height=300
                )
            else:
                st.info("Belum ada history cluster.")

        # ===== RINGKASAN CLUSTER SAAT INI (ph_kmeans_title + ph_kmeans_table) =====
        ph_kmeans_title.markdown("### 📊 Ringkasan Klaster K-Means")
        if not cluster_summary.empty:
            col_order = ["cluster", "Jumlah Data", "Rata-rata Packet Length (Byte)", "Throughput (bps)", 
                         "Rata-rata Inter-Arrival Time (ms)", "Jitter (ms)", "Rata-rata Silhouette", "Jenis Trafik"]
            cluster_summary = cluster_summary[col_order].round(4)
            ph_kmeans_table.dataframe(cluster_summary, use_container_width=True)
        else:
            ph_kmeans_table.info("Belum ada data cluster.")

        # ===== DETEKSI ANOMALI =====
        now_anom = time.strftime("%H:%M:%S")
        anomalies = analyze_anomalies(df, st.session_state.history,
                                      spike_factor=spike_factor,
                                      delay_threshold_ms=delay_threshold_ms,
                                      protocol_flood_count=protocol_flood_count,
                                      portscan_ports=portscan_ports)

        advanced_proto = detect_protocol_flood_advanced(df, st.session_state.history, now_anom)
        if advanced_proto:
            st.session_state.anomaly_log.extend(advanced_proto)

        advanced_silence = detect_silence_drop_advanced(df, st.session_state.history, now_anom)
        if advanced_silence:
            st.session_state.anomaly_log.extend(advanced_silence)

        # Adaptive anomaly dengan jitter_batch (nilai terakhir)
        batch_metrics = {
            "throughput": throughput_batch,
            "jitter": jitter_batch,
            "packet_count": len(df),
            "src_counts": df['src'].value_counts()
        }
        adaptive_anomalies = detect_adaptive_anomaly(batch_metrics, df, st.session_state.history)
        if adaptive_anomalies:
            st.session_state.anomaly_log.extend(adaptive_anomalies)

        if anomalies:
            st.session_state.anomaly_log = (st.session_state.anomaly_log + anomalies)[-200:]

        # ===== ALARM =====
        if alert and (anomalies or adaptive_anomalies or advanced_proto or advanced_silence) and should_play_alarm():
            play_alarm_html_once("alarm.wav")

        time.sleep(interval)

# =================================================================
# MODE UPLOAD FILE PCAP
# =================================================================
else:
    uploaded_file = st.file_uploader("Upload file PCAP (.pcap / .pcapng)", type=["pcap", "pcapng"])

    if uploaded_file:
        st.success(f"File diterima: {uploaded_file.name}")

        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Baca dengan Scapy
        pkts = rdpcap(file_path)
        basic_packets = []
        for pkt in pkts:
            if IP in pkt:
                dst_port = 0
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    dst_port = pkt[UDP].dport
                basic_packets.append({
                    "time": float(pkt.time),
                    "packet_length": len(pkt),
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "dst_port": dst_port
                })

        if not basic_packets:
            st.warning("Tidak ada paket IP.")
            os.remove(file_path)
        else:
            # Ambil protocol dengan tshark
            cmd = ["tshark", "-r", file_path, "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            protocols = {}
            reader = csv.reader(io.StringIO(result.stdout), delimiter="\t")
            for row in reader:
                if len(row) >= 2:
                    try:
                        protocols[int(row[0])] = row[1]
                    except:
                        continue

            packets = []
            for i, pkt in enumerate(basic_packets, start=1):
                packets.append((
                    pkt["time"],
                    pkt["packet_length"],
                    pkt["src"],
                    pkt["dst"],
                    pkt["dst_port"],
                    protocols.get(i, "UNKNOWN")
                ))

            df = pd.DataFrame(packets, columns=["time", "packet_length", "src", "dst", "dst_port", "protocol"])
            df = df.sort_values("time").reset_index(drop=True)

            # ===== HITUNG INTER-ARRIVAL TIME DAN JITTER RFC 3550 (OFFLINE) =====
            times = df['time'].values
            n = len(times)

            last_ts = None
            last_ia = 0.0
            last_j = 0.0
            inter_arrivals = []
            jitters = []
            for i, ts in enumerate(times):
                if last_ts is None:
                    ia = 0.0
                    j = last_j
                else:
                    ia = (ts - last_ts) * 1000.0
                    D = abs(ia - last_ia)
                    j = last_j + (D - last_j) / 16.0
                inter_arrivals.append(ia)
                jitters.append(j)
                last_ts = ts
                last_ia = ia
                last_j = j

            df['inter_arrival_time'] = inter_arrivals
            df['jitter_rfc'] = jitters
            
            # ===== THROUGHPUT INSTAN (PCAP) =====
            df['throughput_raw'] = (
                df['packet_length'] * 8 * 1000
            ) / df['inter_arrival_time'].replace(0, np.nan)

            df['throughput_raw'] = df['throughput_raw'].fillna(0)

            # ===== ROLLING WINDOW (SAMAKAN DENGAN REALTIME) =====
            df = apply_rolling_throughput(df, window_size=5)

            # Tampilkan data mentah
            st.subheader("📦 Data Paket Jaringan")
            df_show = df.copy()
            df_show["time"] = df_show["time"].apply(epoch_to_human)
            st.dataframe(df_show[["time", "src", "dst", "protocol", "packet_length"]], use_container_width=True)
            st.info(f"Total paket: {len(df)}")

            # ===== CLUSTERING (PCAP) =====
            features = ["packet_length", "throughput", "inter_arrival_time", "jitter_rfc"]
            X = df[features].fillna(0)

            scaler = MinMaxScaler()
            X_scaled = scaler.fit_transform(X)

            n_samples = X_scaled.shape[0]

            # 🔥 BEST-K ADAPTIF
            if n_samples >= 2:
                try:
                    best_k = find_best_k(X_scaled)

                    # safety guard
                    if best_k < 2:
                        best_k = 2
                    if best_k >= n_samples:
                        best_k = max(2, n_samples - 1)

                    st.session_state.best_k = best_k

                    kmeans = KMeans(n_clusters=best_k, random_state=42, n_init="auto")
                    df["cluster"] = kmeans.fit_predict(X_scaled)

                    # ===== Silhouette =====
                    if df["cluster"].nunique() > 1:
                        sil_score_pcap = silhouette_score(X_scaled, df["cluster"])
                        df['silhouette_sample'] = silhouette_samples(X_scaled, df['cluster'])
                    else:
                        sil_score_pcap = None
                        df['silhouette_sample'] = np.nan

                except Exception as e:
                    # fallback aman
                    df["cluster"] = 0
                    sil_score_pcap = None
                    df['silhouette_sample'] = np.nan
                    st.warning(f"Best-k fallback: {e}")

            else:
                df["cluster"] = 0
                sil_score_pcap = None
                df['silhouette_sample'] = np.nan

            # ===== TABEL FITUR (nilai instan) =====
            st.subheader("📊 Tabel Hasil Perhitungan Fitur Trafik Jaringan")
            df_feature_table = df[["packet_length", "inter_arrival_time", "throughput", "jitter_rfc"]].copy()
            df_feature_table["packet_length"] = df_feature_table["packet_length"].astype(int)
            df_feature_table["inter_arrival_time"] = df_feature_table["inter_arrival_time"].round(3)
            df_feature_table["throughput"] = df_feature_table["throughput"].round(1)
            df_feature_table["jitter_rfc"] = df_feature_table["jitter_rfc"].round(3)
            df_feature_table.columns = ["Packet Length (Byte)", "Inter-Arrival Time (ms)", "Throughput (bps)", "Jitter (ms)"]
            st.dataframe(df_feature_table, use_container_width=True, height=420)

            # ===== TABEL NORMALISASI =====
            st.subheader("📊 Tabel Data Fitur Setelah Normalisasi (Min-Max Scaling)")
            df_features_raw = df[["packet_length", "inter_arrival_time", "throughput", "jitter_rfc"]].copy()
            scaler_display = MinMaxScaler()
            X_scaled_display = scaler_display.fit_transform(df_features_raw)
            df_features_scaled = pd.DataFrame(
                X_scaled_display,
                columns=["Packet Length", "Inter-Arrival Time", "Throughput", "Jitter"]
            )
            st.dataframe(df_features_scaled.round(3), use_container_width=True, height=420)

            # ===== TABEL EKSTRAKSI + CLUSTER + SILHOUETTE =====
            st.subheader("📊 Tabel Hasil Ekstraksi Fitur Trafik Jaringan (Offline PCAP)")
            df_table = df[["time", "src", "dst", "protocol", "packet_length", "throughput", 
                           "inter_arrival_time", "jitter_rfc", "cluster", "silhouette_sample"]].copy()
            df_table["time"] = df_table["time"].apply(epoch_to_human)
            df_table["packet_length"] = df_table["packet_length"].astype(int)
            df_table["throughput"] = df_table["throughput"].round(1)
            df_table["inter_arrival_time"] = df_table["inter_arrival_time"].round(3)
            df_table["jitter_rfc"] = df_table["jitter_rfc"].round(3)
            df_table["silhouette_sample"] = df_table["silhouette_sample"].round(4)
            df_table.columns = ["Waktu", "Src IP", "Dst IP", "Protocol", "Packet Length (Byte)", 
                                "Throughput (bps)", "Inter-Arrival Time (ms)", "Jitter (ms)", 
                                "Cluster", "Silhouette Score"]
            st.dataframe(df_table, use_container_width=True, height=420)

            # ===== SCATTER PLOT 3D =====
            df["cluster_str"] = df["cluster"].astype(str)
            cluster_colors = {"0": "#1f77b4", "1": "#ff7f0e", "2": "#2ca02c", "3": "#d62728", "4": "#9467bd"}
            fig = px.scatter_3d(
                df, x="packet_length", y="throughput", z="inter_arrival_time",
                color="cluster_str", title="Traffic Clustering (Offline PCAP)",
                height=750, color_discrete_map=cluster_colors,
                labels={'packet_length': 'Packet Length (Byte)', 'throughput': 'Throughput (bps)', 'inter_arrival_time': 'Inter-Arrival Time (ms)'}
            )
            fig.update_layout(legend_title_text="Cluster",
                scene=dict(xaxis_title="Packet Length (Byte)", yaxis_title="Throughput (bps)", zaxis_title="Inter-Arrival Time (ms)"))
            st.plotly_chart(fig, use_container_width=True)

            # ===== RINGKASAN CLUSTER =====
            st.subheader("📊 Tabel Interpretasi Hasil Clustering (Offline PCAP)")
            cluster_summary = []
            for cluster_id in df["cluster"].unique():
                sub = df[df["cluster"] == cluster_id].sort_values("time")
                n_clu = len(sub)
                if n_clu == 0: continue
                durasi = sub["time"].iloc[-1] - sub["time"].iloc[0] if n_clu > 1 else 0.001
                total_bytes = sub["packet_length"].sum()
                throughput_cluster = total_bytes * 8 / durasi
                avg_jitter = sub['jitter_rfc'].mean()
                avg_len = sub["packet_length"].mean()
                avg_iat = sub["inter_arrival_time"].mean()
                avg_sil = sub['silhouette_sample'].mean() if not sub['silhouette_sample'].isna().all() else np.nan
                cluster_summary.append({
                    "cluster": cluster_id,
                    "Jumlah Data": n_clu,
                    "Rata-rata Packet Length (Byte)": avg_len,
                    "Throughput (bps)": throughput_cluster,
                    "Rata-rata Inter-Arrival Time (ms)": avg_iat,
                    "Jitter (ms)": avg_jitter,
                    "Rata-rata Silhouette": avg_sil,
                })
            cluster_summary = pd.DataFrame(cluster_summary)
            cluster_label_map = map_clusters_to_labels(df)
            cluster_summary["Jenis Trafik"] = cluster_summary["cluster"].map(cluster_label_map)

            # ===== SIMPAN HISTORY CLUSTER =====
            if not cluster_summary.empty:
                ts_now = time.strftime("%H:%M:%S")
                cs_copy = cluster_summary.copy()
                if "Jenis Trafik" not in cs_copy.columns:
                    cs_copy["Jenis Trafik"] = "Unknown"
                cs_copy["timestamp"] = ts_now
                st.session_state.cluster_summary_history = pd.concat(
                    [st.session_state.cluster_summary_history, cs_copy],
                    ignore_index=True
                ).tail(300)

            # Advanced detection override
            advanced_flood = detect_protocol_flood_cluster(df)
            advanced_silence = detect_silence_cluster(df)
            cluster_summary.loc[cluster_summary["cluster"].isin(advanced_flood), "Jenis Trafik"] = "Protocol Flood (Advanced)"
            cluster_summary.loc[cluster_summary["cluster"].isin(advanced_silence), "Jenis Trafik"] = "Silence / Drop (Advanced)"

            col_order = ["cluster", "Jumlah Data", "Rata-rata Packet Length (Byte)", "Throughput (bps)", 
                         "Rata-rata Inter-Arrival Time (ms)", "Jitter (ms)", "Jenis Trafik", "Rata-rata Silhouette"]
            cluster_summary = cluster_summary[col_order].round(3)

            row_height = 38
            header_height = 38
            table_height = header_height + len(cluster_summary) * row_height
            st.dataframe(cluster_summary, use_container_width=True, height=table_height)

            # ===== SILHOUETTE SCORE =====
            st.subheader("📐 Evaluasi Kualitas Clustering")
            if sil_score_pcap is not None:
                st.metric("Silhouette Score", f"{sil_score_pcap:.3f}", interpret_silhouette(sil_score_pcap))
                if st.session_state.best_k is not None:
                    st.metric("Best k", st.session_state.best_k)
            else:
                st.warning("Silhouette Score tidak dapat dihitung (jumlah cluster < 2)")

            # Hapus file
            os.remove(file_path)