import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import scapy.all as scapy
from sklearn.cluster import KMeans
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import silhouette_score
import pyshark
import tempfile
import os
import time
import subprocess
from datetime import datetime
import asyncio
import sys

# Fix PyShark + Streamlit event loop
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# =====================================================
# KONFIGURASI HALAMAN
# =====================================================
st.set_page_config(page_title="Sistem Deteksi Anomali Trafik Jaringan dengan Metode K-Means Clustering", layout="wide")
st.title("🔍 Sistem Deteksi Anomali Trafik Jaringan dengan Metode K-Means Clustering")
st.markdown("Aida Vianisa - 240401020009")

# =====================================================
# FUNGSI INTERFACE (tshark)
# =====================================================
def get_interfaces():
    try:
        result = subprocess.check_output(["tshark", "-D"], text=True)
        return [line.strip() for line in result.splitlines()]
    except:
        return []

# =====================================================
# CAPTURE LIVE PACKET (TSHARK)
# =====================================================
def capture_live_packets(interface_line, duration, max_packets):
    packets = []
    try:
        iface_index = interface_line.split(".")[0]
        cmd = [
            "tshark",
            "-i", iface_index,
            "-a", f"duration:{duration}",
            "-c", str(max_packets),
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            packets.append({
                "time": float(parts[0]),
                "packet_length": int(parts[1]),
                "src": parts[2] if parts[2] else "N/A",
                "dst": parts[3] if parts[3] else "N/A",
                "protocol": parts[4]
            })
    except Exception as e:
        st.error(f"Gagal menangkap paket: {e}")
    return packets

# =====================================================
# BACA FILE PCAP (TSHARK)
# =====================================================
def read_pcap_file(file_path, max_packets):
    packets = []
    try:
        cmd = [
            "tshark",
            "-r", file_path,
            "-c", str(max_packets),
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            packets.append({
                "time": float(parts[0]),
                "packet_length": int(parts[1]),
                "src": parts[2] if parts[2] else "N/A",
                "dst": parts[3] if parts[3] else "N/A",
                "protocol": parts[4]
            })
    except Exception as e:
        st.error(f"Gagal membaca PCAP: {e}")
    return packets

# =====================================================
# EKSTRAKSI FITUR TEMPORAL (IAT, THROUGHPUT, JITTER RFC)
# =====================================================
def add_temporal_features(df):
    df = df.copy().sort_values('time').reset_index(drop=True)
    times = df['time'].values

    last_ts = None
    last_ia = 0.0
    last_j = 0.0

    iat_list = []
    jitter_list = []

    for ts in times:
        if last_ts is None:
            ia = 0.0
            j = last_j
        else:
            ia = (ts - last_ts) * 1000.0
            D = abs(ia - last_ia)
            j = last_j + (D - last_j) / 16.0

        iat_list.append(ia)
        jitter_list.append(j)

        last_ts = ts
        last_ia = ia
        last_j = j

    df['iat'] = iat_list
    df['jitter_rfc'] = jitter_list

    # throughput aman dari divide by zero
    df['throughput_raw'] = np.where(
        df['iat'] > 0,
        df['packet_length'] * 8 / (df['iat'] / 1000.0),
        0
    )

    #df['throughput'] = df['throughput_raw']

    window = 5
    df['throughput_smooth'] = df['throughput_raw'].rolling(window=window, min_periods=1).mean()
    df['throughput'] = np.log1p(df['throughput_smooth'])

    return df

# =====================================================
# PEMILIHAN JUMLAH CLUSTER TERBAIK
# =====================================================
def find_best_k(X_scaled, k_min=2, k_max=10):
    best_k = k_min
    best_score = -1

    max_k = min(k_max, len(X_scaled) - 1)

    if max_k < k_min:
        return k_min

    for k in range(k_min, max_k + 1):

        try:

            km = KMeans(
                n_clusters=k,
                random_state=42,
                n_init=20,
                max_iter=500
            )

            labels = km.fit_predict(X_scaled)

            if len(set(labels)) < 2:
                continue

            score = silhouette_score(X_scaled, labels)

            if score > best_score:
                best_score = score
                best_k = k

        except:
            continue

    if best_score == -1:
        return k_min

    return best_k

# =====================================================
# K-MEANS ANOMALY DETECTION (dengan MinMaxScaler)
# =====================================================
def detect_anomalies_kmeans(df, feature_cols, n_clusters=2, percentile=95):
    X = df[feature_cols].fillna(0).values

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # buat dataframe fitur setelah normalisasi
    df_scaled = pd.DataFrame(
        X_scaled,
        columns=[f"{col}_scaled" for col in feature_cols]
    )

    best_k = n_clusters

    if n_clusters is None or n_clusters == 0:

        best_k = find_best_k(X_scaled, 2, 10)

        if best_k >= len(X_scaled):
            best_k = max(2, len(X_scaled) - 1)

    kmeans = KMeans(
        n_clusters=best_k,
        random_state=42,
        n_init=20,
        max_iter=500
    )

    df['cluster'] = kmeans.fit_predict(X_scaled)

    distances = []

    for i, row in enumerate(X_scaled):

        centroid = kmeans.cluster_centers_[df['cluster'].iloc[i]]

        dist = np.linalg.norm(row - centroid)

        distances.append(dist)

    df['distance'] = distances

    threshold = np.percentile(distances, percentile)

    df['anomaly'] = df['distance'] > threshold

    return df, kmeans, scaler, threshold, best_k, X_scaled, df_scaled

# =====================================================
# ANALISIS RATA-RATA JARAK
# =====================================================
def distance_statistics(df):
    if 'distance' not in df.columns or 'anomaly' not in df.columns:
        return None, None, None
    mean_all = df['distance'].mean()
    mean_anomaly = df[df['anomaly']]['distance'].mean() if df['anomaly'].sum() > 0 else 0
    mean_normal = df[~df['anomaly']]['distance'].mean() if (~df['anomaly']).sum() > 0 else 0
    return mean_all, mean_anomaly, mean_normal

# =====================================================
# KONVERSI TIME
# =====================================================
def epoch_to_human(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except:
        return str(ts)

# =====================================================
# SESSION STATE
# =====================================================
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=['time', 'normal', 'anomali', 'throughput_avg', 'iat_avg'])
if 'batch_idx' not in st.session_state:
    st.session_state.batch_idx = 0
if 'silhouette_history' not in st.session_state:
    st.session_state.silhouette_history = pd.DataFrame(columns=['batch', 'silhouette'])
if 'packet_history' not in st.session_state:
    st.session_state.packet_history = pd.DataFrame()
if 'best_k_history' not in st.session_state:
    st.session_state.best_k_history = pd.DataFrame(columns=['batch', 'best_k'])

# =====================================================
# SIDEBAR
# =====================================================
st.sidebar.header("⚙️ Pengaturan")

mode = st.sidebar.radio("Pilih Mode:", ["Real-Time Capture", "Upload File PCAP"])

# Pilihan fitur (sesuaikan dengan kolom hasil add_temporal_features)
all_features = ['packet_length', 'iat', 'throughput', 'jitter_rfc']
default_features = all_features.copy()
feature_options = st.sidebar.multiselect(
    "Pilih fitur untuk clustering",
    all_features,
    default=default_features
)

n_clusters = st.sidebar.number_input("Jumlah Cluster (0 = otomatis)", min_value=0, max_value=10, value=0)
percentile = st.sidebar.slider("Persentil Threshold Anomali", 90, 99, 95)

# =====================================================
# MODE REALTIME
# =====================================================
if mode == "Real-Time Capture":
    st.header("📡 Tangkap Langsung dari Interface")
    interfaces = get_interfaces()
    interface = st.selectbox("Pilih Interface Jaringan:", interfaces)

    col1, col2 = st.columns(2)
    with col1:
        duration = st.number_input("Durasi Tangkapan (detik)", 1, 30, 10)
    with col2:
        max_packets = st.number_input("Maksimum Paket per Batch", 10, 2000, 500)

    col_start, col_stop = st.columns(2)
    if col_start.button("Mulai Capture"):
        st.session_state.running = True
    if col_stop.button("Stop"):
        st.session_state.running = False

    ph_metrics = st.empty()
    ph_chart = st.empty()
    ph_table = st.empty()
    ph_extra = st.empty()
    ph_silhouette = st.empty()

    while st.session_state.get('running', False):
        packets = capture_live_packets(interface, duration, max_packets)
        if not packets:
            st.warning("Tidak ada paket yang tertangkap.")
            time.sleep(2)
            continue

        df = pd.DataFrame(packets)
        if df.empty:
            st.warning("Tidak ada paket.")
            time.sleep(2)
            continue

        # Tambahkan fitur temporal (IAT, jitter RFC, throughput)
        df = add_temporal_features(df)

        # Pilih fitur yang akan digunakan (pastikan semuanya ada)
        used_features = [f for f in feature_options if f in df.columns]
        if len(used_features) < 2:
            st.error("Minimal pilih 2 fitur untuk clustering")
            st.stop()
        if not used_features:
            st.error("Tidak ada fitur yang dipilih! Gunakan fitur default.")
            used_features = ['packet_length']

        k_opt = n_clusters if n_clusters > 0 else None
        df_result, kmeans, scaler, thresh, best_k, X_scaled, df_scaled = detect_anomalies_kmeans(
            df, used_features, k_opt, percentile
        )
        mean_all, mean_anomaly, mean_normal = distance_statistics(df_result)

        # Silhouette score dan best k
        if df_result['cluster'].nunique() > 1:
            sil_score = silhouette_score(X_scaled, df_result['cluster'])
            st.session_state.batch_idx += 1
            new_sil = pd.DataFrame({'batch': [st.session_state.batch_idx], 'silhouette': [sil_score]})
            st.session_state.silhouette_history = pd.concat(
                [st.session_state.silhouette_history, new_sil], ignore_index=True).tail(50)
            # Simpan best k
            best_k_used = len(df_result['cluster'].unique())
            new_best_k = pd.DataFrame({'batch': [st.session_state.batch_idx], 'best_k': [best_k_used]})
            st.session_state.best_k_history = pd.concat(
                [st.session_state.best_k_history, new_best_k], ignore_index=True).tail(50)
        else:
            sil_score = None

        # Throughput agregat batch (dalam bps, tanpa log)
        if len(df_result) > 1:
            durasi = df_result['time'].iloc[-1] - df_result['time'].iloc[0]
            throughput_batch = df_result['packet_length'].sum() * 8 / durasi if durasi > 0 else 0
            iat_avg = df_result['iat'].mean()  # ms
        else:
            throughput_batch = 0
            iat_avg = 0

        total_anomali = df_result['anomaly'].sum()
        total_normal = len(df_result) - total_anomali

        with ph_metrics.container():
            c1, c2, c3, c4, c5, c6, c7, c8, c9 = st.columns(9)
            c1.metric("Total Paket", len(df_result))
            c2.metric("Normal", total_normal)
            c3.metric("Anomali", total_anomali)
            c4.metric("Throughput (bps)", f"{throughput_batch:.1f}")
            c5.metric("Silhouette", f"{sil_score:.3f}" if sil_score else "N/A")
            c6.metric("Best k", best_k)
            c7.metric("Mean Distance (All)", f"{mean_all:.4f}")
            c8.metric("Mean Distance (Anomali)", f"{mean_anomaly:.4f}")
            c9.metric("Mean Distance (Normal)", f"{mean_normal:.4f}")

        # Scatter plot jarak
        fig = px.scatter(
            df_result,
            x=df_result.index,
            y='distance',
            color='anomaly',
            symbol='cluster',
            title="Jarak ke Centroid vs Indeks Paket",
            color_discrete_map={True: "red", False: "blue"}
        )
        ph_chart.plotly_chart(fig, use_container_width=True)

        # Tampilkan data paket
        df_display = df_result[['time', 'src', 'dst', 'protocol', 'packet_length',
                        'iat', 'throughput_raw', 'jitter_rfc', 'cluster', 'distance', 'anomaly']].copy()
        df_display = df_display.rename(columns={'throughput_raw': 'throughput'})
        df_display['time'] = df_display['time'].apply(epoch_to_human)
        # Bulatkan agar lebih rapi
        df_display['iat'] = df_display['iat'].round(3)
        df_display['throughput'] = df_display['throughput'].round(1)
        df_display['jitter_rfc'] = df_display['jitter_rfc'].round(3)

        # Simpan history
        st.session_state.packet_history = pd.concat(
            [st.session_state.packet_history, df_display], ignore_index=True
        ).tail(2000)

        ph_table.subheader("📋 History Paket (Real-Time)")
        ph_table.dataframe(st.session_state.packet_history, use_container_width=True, height=400)

        with ph_extra.container():
            st.subheader("📊 Fitur yang Digunakan")
            # Tampilkan fitur asli + scaling (opsional)
            st.dataframe(df_result[used_features + ['cluster', 'distance', 'anomaly']].round(4), use_container_width=True, height=300)

        # Plot silhouette history
        if not st.session_state.silhouette_history.empty:
            fig_sil = px.line(st.session_state.silhouette_history,
                              x='batch', y='silhouette', markers=True,
                              title="Histori Silhouette Score")
            fig_sil.update_yaxes(range=[-1, 1])
            ph_silhouette.plotly_chart(fig_sil, use_container_width=True)

        time.sleep(1)

# =====================================================
# MODE PCAP
# =====================================================
else:
    st.header("📁 Upload File PCAP")
    uploaded = st.file_uploader("Pilih file .pcap atau .pcapng", type=["pcap", "pcapng"])

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        max_packets = st.number_input("Maksimum paket diproses", 10, 5000, 1000)

        packets = read_pcap_file(tmp_path, max_packets)
        os.unlink(tmp_path)

        if packets:
            df = pd.DataFrame(packets)
            if not df.empty:
                # Tambahkan fitur temporal
                df = add_temporal_features(df)

                used_features = [f for f in feature_options if f in df.columns]
                if len(used_features) < 2:
                    st.error("Minimal pilih 2 fitur untuk clustering")
                    st.stop()
                if not used_features:
                    st.error("Tidak ada fitur yang dipilih! Gunakan fitur default.")
                    used_features = ['packet_length']

                k_opt = n_clusters if n_clusters > 0 else None
                df_result, kmeans, scaler, thresh, best_k, X_scaled, df_scaled = detect_anomalies_kmeans(
                    df, used_features, k_opt, percentile
                )
                mean_all, mean_anomaly, mean_normal = distance_statistics(df_result)

                # Silhouette
                if df_result['cluster'].nunique() > 1:
                    sil_score = silhouette_score(X_scaled, df_result['cluster'])
                else:
                    sil_score = None

                # Metrik tambahan
                if len(df_result) > 1:
                    durasi = df_result['time'].iloc[-1] - df_result['time'].iloc[0]
                    throughput_batch = df_result['packet_length'].sum() * 8 / durasi if durasi > 0 else 0
                    iat_avg = df_result['iat'].mean()
                else:
                    throughput_batch = 0
                    iat_avg = 0

                st.subheader("📊 Hasil Deteksi Anomali")
                col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns(9)
                col1.metric("Total Paket", len(df_result))
                col2.metric("Jumlah Anomali", df_result['anomaly'].sum())
                col3.metric("Threshold Jarak", f"{thresh:.4f}")
                col4.metric("Silhouette", f"{sil_score:.3f}" if sil_score else "N/A")
                col5.metric("Best k", len(df_result['cluster'].unique()) if 'cluster' in df_result else "N/A")
                col6.metric("Mean Distance (All)", f"{mean_all:.4f}")
                col7.metric("Mean Distance (Anomali)", f"{mean_anomaly:.4f}")
                col8.metric("Mean Distance (Normal)", f"{mean_normal:.4f}")
                col9.metric("Throughput (bps)", f"{throughput_batch:.1f}")

                # Scatter plot jarak
                fig = px.scatter(
                    df_result,
                    x=df_result.index,
                    y='distance',
                    color='anomaly',
                    symbol='cluster',
                    title="Jarak ke Centroid vs Indeks Paket",
                    color_discrete_map={True: "red", False: "blue"}
                )
                st.plotly_chart(fig, use_container_width=True)

                # Tabel data
                st.subheader("📋 Data Paket (dengan fitur)")
                df_display = df_result[['time', 'src', 'dst', 'protocol', 'packet_length',
                        'iat', 'throughput_raw', 'jitter_rfc', 'cluster', 'distance', 'anomaly']].copy()
                df_display = df_display.rename(columns={'throughput_raw': 'throughput'})
                df_display['time'] = df_display['time'].apply(epoch_to_human)
                df_display['iat'] = df_display['iat'].round(3)
                df_display['throughput'] = df_display['throughput'].round(1)
                df_display['jitter_rfc'] = df_display['jitter_rfc'].round(3)
                st.dataframe(df_display, use_container_width=True)

                # Tampilkan fitur yang digunakan (opsional)
                # st.subheader("📊 Data Fitur untuk Clustering")
                # st.dataframe(df_result[used_features + ['cluster', 'distance', 'anomalys']].round(4), use_container_width=True)

                # Tabel Normalisai Minmax Scalling
                st.subheader("📊 Fitur Setelah Normalisasi (Min-Max Scaling)")
                st.dataframe(
                    df_scaled,
                    use_container_width=True,
                    height=300
                )

                # Tabel Jumlah Data per Cluster
                st.subheader("📊 Distribusi Data pada Setiap Cluster")
                cluster_summary = (
                    df_result.groupby("cluster")
                    .size()
                    .reset_index(name="jumlah_data")
                    .sort_values("cluster")
                )

                st.dataframe(cluster_summary, use_container_width=False)

                st.subheader("📊 Statistik Jarak Paket terhadap Centroid")

                # ubah label agar lebih mudah dibaca
                df_result["kelas"] = df_result["anomaly"].map({False: "Normal", True: "Anomali"})

                # hitung statistik
                distance_stats = (
                    df_result.groupby("kelas")["distance"]
                    .agg(
                        jumlah_paket="count",
                        rata_rata_jarak="mean",
                        jarak_minimum="min",
                        jarak_maksimum="max",
                        standar_deviasi="std"
                    )
                    .reset_index()
                )

                # pembulatan angka
                distance_stats = distance_stats.round(3)

                # ubah nama kolom agar sesuai tabel laporan
                distance_stats.columns = [
                    "Kelas",
                    "Jumlah Paket",
                    "Rata-rata Jarak",
                    "Jarak Minimum",
                    "Jarak Maksimum",
                    "Standar Deviasi"
                ]

                # tampilkan tabel
                st.table(distance_stats)

            else:
                st.warning("Tidak ada paket IP di file.")
        else:
            st.error("Tidak ada paket yang bisa dibaca.")
