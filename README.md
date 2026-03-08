
# Sistem Deteksi Anomali Trafik Jaringan dengan Metode K-Means Clustering

Aplikasi ini adalah sistem **deteksi anomali trafik jaringan** berbasis **Streamlit** yang menggunakan metode **K-Means Clustering**.  
Aplikasi dapat menganalisis trafik jaringan secara **real-time** maupun dari **file PCAP**.

----------

# Requirements

Pastikan software berikut sudah terinstall:

-   **Python 3.8+**
    
-   **Wireshark / TShark**
    
-   **Git**
    

Cek apakah TShark sudah tersedia:

    tshark -v

Jika belum ada, install **Wireshark** dari:

[https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

Saat instalasi, pastikan **TShark ikut diinstall**.

----------

# 1. Clone Repository

    git clone https://github.com/username/network-anomaly-detection.git  
    cd network-anomaly-detection

----------

# 2. Buat Virtual Environment (Opsional)

    python -m venv venv

Aktifkan environment:

Windows

    venv\Scripts\activate

Linux / Mac

    source venv/bin/activate

----------

# 3. Install Dependencies

    pip install -r requirements.txt

Jika belum ada `requirements.txt`, install manual:

    pip install streamlit pandas numpy plotly scapy pyshark scikit-learn

----------

# 4. Menjalankan Aplikasi

Jalankan aplikasi Streamlit:

    streamlit run app.py

Setelah itu buka browser:

    http://localhost:8501

----------

# 5. Mode Penggunaan

Aplikasi menyediakan dua mode analisis:

### Real-Time Capture

Menangkap paket jaringan langsung dari interface menggunakan **TShark**.

### Upload PCAP

Mengupload file **.pcap** atau **.pcapng** untuk dianalisis.

----------

# 6. Output Sistem

Aplikasi akan menampilkan:

-   Total paket jaringan
    
-   Jumlah paket anomali
    
-   Nilai Silhouette Score
    
-   Jumlah cluster terbaik
    
-   Visualisasi jarak terhadap centroid
    
-   Tabel paket jaringan dan fitur yang diekstrak
