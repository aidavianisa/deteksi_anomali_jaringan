
# Network Anomaly Detector (K-Means)

Aplikasi ini merupakan sistem deteksi anomali trafik jaringan berbasis metode K-Means Clustering. Sistem dapat berjalan dalam dua mode, yaitu real-time capture dan analisis file PCAP (offline). Aplikasi dibangun menggunakan Streamlit, Scikit-Learn, serta tools analisis jaringan seperti TShark, PyShark, dan Scapy.

----------

## Fitur Utama

-   Clustering trafik jaringan menggunakan K-Means
    
-   Penentuan jumlah cluster otomatis menggunakan Silhouette Score
    
-   Deteksi anomali meliputi:
    
    -   Traffic Spike
        
    -   Protocol Flood
        
    -   Port Scan
        
    -   Silence / Drop
    
-   Visualisasi interaktif menggunakan Plotly
    
-   Mode real-time dan offline PCAP
    

----------

## Struktur Proyek

    project/  
    ├── deteksi_anomali.py  
    ├── realtime_analyzer.py  
    ├── alarm.wav (opsional)  
    └── README.md

----------

## Persyaratan Sistem

Gunakan Python versi 3.9 atau lebih baru.

### Instalasi TShark (Wajib)

Ubuntu atau Debian:

    sudo apt update  
    sudo apt install tshark

Windows:

Unduh dan instal Wireshark dari:  
[https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

Pastikan komponen TShark dicentang saat proses instalasi.

----------

## Verifikasi Instalasi TShark

    tshark -v

Jika versi TShark tampil, maka instalasi berhasil.

----------

## Instalasi Dependensi Python

    pip install streamlit pandas plotly numpy scikit-learn pyshark scapy

Jika terjadi masalah pada PyShark:

    pip install --upgrade pyshark

----------

## Cara Menjalankan Aplikasi

Masuk ke direktori proyek:

    cd project

Jalankan aplikasi:

    streamlit run deteksi_anomali.py

Aplikasi dapat diakses melalui browser pada alamat:

    http://localhost:8501

----------

## Catatan

-   Jalankan aplikasi sebagai Administrator atau root jika proses real-time capture gagal.
    
-   Pastikan interface jaringan dalam keadaan aktif.
    
-   File alarm.wav bersifat opsional dan digunakan untuk fitur alarm.
