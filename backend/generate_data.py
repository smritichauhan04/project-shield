"""
Project Shield - Data Generation Script
Generates simulated NSL-KDD style security log data for training and demo.
"""
import numpy as np
import pandas as pd
import os

np.random.seed(42)

# ── Feature columns (NSL-KDD inspired) ─────────────────────────────────────
ATTACK_TYPES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
PROTOCOLS    = ["tcp", "udp", "icmp"]
SERVICES     = ["http", "ftp", "smtp", "ssh", "dns", "telnet", "pop3", "imap"]
FLAGS        = ["SF", "S0", "REJ", "RSTO", "SH", "OTH"]

def generate_normal(n=600):
    return pd.DataFrame({
        "duration":         np.random.exponential(5, n),
        "protocol_type":    np.random.choice(PROTOCOLS, n, p=[0.7, 0.2, 0.1]),
        "service":          np.random.choice(SERVICES, n),
        "flag":             np.random.choice(FLAGS, n, p=[0.85,0.05,0.04,0.03,0.02,0.01]),
        "src_bytes":        np.random.exponential(2000, n),
        "dst_bytes":        np.random.exponential(1500, n),
        "land":             np.zeros(n, dtype=int),
        "wrong_fragment":   np.random.poisson(0.01, n),
        "urgent":           np.zeros(n, dtype=int),
        "hot":              np.random.poisson(1, n),
        "num_failed_logins": np.zeros(n, dtype=int),
        "logged_in":        np.ones(n, dtype=int),
        "num_compromised":  np.zeros(n, dtype=int),
        "count":            np.random.randint(1, 50, n),
        "srv_count":        np.random.randint(1, 50, n),
        "same_srv_rate":    np.random.uniform(0.7, 1.0, n),
        "diff_srv_rate":    np.random.uniform(0.0, 0.3, n),
        "dst_host_count":   np.random.randint(50, 255, n),
        "label":            ["Normal"] * n
    })

def generate_dos(n=120):
    return pd.DataFrame({
        "duration":         np.zeros(n),
        "protocol_type":    np.random.choice(PROTOCOLS, n, p=[0.5, 0.3, 0.2]),
        "service":          np.random.choice(["http", "smtp", "ftp"], n),
        "flag":             np.random.choice(["S0", "REJ", "SF"], n, p=[0.6, 0.3, 0.1]),
        "src_bytes":        np.random.exponential(100, n),
        "dst_bytes":        np.zeros(n),
        "land":             np.random.choice([0, 1], n, p=[0.9, 0.1]),
        "wrong_fragment":   np.random.poisson(0.5, n),
        "urgent":           np.zeros(n, dtype=int),
        "hot":              np.zeros(n, dtype=int),
        "num_failed_logins": np.zeros(n, dtype=int),
        "logged_in":        np.zeros(n, dtype=int),
        "num_compromised":  np.zeros(n, dtype=int),
        "count":            np.random.randint(200, 512, n),
        "srv_count":        np.random.randint(200, 512, n),
        "same_srv_rate":    np.random.uniform(0.9, 1.0, n),
        "diff_srv_rate":    np.random.uniform(0.0, 0.1, n),
        "dst_host_count":   np.random.randint(1, 30, n),
        "label":            ["DoS"] * n
    })

def generate_probe(n=80):
    return pd.DataFrame({
        "duration":         np.random.uniform(0, 2, n),
        "protocol_type":    np.random.choice(PROTOCOLS, n, p=[0.3, 0.3, 0.4]),
        "service":          np.random.choice(SERVICES, n),
        "flag":             np.random.choice(FLAGS, n, p=[0.4, 0.3, 0.15, 0.1, 0.03, 0.02]),
        "src_bytes":        np.random.exponential(500, n),
        "dst_bytes":        np.random.exponential(300, n),
        "land":             np.zeros(n, dtype=int),
        "wrong_fragment":   np.random.poisson(0.1, n),
        "urgent":           np.zeros(n, dtype=int),
        "hot":              np.random.poisson(3, n),
        "num_failed_logins": np.zeros(n, dtype=int),
        "logged_in":        np.random.choice([0, 1], n, p=[0.6, 0.4]),
        "num_compromised":  np.zeros(n, dtype=int),
        "count":            np.random.randint(100, 255, n),
        "srv_count":        np.random.randint(1, 30, n),
        "same_srv_rate":    np.random.uniform(0.1, 0.5, n),
        "diff_srv_rate":    np.random.uniform(0.5, 1.0, n),
        "dst_host_count":   np.random.randint(100, 255, n),
        "label":            ["Probe"] * n
    })

def generate_r2l(n=40):
    return pd.DataFrame({
        "duration":         np.random.exponential(50, n),
        "protocol_type":    np.random.choice(["tcp", "udp"], n, p=[0.8, 0.2]),
        "service":          np.random.choice(["ftp", "telnet", "smtp", "imap"], n),
        "flag":             np.random.choice(["SF", "RSTO"], n, p=[0.7, 0.3]),
        "src_bytes":        np.random.exponential(5000, n),
        "dst_bytes":        np.random.exponential(3000, n),
        "land":             np.zeros(n, dtype=int),
        "wrong_fragment":   np.zeros(n, dtype=int),
        "urgent":           np.zeros(n, dtype=int),
        "hot":              np.random.poisson(8, n),
        "num_failed_logins": np.random.poisson(3, n),
        "logged_in":        np.zeros(n, dtype=int),
        "num_compromised":  np.random.poisson(2, n),
        "count":            np.random.randint(1, 10, n),
        "srv_count":        np.random.randint(1, 10, n),
        "same_srv_rate":    np.random.uniform(0.5, 1.0, n),
        "diff_srv_rate":    np.random.uniform(0.0, 0.5, n),
        "dst_host_count":   np.random.randint(1, 20, n),
        "label":            ["R2L"] * n
    })

def generate_u2r(n=20):
    return pd.DataFrame({
        "duration":         np.random.exponential(100, n),
        "protocol_type":    ["tcp"] * n,
        "service":          np.random.choice(["telnet", "ssh", "ftp"], n),
        "flag":             ["SF"] * n,
        "src_bytes":        np.random.exponential(8000, n),
        "dst_bytes":        np.random.exponential(5000, n),
        "land":             np.zeros(n, dtype=int),
        "wrong_fragment":   np.zeros(n, dtype=int),
        "urgent":           np.random.poisson(0.5, n).astype(int),
        "hot":              np.random.poisson(15, n),
        "num_failed_logins": np.random.poisson(1, n),
        "logged_in":        np.ones(n, dtype=int),
        "num_compromised":  np.random.poisson(10, n),
        "count":            np.random.randint(1, 5, n),
        "srv_count":        np.random.randint(1, 5, n),
        "same_srv_rate":    np.random.uniform(0.8, 1.0, n),
        "diff_srv_rate":    np.random.uniform(0.0, 0.2, n),
        "dst_host_count":   np.random.randint(1, 10, n),
        "label":            ["U2R"] * n
    })

def main():
    os.makedirs("data", exist_ok=True)
    df = pd.concat([
        generate_normal(),
        generate_dos(),
        generate_probe(),
        generate_r2l(),
        generate_u2r()
    ], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    df.to_csv("data/security_logs.csv", index=False)
    print(f"[✓] Generated {len(df)} records -> data/security_logs.csv")
    print(df["label"].value_counts())

if __name__ == "__main__":
    main()
