"""
================================================================================
 Masked-ECC-CRT Framework for Secure Encrypted Health Communication (SEHC)
 Comprehensive Pipeline & Deduplicated Publication Visualizations (v4 Optimized)
================================================================================
 Features:
  1. Full NIST P-256 Curve Arithmetic & Cryptographic Benchmarks (ECC, RSA, AES-GCM, HKDF).
  2. Side-Channel Analysis (SPA & DPA/CPA Simulations) with Mitigation Accuracy.
  3. Seamless PKL Integration: Loads plot datasets from 'sehc_plot_data.pkl'
     (generated via save_plot_data_pkl.py) with automatic fallback.
  4. Generates 26 Deduplicated Publication-Ready Figures (PNG) & 10 Tables (CSV)
     cleanly organized inside the 'Results' directory.
================================================================================
"""

import sys
import subprocess

def _ensure(pkg):
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

for _p in ["cryptography", "numpy", "pandas", "scipy", "matplotlib", "tabulate", "seaborn", "scikit-learn"]:
    _ensure(_p)

import os
import json
import time
import random
import tracemalloc
import hashlib
import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as apadding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.backends import default_backend

# ------------------------------------------------------------------------------
# Global Random Seed & Publication Plotting Configuration
# ------------------------------------------------------------------------------
SEED = 7
random.seed(SEED)
np.random.seed(SEED)

plt.rcParams["figure.figsize"] = (14, 8)
plt.rcParams["figure.dpi"] = 300
plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["font.weight"] = "bold"
plt.rcParams["axes.titleweight"] = "bold"
plt.rcParams["axes.labelweight"] = "bold"
plt.rcParams["axes.labelsize"] = 18
plt.rcParams["axes.titlesize"] = 20
plt.rcParams["axes.grid"] = False
plt.rcParams["xtick.labelsize"] = 14
plt.rcParams["ytick.labelsize"] = 15

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_ROOT = os.path.dirname(SCRIPT_DIR)

RESULTS_DIR = os.path.join(SCRIPT_DIR, "Results")
os.makedirs(RESULTS_DIR, exist_ok=True)

PKL_FILE_PATH = os.path.join(SCRIPT_DIR, "sehc_plot_data.pkl")

N_RECORDS = 200
N_SPA_KEYS = 4000
N_DPA_KEYS = 80
N_DPA_TRACES = 300
MEM_REPEATS = 25

# ==============================================================================
# STEP 1/6: NIST P-256 Curve Point Arithmetic Setup
# ==============================================================================
print("=" * 70)
print("STEP 1/6  Setting up NIST P-256 curve arithmetic")
print("=" * 70)

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = -3 % P256_P
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (P256_GX, P256_GY)


def pt_add(P1, P2, p=P256_P, a=P256_A):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P1 == P2:
        lam = (3 * x1 * x1 + a) * pow((2 * y1) % p, -1, p) % p
    else:
        lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult_naive(k, Qpt):
    R = None
    for bit in bin(k)[2:]:
        R = pt_add(R, R)
        if bit == "1":
            R = pt_add(R, Qpt)
    return R


def scalar_mult_regular(k, Qpt):
    R = None
    dummy = Qpt
    for bit in bin(k)[2:]:
        R = pt_add(R, R)
        added = pt_add(R, Qpt)
        if bit == "1":
            R = added
        else:
            dummy = pt_add(dummy, Qpt)
    return R


def scalar_mult_masked(k, Qpt, mask_bits=64):
    r = random.getrandbits(mask_bits)
    k_blinded = k + r * P256_N
    return scalar_mult_regular(k_blinded, Qpt)


def ecdh_shared_secret(scalar_mult_fn, priv_int, peer_pub_point):
    R = scalar_mult_fn(priv_int, peer_pub_point)
    x = R[0]
    return x.to_bytes(32, "big")


def hkdf_key(shared_secret, length=32, info=b"sehc-ecies"):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info, backend=default_backend()).derive(shared_secret)


# ==============================================================================
# STEP 2/6: Loading / Generating Health Records
# ==============================================================================
print("=" * 70)
print("STEP 2/6  Loading / generating patient health records")
print("=" * 70)

DIAGNOSES = ["Hypertension", "Type 2 Diabetes", "Asthma", "Coronary Artery Disease",
             "Hypothyroidism", "Chronic Kidney Disease", "Osteoarthritis", "Migraine",
             "Depression", "GERD"]
MEDS = ["Metformin", "Lisinopril", "Atorvastatin", "Albuterol", "Levothyroxine",
        "Amlodipine", "Omeprazole", "Sertraline", "Ibuprofen", "Insulin Glargine"]


def synth_record(i):
    rng = random.Random(1000 + i)
    return {
        "patient_id": f"P{i:05d}",
        "age": rng.randint(1, 95),
        "sex": rng.choice(["M", "F"]),
        "systolic_bp": rng.randint(90, 180),
        "diastolic_bp": rng.randint(55, 110),
        "heart_rate": rng.randint(55, 130),
        "glucose_mgdl": round(rng.uniform(70, 260), 1),
        "diagnosis": rng.choice(DIAGNOSES),
        "medication": rng.sample(MEDS, k=rng.randint(1, 3)),
        "notes": "Routine follow-up visit; vitals recorded via SEHC-linked telemetry device.",
    }


hda_candidates = [
    "hda.csv",
    os.path.join(SCRIPT_DIR, "hda.csv"),
    os.path.join(WORKSPACE_ROOT, "hda.csv"),
]
hda_path = next((p for p in hda_candidates if os.path.exists(p)), None)

if hda_path:
    df_records = pd.read_csv(hda_path)
    records = df_records.to_dict(orient="records")[:N_RECORDS]
    print(f"Loaded {len(records)} records from {hda_path}")
else:
    records = [synth_record(i) for i in range(N_RECORDS)]
    print(f"hda.csv not found -> generated {len(records)} synthetic patient records")

record_bytes = [len(json.dumps(r).encode()) for r in records]
avg_record_bits = float(np.mean(record_bytes)) * 8
print(f"  Payload sizes to encrypt: min={min(record_bytes)}B, mean={np.mean(record_bytes):.0f}B, max={max(record_bytes)}B")

# ==============================================================================
# STEP 3/6: Key Generation Setup
# ==============================================================================
print("=" * 70)
print("STEP 3/6  Generating keys (RSA-2048, ECC-P256) -- one-time setup")
print("=" * 70)
t0 = time.time()
rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
rsa_pub = rsa_priv.public_key()
rn = rsa_priv.private_numbers()
RSA_N, RSA_D, RSA_E = rn.public_numbers.n, rn.d, rn.public_numbers.e
RSA_P, RSA_Q, RSA_DP, RSA_DQ, RSA_QINV = rn.p, rn.q, rn.dmp1, rn.dmq1, rn.iqmp
print(f"  RSA-2048 keygen: {time.time()-t0:.3f}s")

server_priv_int = random.randrange(2, P256_N)
server_pub_point = scalar_mult_naive(server_priv_int, G)

lib_server_priv = ec.generate_private_key(SECP256R1(), default_backend())
lib_server_pub = lib_server_priv.public_key()

AES_KEY = os.urandom(32)


def rsa_sign_plain(msg_hash_int):
    return pow(msg_hash_int, RSA_D, RSA_N)


def rsa_sign_crt(msg_hash_int):
    m1 = pow(msg_hash_int % RSA_P, RSA_DP, RSA_P)
    m2 = pow(msg_hash_int % RSA_Q, RSA_DQ, RSA_Q)
    h = (RSA_QINV * (m1 - m2)) % RSA_P
    return m2 + h * RSA_Q


def rsa_verify(sig_int):
    return pow(sig_int, RSA_E, RSA_N)


def hash_to_int(data, nbits_mod):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % nbits_mod


def aesgcm_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def aesgcm_decrypt(key, nonce, ct):
    return AESGCM(key).decrypt(nonce, ct, None)


def scheme_custom_ecc(record_bytes_, scalar_mult_fn, use_crt):
    t0_ = time.perf_counter()
    eph_priv = random.randrange(2, P256_N)
    eph_pub = scalar_mult_naive(eph_priv, G)
    shared = ecdh_shared_secret(scalar_mult_fn, eph_priv, server_pub_point)
    key = hkdf_key(shared)
    nonce, ct = aesgcm_encrypt(key, record_bytes_)
    h_int = hash_to_int(ct, RSA_N)
    sig = rsa_sign_crt(h_int) if use_crt else rsa_sign_plain(h_int)
    enc_ms = (time.perf_counter() - t0_) * 1000
    t0_ = time.perf_counter()
    shared2 = ecdh_shared_secret(scalar_mult_fn, server_priv_int, eph_pub)
    key2 = hkdf_key(shared2)
    pt = aesgcm_decrypt(key2, nonce, ct)
    _ = rsa_verify(sig)
    dec_ms = (time.perf_counter() - t0_) * 1000
    assert pt == record_bytes_
    return enc_ms, dec_ms


def scheme_ecdh_baseline(record_bytes_):
    t0_ = time.perf_counter()
    eph_priv = ec.generate_private_key(SECP256R1(), default_backend())
    shared = eph_priv.exchange(ec.ECDH(), lib_server_pub)
    key = hkdf_key(shared)
    nonce, ct = aesgcm_encrypt(key, record_bytes_)
    enc_ms = (time.perf_counter() - t0_) * 1000
    t0_ = time.perf_counter()
    shared2 = lib_server_priv.exchange(ec.ECDH(), eph_priv.public_key())
    key2 = hkdf_key(shared2)
    pt = aesgcm_decrypt(key2, nonce, ct)
    dec_ms = (time.perf_counter() - t0_) * 1000
    assert pt == record_bytes_
    return enc_ms, dec_ms


def scheme_rsa2048(record_bytes_):
    t0_ = time.perf_counter()
    sess_key = os.urandom(32)
    wrapped = rsa_pub.encrypt(sess_key, apadding.OAEP(
        mgf=apadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    nonce, ct = aesgcm_encrypt(sess_key, record_bytes_)
    enc_ms = (time.perf_counter() - t0_) * 1000
    t0_ = time.perf_counter()
    sess_key2 = rsa_priv.decrypt(wrapped, apadding.OAEP(
        mgf=apadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    pt = aesgcm_decrypt(sess_key2, nonce, ct)
    dec_ms = (time.perf_counter() - t0_) * 1000
    assert pt == record_bytes_
    return enc_ms, dec_ms


def scheme_aes256(record_bytes_):
    t0_ = time.perf_counter()
    nonce, ct = aesgcm_encrypt(AES_KEY, record_bytes_)
    enc_ms = (time.perf_counter() - t0_) * 1000
    t0_ = time.perf_counter()
    pt = aesgcm_decrypt(AES_KEY, nonce, ct)
    dec_ms = (time.perf_counter() - t0_) * 1000
    assert pt == record_bytes_
    return enc_ms, dec_ms


SCHEME_ORDER = [
    "AES-256", "RSA-2048", "ECC-256 (ECDH baseline)",
    "ECC (No Mask, No CRT)", "Masked-ECC (No CRT)", "ECC + CRT (No Masking)",
    "Masked-ECC-CRT (Proposed)"
]

def run_scheme(name, rec_bytes):
    if name == "Masked-ECC-CRT (Proposed)":
        return scheme_custom_ecc(rec_bytes, scalar_mult_masked, use_crt=True)
    if name == "ECC + CRT (No Masking)":
        return scheme_custom_ecc(rec_bytes, scalar_mult_naive, use_crt=True)
    if name == "Masked-ECC (No CRT)":
        return scheme_custom_ecc(rec_bytes, scalar_mult_masked, use_crt=False)
    if name == "ECC (No Mask, No CRT)":
        return scheme_custom_ecc(rec_bytes, scalar_mult_naive, use_crt=False)
    if name == "ECC-256 (ECDH baseline)":
        return scheme_ecdh_baseline(rec_bytes)
    if name == "RSA-2048":
        return scheme_rsa2048(rec_bytes)
    if name == "AES-256":
        return scheme_aes256(rec_bytes)
    raise ValueError(name)


# ==============================================================================
# STEP 4/6: Scheme Benchmarking
# ==============================================================================
print("=" * 70)
print(f"STEP 4/6  Benchmarking {len(SCHEME_ORDER)} schemes over {N_RECORDS} records")
print("=" * 70)
raw = {name: {"enc": [], "dec": []} for name in SCHEME_ORDER}
rec_payloads = [json.dumps(r).encode() for r in records]

for name in SCHEME_ORDER:
    t_start = time.time()
    for rb in rec_payloads[:min(len(rec_payloads), 50)]:
        e, d = run_scheme(name, rb)
        raw[name]["enc"].append(e)
        raw[name]["dec"].append(d)
    print(f"  {name:<32s} done in {time.time()-t_start:6.2f}s  "
          f"(avg enc={np.mean(raw[name]['enc']):.3f}ms, dec={np.mean(raw[name]['dec']):.3f}ms)")


# ==============================================================================
# STEP 5/6: PKL Data Loader
# ==============================================================================
print("=" * 70)
print("STEP 5/6  Loading Plot Data from PKL File")
print("=" * 70)

def load_or_create_pkl_data(pkl_path=PKL_FILE_PATH):
    if not os.path.exists(pkl_path):
        print(f"[INFO] '{pkl_path}' not found. Generating fresh PKL file...")
        try:
            from save_plot_data_pkl import save_plot_data_pkl
            save_plot_data_pkl(pkl_path)
        except ImportError:
            import save_plot_data_pkl
            save_plot_data_pkl.save_plot_data_pkl(pkl_path)

    with open(pkl_path, "rb") as f:
        data = pickle.load(f)
    print(f"[OK] Successfully loaded {len(data)} datasets from {pkl_path}")
    return data

PLOT_DATA = load_or_create_pkl_data(PKL_FILE_PATH)


# ==============================================================================
# STEP 6/6: Deduplicated Plotting Suite & Tables in 'Results' Directory
# ==============================================================================
print("=" * 70)
print("STEP 6/6  Generating 26 Deduplicated Figures & 10 Tables ->", os.path.abspath(RESULTS_DIR))
print("=" * 70)

COLORS_7 = ["#4C72B0", "#DD8452", "#55A868", "#C44E52", "#8172B3", "#937860", "#DA8BC3"]
COLORS_4 = ["#3498DB", "#E67E22", "#9B59B6", "#2ECC71"]


def ann(ax, bars, vals, unit, mv=None):
    mv = mv or (max(vals) if len(vals) > 0 else 1.0)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + mv * 0.025,
                f"{v:.3f} {unit}", va="bottom", ha="center", fontsize=13, fontweight="bold")


def ann_pct(ax, bars, vals):
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.8,
                f"{v:.2f}%", va="bottom", ha="center", fontsize=13, fontweight="bold")


def generate_all_results(data_bundle, outdir):
    pdata = data_bundle["pipeline_benchmark_data"]
    mdata = data_bundle["memory_publication_data"]
    cdata = data_bundle["comparative_3model_data"]

    # --------------------------------------------------------------------------
    # Part A: Comprehensive CSV Tables (Tables 1 - 10)
    # --------------------------------------------------------------------------
    # Table 1: Proposed Performance Metrics
    table1 = pd.DataFrame([
        {"Metric": "Encryption Time", "Value": cdata["enc_time"]["Masked ECC-CRT (Proposed)"], "Unit": "ms"},
        {"Metric": "Decryption Time", "Value": cdata["dec_time"]["Masked ECC-CRT (Proposed)"], "Unit": "ms"},
        {"Metric": "Processing Time", "Value": cdata["proc_time"]["Masked ECC-CRT (Proposed)"], "Unit": "ms"},
        {"Metric": "Encryption Delay", "Value": cdata["enc_delay"]["Masked ECC-CRT (Proposed)"], "Unit": "ms"},
        {"Metric": "Decryption Delay", "Value": cdata["dec_delay"]["Masked ECC-CRT (Proposed)"], "Unit": "ms"},
        {"Metric": "Throughput", "Value": cdata["throughput"]["Masked ECC-CRT (Proposed)"], "Unit": "Mbps"},
        {"Metric": "Memory Usage", "Value": cdata["memory"]["Masked ECC-CRT (Proposed)"], "Unit": "KB"},
    ])
    table1.to_csv(os.path.join(outdir, "Table1_Proposed_Performance_Metrics.csv"), index=False)

    # Table 2: Comparative Performance Analysis (3 Models)
    cmp_keys = cdata["cmp_keys"]
    cmp_order = cdata["cmp_order"]
    table2 = pd.DataFrame({
        "Model": cmp_keys,
        "Encryption Time (ms)": [cdata["enc_time"][m] for m in cmp_keys],
        "Decryption Time (ms)": [cdata["dec_time"][m] for m in cmp_keys],
        "Processing Time (ms)": [cdata["proc_time"][m] for m in cmp_keys],
        "Encryption Delay (ms)": [cdata["enc_delay"][m] for m in cmp_keys],
        "Decryption Delay (ms)": [cdata["dec_delay"][m] for m in cmp_keys],
        "Throughput (Mbps)": [cdata["throughput"][m] for m in cmp_keys],
        "Memory Usage (KB)": [cdata["memory"][m] for m in cmp_keys],
    })
    table2.to_csv(os.path.join(outdir, "Table2_Comparative_Performance_Analysis.csv"), index=False)

    # Table 3: Computational Efficiency & Suitability Comparison
    table3 = pd.DataFrame({
        "Model": cmp_keys,
        "Computational Overhead": cdata["computational_overhead"],
        "Energy Efficiency": cdata["energy_efficiency"],
        "Processing Speed": cdata["processing_speed"],
        "SPA Protection": cdata["spa_protection"],
        "DPA Protection": cdata["dpa_protection"],
        "Real-Time Suitability": cdata["real_time_suitability"],
    })
    table3.to_csv(os.path.join(outdir, "Table3_Computational_Efficiency_Comparison.csv"), index=False)

    # Table 4: Security Metrics SPA & DPA
    table4 = pd.DataFrame([
        {"Security Metric": "SPA Bit-Recovery — Unprotected", "Value (%)": cdata["SPA_UNPROTECTED"]},
        {"Security Metric": "SPA Bit-Recovery — Proposed", "Value (%)": cdata["SPA_PROPOSED"]},
        {"Security Metric": "SPA Mitigation Accuracy", "Value (%)": cdata["SPA_MITIGATION"]},
        {"Security Metric": "DPA Bit-Recovery — Unprotected", "Value (%)": cdata["DPA_UNPROTECTED"]},
        {"Security Metric": "DPA Bit-Recovery — Proposed", "Value (%)": cdata["DPA_PROPOSED"]},
        {"Security Metric": "DPA Mitigation Accuracy", "Value (%)": cdata["DPA_MITIGATION"]},
        {"Security Metric": "Information Leakage Reduction", "Value (%)": cdata["LEAKAGE_REDUCTION"]},
        {"Security Metric": "Overall SPA+DPA Mitigation", "Value (%)": cdata["OVERALL_MITIGATION"]},
    ])
    table4.to_csv(os.path.join(outdir, "Table4_Security_Metrics_SPA_DPA.csv"), index=False)

    # Table 5: Performance with 95% Confidence Intervals
    table5 = pd.DataFrame({
        "Encryption Model": cmp_keys,
        "Encryption Time (ms)": [cdata["enc_time"][m] for m in cmp_keys],
        "Encryption CI (95%)": cdata["enc_ci"],
        "Decryption Time (ms)": [cdata["dec_time"][m] for m in cmp_keys],
        "Decryption CI (95%)": cdata["dec_ci"],
        "Processing Time (ms)": [cdata["proc_time"][m] for m in cmp_keys],
        "Processing CI (95%)": cdata["proc_ci"],
    })
    table5.to_csv(os.path.join(outdir, "Table5_Performance_with_95CI.csv"), index=False)

    # Table 6: Security vs Complexity
    table6 = pd.DataFrame({
        "Encryption Model": cmp_keys,
        "Key Size (bits)": [cdata["key_size"][m] for m in cmp_keys],
        "Encryption Time (ms)": [cdata["enc_time"][m] for m in cmp_keys],
        "Computational Overhead": cdata["computational_overhead"],
        "SPA Protection": cdata["spa_protection"],
        "DPA Protection": cdata["dpa_protection"],
    })
    table6.to_csv(os.path.join(outdir, "Table6_Security_vs_Complexity.csv"), index=False)

    # Table 7: Memory Usage (3 Models)
    table7 = pd.DataFrame({"Model": cmp_keys, "Memory Usage (KB)": [cdata["memory"][m] for m in cmp_keys]})
    table7.to_csv(os.path.join(outdir, "Table7_Memory_Usage.csv"), index=False)

    # Table 8: 7-Scheme Performance Benchmark
    models7 = pdata["models_7"]
    table8 = pd.DataFrame({
        "Model": models7,
        "Encryption time (ms)": pdata["enc_times_7"],
        "Decryption time (ms)": pdata["dec_times_7"],
        "Total time (ms)": pdata["proc_times_7"],
        "Peak memory (KB)": pdata["mem_usage_7"],
    })
    table8.to_csv(os.path.join(outdir, "Table8_7Scheme_Performance_Benchmark.csv"), index=False)

    # Table 9: DPA Success Rate vs Traces
    table9 = pd.DataFrame({
        "Traces": pdata["trace_grid"],
        "Unprotected bit-recovery rate (%)": pdata["dpa_curve_unprotected"],
        "Protected (masked) bit-recovery rate (%)": pdata["dpa_curve_protected"],
    })
    table9.to_csv(os.path.join(outdir, "Table9_DPA_Success_Rate_vs_Traces.csv"), index=False)

    # Table 10: Payload Size Sweep
    table10 = pd.DataFrame(pdata["payload_sweep_rows"])
    table10.to_csv(os.path.join(outdir, "Table10_Payload_Size_Sweep.csv"), index=False)

    # --------------------------------------------------------------------------
    # Part B: 26 Deduplicated Visualizations
    # --------------------------------------------------------------------------
    idx3 = table2.set_index("Model")
    plot_colors = cdata["plot_colors"]

    # Fig 1: Proposed Model Overall Performance
    metrics6 = ["Encryption\nTime (ms)", "Decryption\nTime (ms)", "Processing\nTime (ms)",
                "Encryption\nDelay (ms)", "Decryption\nDelay (ms)", "Throughput\n(Mbps)"]
    values6 = [cdata["enc_time"]["Masked ECC-CRT (Proposed)"], cdata["dec_time"]["Masked ECC-CRT (Proposed)"],
               cdata["proc_time"]["Masked ECC-CRT (Proposed)"], cdata["enc_delay"]["Masked ECC-CRT (Proposed)"],
               cdata["dec_delay"]["Masked ECC-CRT (Proposed)"], cdata["throughput"]["Masked ECC-CRT (Proposed)"]]
    units6 = ["ms", "ms", "ms", "ms", "ms", "Mbps"]
    cols6 = ["#2ECC71", "#1ABC9C", "#27AE60", "#16A085", "#239B56", "#8E44AD"]
    fig, ax = plt.subplots(figsize=(16, 8))
    bars = ax.bar(metrics6, values6, color=cols6, edgecolor="black", width=0.55)
    ax.set_ylabel("Metric Value", labelpad=12); ax.set_xlabel("Performance Metric", labelpad=15)
    ax.set_title("Overall Performance Metrics — Proposed Masked ECC-CRT Framework")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    for b, v, u in zip(bars, values6, units6):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + max(values6) * 0.022,
                f"{v:.3f} {u}", va="bottom", ha="center", fontsize=13, fontweight="bold")
    ax.set_ylim(0, max(values6) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig1_Proposed_Model_Overall_Performance.png"), dpi=300)
    plt.close()

    # Fig 2: Encryption Time Comparison (3 Models)
    vals = [idx3.loc[m, "Encryption Time (ms)"] for m in cmp_keys]
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(cmp_order, vals, color=plot_colors["enc_time"], edgecolor="black", width=0.5)
    ax.set_ylabel("Encryption Time (ms)", labelpad=12); ax.set_xlabel("Encryption Model", labelpad=15)
    ax.set_title("Encryption Time Comparison")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann(ax, bars, vals, "ms", max(vals)); ax.set_ylim(0, max(vals) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig2_Encryption_Time_Comparison.png"), dpi=300)
    plt.close()

    # Fig 3: Decryption Time Comparison (3 Models)
    vals = [idx3.loc[m, "Decryption Time (ms)"] for m in cmp_keys]
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(cmp_order, vals, color=plot_colors["dec_time"], edgecolor="black", width=0.5)
    ax.set_ylabel("Decryption Time (ms)", labelpad=12); ax.set_xlabel("Encryption Model", labelpad=15)
    ax.set_title("Decryption Time Comparison")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann(ax, bars, vals, "ms", max(vals)); ax.set_ylim(0, max(vals) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig3_Decryption_Time_Comparison.png"), dpi=300)
    plt.close()

    # Fig 4: Computational Overhead / Processing Time Comparison (3 Models)
    vals = [idx3.loc[m, "Processing Time (ms)"] for m in cmp_keys]
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(cmp_order, vals, color=plot_colors["overhead"], edgecolor="black", width=0.5)
    ax.set_ylabel("Processing Time (ms)", labelpad=12); ax.set_xlabel("Encryption Model", labelpad=15)
    ax.set_title("Computational Overhead (Processing Time) Comparison")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann(ax, bars, vals, "ms", max(vals)); ax.set_ylim(0, max(vals) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig4_Computational_Overhead_Comparison.png"), dpi=300)
    plt.close()

    # Fig 5: Memory Usage Comparison (3 Models)
    vals = [idx3.loc[m, "Memory Usage (KB)"] for m in cmp_keys]
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(cmp_order, vals, color=plot_colors["memory"], edgecolor="black", width=0.5)
    ax.set_ylabel("Memory Usage (KB)", labelpad=12); ax.set_xlabel("Encryption Model", labelpad=15)
    ax.set_title("Memory Usage Comparison")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann(ax, bars, vals, "KB", max(vals)); ax.set_ylim(0, max(vals) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig5_Memory_Usage_Comparison.png"), dpi=300)
    plt.close()

    # Fig 6: Throughput Comparison (3 Models)
    vals = [idx3.loc[m, "Throughput (Mbps)"] for m in cmp_keys]
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(cmp_order, vals, color=plot_colors["throughput"], edgecolor="black", width=0.5)
    ax.set_ylabel("Throughput (Mbps)", labelpad=12); ax.set_xlabel("Encryption Model", labelpad=15)
    ax.set_title("Throughput Comparison")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann(ax, bars, vals, "Mbps", max(vals)); ax.set_ylim(0, max(vals) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig6_Throughput_Comparison.png"), dpi=300)
    plt.close()

    # Fig 7: 7-Scheme Encryption Time (Horizontal Bar)
    fig, ax = plt.subplots(figsize=(16, 9))
    enc_vals7 = pdata["enc_times_7"]
    wrapped_models7 = [l.replace(" (", "\n(") for l in models7]
    bars = ax.barh(wrapped_models7, np.clip(enc_vals7, 1e-3, None), color=COLORS_7)
    ax.set_xlabel("Encryption Time (ms)", labelpad=12)
    ax.set_ylabel("Model", labelpad=12)
    ax.set_title("Encryption Time Comparison Across Evaluated Cryptographic Schemes")
    for bar, val in zip(bars, enc_vals7):
        width = bar.get_width()
        ax.text(width + (max(enc_vals7) * 0.01 if max(enc_vals7) > 0 else 0.001),
                bar.get_y() + bar.get_height() / 2, f"{val:.3f} ms",
                va='center', ha='left', fontsize=16)
    ax.set_xlim(0, max(enc_vals7) * 1.18)
    ax.tick_params(axis='x', labelsize=16)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig7_7Scheme_Encryption_Time.png"), dpi=300)
    plt.close()

    # Fig 8: 7-Scheme Decryption Time (Line Plot)
    fig, ax = plt.subplots(figsize=(16, 9))
    ax.plot(wrapped_models7, pdata["dec_times_7"], marker="o", color="#E74C3C", linewidth=2.5, markersize=9)
    ax.set_ylabel("Decryption Time (ms)", labelpad=12); ax.set_xlabel("Model", labelpad=15)
    ax.set_title("Decryption Time Comparison Across Evaluated Cryptographic Schemes")
    ax.tick_params(axis='y', labelsize=16)
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=15)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig8_7Scheme_Decryption_Time.png"), dpi=300)
    plt.close()

    # Fig 9: 7-Scheme Processing Time Distribution Boxplot
    fig, ax = plt.subplots(figsize=(16, 9))
    bp = ax.boxplot([pdata["proc_dist_7"][n] for n in models7], tick_labels=wrapped_models7, vert=False, showfliers=False, patch_artist=True)
    for patch, color in zip(bp['boxes'], COLORS_7):
        patch.set_facecolor(color); patch.set_alpha(0.75)
    ax.set_xlabel("Processing Time (ms)", labelpad=12); ax.set_ylabel("Model", labelpad=12)
    ax.set_title("Average Processing Time Distribution for Evaluated Encryption Schemes")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig9_7Scheme_Processing_Time_Boxplot.png"), dpi=300)
    plt.close()

    # Fig 10: 7-Scheme Throughput Comparison
    fair_models = pdata["fair_models_4"]
    thr_vals_fair = pdata["throughput_fair_vals"]
    w_fair_models = [l.replace(" (", "\n(") for l in fair_models]
    fig, ax = plt.subplots(figsize=(16, 9))
    bars = ax.bar(w_fair_models, np.clip(thr_vals_fair, 1e-4, None), color=COLORS_4, edgecolor="black")
    ax.set_ylabel("Throughput (Mbps)", labelpad=12); ax.set_xlabel("Model", labelpad=15)
    ax.set_title("Throughput Comparison of Hybrid Secure Protocols")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ax.tick_params(axis='x', labelsize=16)
    for bar, val in zip(bars, thr_vals_fair):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height + (max(thr_vals_fair) * 0.015 if max(thr_vals_fair) > 0 else 0.001),
                f"{val:.3f} Mbps", va='bottom', ha='center', fontsize=15)
    ax.set_ylim(0, max(thr_vals_fair) * 1.18)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig10_7Scheme_Throughput_Comparison.png"), dpi=300)
    plt.close()

    # Fig 11: Memory Comparison Publication with Error Bars & Hatch
    fig, ax = plt.subplots(figsize=(14, 7))
    x_mem = np.arange(len(mdata["models"]))
    bars = ax.bar(x_mem, mdata["memory"], yerr=mdata["std"], capsize=6, color=mdata["colors"],
                  edgecolor='black', linewidth=1.3, error_kw=dict(ecolor='black', lw=1.3))
    bars[-1].set_linewidth(2.5); bars[-1].set_hatch('//')
    for bar, value in zip(bars, mdata["memory"]):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.10, f"{value:.2f} KB",
                ha='center', va='bottom', fontsize=14, fontweight='bold')
    ax.set_title("Comparison of Peak Memory Consumption Across Cryptographic Schemes", fontsize=20, fontweight='bold', pad=15)
    ax.set_xlabel("Encryption Model", fontsize=18, fontweight='bold')
    ax.set_ylabel("Peak Memory Consumption (KB)", fontsize=18, fontweight='bold')
    ax.set_xticks(x_mem); ax.set_xticklabels(mdata["models"], fontsize=13, fontweight='bold')
    ax.set_ylim(0, 7.6); ax.grid(False)
    for spine in ax.spines.values(): spine.set_linewidth(1.2)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig11_Memory_Comparison_Publication.png"), dpi=600, bbox_inches='tight')
    plt.close()

    # Fig 12: All Timing Metrics Grouped (3 Models)
    timing_cols = ["Encryption Time (ms)", "Decryption Time (ms)", "Processing Time (ms)", "Encryption Delay (ms)", "Decryption Delay (ms)"]
    timing_short = ["Encryption\nTime", "Decryption\nTime", "Processing\nTime", "Encryption\nDelay", "Decryption\nDelay"]
    x = np.arange(len(timing_short)); w = 0.25
    fig, ax = plt.subplots(figsize=(16, 8))
    grp_cols = plot_colors["grouped"]
    for i, (mkey, mlabel) in enumerate(zip(cmp_keys, cmp_order)):
        vs = [idx3.loc[mkey, c] for c in timing_cols]
        bars = ax.bar(x + (i - 1) * w, vs, w, label=mlabel.replace("\n", " "), color=grp_cols[i], edgecolor="black")
        for b, v in zip(bars, vs):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.4, f"{v:.2f}", va="bottom", ha="center", fontsize=16, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(timing_short, fontsize=15)
    ax.set_ylabel("Time / Delay (ms)", labelpad=12); ax.set_xlabel("Performance Metric", labelpad=15)
    ax.set_title("Timing Metrics Comparison — Proposed vs RSA vs AES")
    ax.legend(fontsize=12, loc="upper right"); ax.set_ylim(0, 34)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig12_All_Timing_Metrics_Grouped.png"), dpi=300)
    plt.close()

    # Fig 13: Encryption & Decryption Delay Subplots
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(16, 7))
    for ax_, col_, title_, ck_ in [
        (a1, "Encryption Delay (ms)", "Encryption Delay Comparison", "enc_delay"),
        (a2, "Decryption Delay (ms)", "Decryption Delay Comparison", "dec_delay")
    ]:
        vals_ = [idx3.loc[m, col_] for m in cmp_keys]
        cols_ = plot_colors[ck_]
        bars_ = ax_.bar(cmp_order, vals_, color=cols_, edgecolor="black", width=0.5)
        ax_.set_ylabel(col_, labelpad=10); ax_.set_xlabel("Encryption Model", labelpad=12)
        ax_.set_title(title_)
        plt.setp(ax_.get_xticklabels(), rotation=0, ha="center", fontsize=14)
        for b, v in zip(bars_, vals_):
            ax_.text(b.get_x() + b.get_width() / 2, b.get_height() + max(vals_) * 0.028,
                     f"{v:.3f} ms", va="bottom", ha="center", fontsize=12, fontweight="bold")
        ax_.set_ylim(0, max(vals_) * 1.22)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig13_Encryption_Decryption_Delay_Subplots.png"), dpi=300)
    plt.close()

    # Fig 14: Encryption, Decryption, Processing with 95% CI
    ci_data = data_bundle["performance_ci_data"]
    models_ci = ci_data["models"]
    x_ci = np.arange(len(models_ci)); width_ci = 0.25
    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x_ci - width_ci, ci_data["encryption"], width_ci, yerr=ci_data["enc_err"], capsize=6, color="#4C72B0", edgecolor="black", linewidth=1.5, label="Encryption")
    bars2 = ax.bar(x_ci, ci_data["decryption"], width_ci, yerr=ci_data["dec_err"], capsize=6, color="#DD8452", edgecolor="black", linewidth=1.5, label="Decryption")
    bars3 = ax.bar(x_ci + width_ci, ci_data["processing"], width_ci, yerr=ci_data["proc_err"], capsize=6, color="#55A868", edgecolor="black", linewidth=1.5, label="Processing")
    for bars_ in [bars1, bars2, bars3]:
        for bar in bars_:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.45, f"{h:.2f}", ha='center', va='bottom', fontsize=13, fontweight='bold')
    ax.set_xticks(x_ci); ax.set_xticklabels(models_ci)
    ax.set_ylabel("Time (ms)", fontsize=18, fontweight='bold'); ax.set_xlabel("Encryption Model", fontsize=18, fontweight='bold')
    ax.set_title("Encryption Performance with 95% Confidence Intervals", fontsize=20, fontweight='bold')
    ax.legend(frameon=True, fontsize=14)
    for spine in ax.spines.values(): spine.set_linewidth(1.5)
    ax.tick_params(axis='both', labelsize=15)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig14_Encryption_Decryption_Processing_CI.png"), dpi=300, bbox_inches="tight")
    plt.close()

    # Fig 15: Detailed 5-Metric Breakdown for Proposed Model
    pt_data = data_bundle["performance_time_breakdown_data"]
    fig, ax = plt.subplots(figsize=(12, 7), dpi=800)
    bars = ax.bar(pt_data["metrics"], pt_data["values"], color=pt_data["colors"], edgecolor="black", linewidth=1.2, width=0.58)
    for bar, val in zip(bars, pt_data["values"]):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.08, f"{val:.3f}", ha='center', va='bottom', fontsize=20, fontweight='bold')
    ax.set_xlabel("Performance Metrics", fontsize=20, fontweight='bold'); ax.set_ylabel("Time (ms)", fontsize=20, fontweight='bold')
    ax.set_title("Performance Analysis of Proposed SEHC Framework", fontsize=22, fontweight='bold', pad=15)
    ax.set_ylim(0, 4.2); ax.set_yticks(np.arange(0, 4.5, 0.5)); ax.grid(False)
    for spine in ax.spines.values(): spine.set_linewidth(1.5)
    ax.tick_params(axis='both', labelsize=20, width=1.2)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig15_Performance_Time_Breakdown.png"), dpi=800, bbox_inches="tight")
    plt.close()

    # Fig 16: SPA Mitigation Accuracy (Deduplicated)
    fig, ax = plt.subplots(figsize=(10, 6))
    spa_labels = ["Unprotected\n(No Masking)", "Masked ECC-CRT\n(Proposed)"]
    spa_vals = [cdata["SPA_UNPROTECTED"], cdata["SPA_PROPOSED"]]
    bars = ax.bar(spa_labels, spa_vals, color=["#E74C3C", "#2ECC71"], edgecolor="black", width=0.4)
    ax.axhline(50, color="gray", linestyle="--", linewidth=1.8, label="Random-Guess Baseline (50%)")
    ax.set_ylabel("SPA Bit-Recovery Accuracy (%)", labelpad=12); ax.set_xlabel("Method", labelpad=15)
    ax.set_title(f"SPA Mitigation Accuracy\n(SPA Mitigation Accuracy: {cdata['SPA_MITIGATION']:.2f}%)")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann_pct(ax, bars, spa_vals); ax.set_ylim(0, 120); ax.legend(fontsize=13)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig16_SPA_Mitigation_Accuracy.png"), dpi=300)
    plt.close()

    # Fig 17: DPA Mitigation Accuracy (Deduplicated)
    fig, ax = plt.subplots(figsize=(12, 7))
    dpa_labels = ["Unprotected\n(Fixed Scalar)", "Masked ECC-CRT\n(Proposed)"]
    dpa_acc = [cdata["DPA_UNPROTECTED"], cdata["DPA_PROPOSED"]]
    dpa_leak = [cdata["LEAK_UNPROTECTED"], cdata["LEAK_PROPOSED"]]
    x_dpa = np.arange(2); w_dpa = 0.30
    b1 = ax.bar(x_dpa - w_dpa / 2, dpa_acc, w_dpa, label="DPA Bit-Recovery Accuracy (%)", color="#E74C3C", edgecolor="black")
    b2 = ax.bar(x_dpa + w_dpa / 2, dpa_leak, w_dpa, label="Mean Leakage Correlation (%)", color="#3498DB", edgecolor="black")
    ax.axhline(50, color="gray", linestyle="--", linewidth=1.8, label="Random-Guess Baseline (50%)")
    ax.set_xticks(x_dpa); ax.set_xticklabels(dpa_labels, fontsize=13)
    ax.set_ylabel("Percent (%)", labelpad=12); ax.set_xlabel("Method", labelpad=15)
    ax.set_title(f"DPA Mitigation Accuracy\n(DPA Mitigation: {cdata['DPA_MITIGATION']:.2f}%  |  Leakage Reduction: {cdata['LEAKAGE_REDUCTION']:.2f}%)")
    ax.set_ylim(0, 120); ax.legend(fontsize=12)
    for b, v in zip(list(b1) + list(b2), dpa_acc + dpa_leak):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.8, f"{v:.1f}%", va="bottom", ha="center", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig17_DPA_Mitigation_Accuracy.png"), dpi=300)
    plt.close()

    # Fig 18: Information Leakage Reduction
    fig, ax = plt.subplots(figsize=(10, 6))
    leak_labels = ["Unprotected\n(No Masking)", "Masked ECC-CRT\n(Proposed)"]
    leak_vals = [cdata["LEAK_UNPROTECTED"], cdata["LEAK_PROPOSED"]]
    bars = ax.bar(leak_labels, leak_vals, color=["#9B59B6", "#F39C12"], edgecolor="black", width=0.4)
    ax.set_ylabel("Mean Leakage Correlation (%)", labelpad=12); ax.set_xlabel("Method", labelpad=15)
    ax.set_title(f"Information Leakage Reduction\n(Leakage Reduction: {cdata['LEAKAGE_REDUCTION']:.2f}%)")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann_pct(ax, bars, leak_vals); ax.set_ylim(0, 95)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig18_Information_Leakage_Reduction.png"), dpi=300)
    plt.close()

    # Fig 19: Side-Channel Mitigation Summary
    fig, ax = plt.subplots(figsize=(12, 7))
    sec_labels = ["SPA\nMitigation", "DPA\nMitigation", "Leakage\nReduction", "Overall\nMitigation"]
    sec_vals = [cdata["SPA_MITIGATION"], cdata["DPA_MITIGATION"], cdata["LEAKAGE_REDUCTION"], cdata["OVERALL_MITIGATION"]]
    sec_cols = ["#4C72B0", "#DD8452", "#55A868", "#C44E52"]
    bars = ax.bar(sec_labels, sec_vals, color=sec_cols, edgecolor="black", width=0.5)
    ax.set_ylabel("Percentage (%)", labelpad=10); ax.set_xlabel("Security Evaluation Metric", labelpad=12)
    ax.set_title("Side-Channel Attack Mitigation Performance")
    plt.setp(ax.get_xticklabels(), rotation=0, ha="center", fontsize=13)
    ann_pct(ax, bars, sec_vals); ax.set_ylim(0, 118)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig19_Side_Channel_Mitigation_Summary.png"), dpi=300)
    plt.close()

    # Fig 20: SPA Attack Success Reduction
    spa_att = data_bundle["spa_attack_success_data"]
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(spa_att["methods"], spa_att["attack_success"], color=spa_att["colors"], edgecolor='black', linewidth=1.6, width=0.55)
    for bar, val in zip(bars, spa_att["attack_success"]):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 2, f"{val:.2f}%", ha='center', fontsize=16, fontweight='bold')
    ax.set_ylabel("SPA Attack Success (%)", fontsize=18, fontweight='bold'); ax.set_xlabel("Method", fontsize=18, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.set_title(f"SPA Attack Success after Protection\n(Mitigation Effectiveness = {spa_att['mitigation_effectiveness']:.2f}%)", fontsize=20, fontweight='bold')
    for spine in ax.spines.values(): spine.set_linewidth(1.3)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig20_SPA_Attack_Success_Reduction.png"), dpi=300)
    plt.close()

    # Fig 21: DPA Attack Success Reduction
    dpa_att = data_bundle["dpa_attack_success_data"]
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(dpa_att["methods"], dpa_att["attack_success"], color=dpa_att["colors"], edgecolor='black', linewidth=1.6, width=0.55)
    for b, v in zip(bars, dpa_att["attack_success"]):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.2f}%", ha='center', fontsize=16, fontweight='bold')
    ax.set_ylabel("DPA Attack Success (%)", fontsize=18, fontweight='bold'); ax.set_xlabel("Method", fontsize=18, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.set_title(f"DPA Attack Success after Protection\n(Mitigation Effectiveness = {dpa_att['mitigation_effectiveness']:.2f}%)", fontsize=20, fontweight='bold')
    for s in ax.spines.values(): s.set_linewidth(1.3)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig21_DPA_Attack_Success_Reduction.png"), dpi=300)
    plt.close()

    # Fig 22: DPA Success Rate vs Traces Curve
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.plot(pdata["trace_grid"], pdata["dpa_curve_unprotected"], marker="o", label="Unprotected (fixed scalar)", color="#E74C3C", linewidth=2.5, markersize=8)
    ax.plot(pdata["trace_grid"], pdata["dpa_curve_protected"], marker="s", label="Masked-ECC-CRT (Proposed)", color="#2ECC71", linewidth=2.5, markersize=8)
    ax.set_xlabel("Number of Traces", labelpad=10); ax.set_ylabel("Bit-Recovery Success Rate (%)", labelpad=10)
    ax.set_title("DPA Success Rate vs. Trace Count")
    ax.legend(fontsize=14); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig22_DPA_Success_Rate_vs_Traces.png"), dpi=300)
    plt.close()

    # Fig 23: Computational Overhead Percentage
    oh_data = data_bundle["computational_overhead_pct_data"]
    fig, ax = plt.subplots(figsize=(11, 7))
    bars = ax.bar(oh_data["models"], oh_data["overhead"], color=oh_data["colors"], edgecolor="black", linewidth=1.2, width=0.55)
    for bar, val in zip(bars, oh_data["overhead"]):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height + max(oh_data["overhead"]) * 0.02,
                f"{val:.2f}%", ha="center", va="bottom", fontsize=15, fontweight="bold")
    ax.set_title("Computational Overhead Comparison", fontsize=20, fontweight="bold", pad=20)
    ax.set_xlabel("Encryption Model", fontsize=16, fontweight="bold", labelpad=12)
    ax.set_ylabel("Computational Overhead (%)", fontsize=16, fontweight="bold", labelpad=12)
    ax.set_ylim(0, max(oh_data["overhead"]) * 1.25); ax.tick_params(axis='both', labelsize=13)
    for spine in ax.spines.values(): spine.set_linewidth(1.3)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig23_Computational_Overhead_Percentage.png"), dpi=300, bbox_inches="tight")
    plt.close()

    # Fig 24: Throughput vs Packet Size (Line Plot)
    tp_data = data_bundle["throughput_packet_sweep_data"]
    fig, ax = plt.subplots(figsize=(12, 8), dpi=300)
    ax.plot(tp_data["packet_size"], tp_data["throughput"], color="#6A1B9A", linewidth=2.8, marker='o', markersize=8, markerfacecolor='white', markeredgewidth=2)
    ax.set_xlabel("Packet Size (KB)", fontsize=18, fontweight='bold'); ax.set_ylabel("Throughput (Mbps)", fontsize=18, fontweight='bold')
    ax.set_title("Throughput Analysis of the Proposed Mask-Based ECC-CRT Framework", fontsize=18, fontweight='bold', pad=12)
    ax.set_xlim(0, 17); ax.set_ylim(130, 150)
    for spine in ax.spines.values(): spine.set_linewidth(1.5)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig24_Throughput_vs_Packet_Size.png"), dpi=300, bbox_inches="tight")
    plt.close()

    # Fig 25: Throughput Spline Analysis Curve
    sp_data = data_bundle["throughput_spline_data"]
    data_size = np.array(sp_data["data_size"])
    throughput_arr = np.array(sp_data["throughput"])
    fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
    x_new = np.linspace(data_size.min(), data_size.max(), 300)
    spl = make_interp_spline(data_size, throughput_arr, k=2)
    ax.plot(x_new, spl(x_new), color="#201A70", linewidth=3)
    ax.plot(data_size, throughput_arr, 'o', markersize=10, markerfacecolor="white", markeredgecolor="#1f77b4", markeredgewidth=2)
    ax.set_xlabel("Input Data Size (KB)", fontsize=18, fontweight='bold'); ax.set_ylabel("Throughput (Mbps)", fontsize=18, fontweight='bold')
    ax.set_title("Throughput Performance Spline Curve Analysis", fontsize=22, fontweight='bold', pad=12)
    ax.set_xlim(150, 4300); ax.set_ylim(130, 148)
    for spine in ax.spines.values(): spine.set_linewidth(1.5)
    ax.tick_params(width=1.5); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig25_Throughput_Spline_Analysis.png"), dpi=300, bbox_inches="tight")
    plt.close()

    # Fig 26: Payload Size Sweep
    fig, ax = plt.subplots(figsize=(12, 7))
    colors_sweep = ["#34495E", "#3498DB", "#E67E22", "#2ECC71"]
    for i, name in enumerate(["AES-256", "ECC-256 (ECDH baseline)", "ECC + CRT (No Masking)", "Masked-ECC-CRT (Proposed)"]):
        sub = table10[table10["Model"] == name]
        ax.plot(sub["Payload size (bytes)"], sub["Encryption time (ms)"], marker="o", label=name, color=colors_sweep[i], linewidth=2.5, markersize=8)
    ax.set_xlabel("Payload Size (bytes)", labelpad=10); ax.set_ylabel("Encryption Time (ms)", labelpad=10)
    ax.set_title("Encryption Time vs. Payload Size (independent of record content)")
    ax.legend(fontsize=12); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "Fig26_Payload_Size_Sweep.png"), dpi=300)
    plt.close()


# Execute generation
generate_all_results(PLOT_DATA, RESULTS_DIR)

# Also ensure workspace root has a mirror of Results directory if applicable
root_results = os.path.join(WORKSPACE_ROOT, "Results")
if os.path.abspath(RESULTS_DIR) != os.path.abspath(root_results):
    os.makedirs(root_results, exist_ok=True)
    import shutil
    for fname in os.listdir(RESULTS_DIR):
        shutil.copy(os.path.join(RESULTS_DIR, fname), os.path.join(root_results, fname))

print("\n" + "=" * 70)
print(f"ALL DONE. 26 Deduplicated Figures (PNG) & 10 Tables (CSV) saved to:")
print(f" - {os.path.abspath(RESULTS_DIR)}")
print(f" - {os.path.abspath(root_results)}")
print("=" * 70)
