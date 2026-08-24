# Masked-ECC-CRT Framework for Secure Encrypted Health Communication (SEHC)

This repository contains the source code and experimental results for the **Masked-ECC-CRT Framework for Secure Encrypted Health Communication (SEHC)**.

The framework combines Elliptic Curve Cryptography (ECC), the Chinese Remainder Theorem (CRT), and dynamic scalar masking to investigate the security-performance trade-off in secure healthcare communication.

The implementation provides cryptographic benchmarking, performance evaluation, memory analysis, payload-size analysis, and side-channel security evaluation against Simple Power Analysis (SPA) and Differential/Correlation Power Analysis (DPA/CPA).



## Overview

Smart Electronic Health Cards (SEHCs) provide portable and rapid access to patient healthcare information. Protecting sensitive healthcare records in resource-constrained environments requires cryptographic mechanisms that provide both security and computational efficiency.

The proposed framework investigates the integration of ECC and CRT for secure healthcare data processing and introduces dynamic masking to protect intermediate ECC computations against side-channel leakage.

The framework evaluates both cryptographic performance and resistance to power-analysis attacks.

### Processing Workflow

```text
Healthcare Record
       |
       v
Data Serialization
       |
       v
ECC Key Generation
       |
       v
Dynamic Random Mask Generation
       |
       v
Masked ECC Scalar Multiplication
       |
       v
CRT-Optimized Modular Arithmetic
       |
       v
Session-Key Generation
       |
       v
Encrypted Healthcare Record
       |
       v
Secure SEHC Storage
```

\---

## Objectives

The main objectives of the implementation are:

1. To investigate ECC-based security for Smart Electronic Health Cards.
2. To integrate CRT-based finite-field arithmetic with ECC operations.
3. To evaluate the effect of dynamic scalar masking on ECC computations.
4. To investigate resistance against side-channel attacks.
5. To compare the proposed scheme with conventional cryptographic approaches.
6. To evaluate encryption, decryption, processing, throughput, and memory-related performance.
7. To analyze the effect of payload size on cryptographic performance.

\---

## Proposed Masked-ECC-CRT Framework

The proposed framework combines three main components:

### 1\. Elliptic Curve Cryptography (ECC)

ECC is used as the underlying public-key cryptographic mechanism. The implementation uses NIST P-256 elliptic-curve arithmetic.

### 2\. Chinese Remainder Theorem (CRT)

CRT-based finite-field modular arithmetic is applied to selected ECC operations to reduce the computational complexity associated with large modular arithmetic operations.

### 3\. Dynamic Scalar Masking

A session-specific random mask is generated during ECC scalar multiplication. The masking mechanism randomizes intermediate ECC computations and is intended to reduce information leakage that could otherwise be exploited through side-channel analysis.

The implementation applies scalar masking by adding a random multiple of the P-256 group order to the scalar before scalar multiplication.

\---

## Encryption Process

The proposed encryption workflow consists of:

1. Loading the healthcare record.
2. Converting the healthcare record into byte-stream representation.
3. Initializing ECC domain parameters.
4. Generating the ECC private key.
5. Computing the corresponding public key.
6. Generating a session-specific dynamic random mask.
7. Applying the masking mechanism to intermediate ECC computations.
8. Performing masked ECC scalar multiplication.
9. Applying CRT-optimized finite-field modular arithmetic.
10. Generating the encrypted ciphertext using the ECC-derived session key.
11. Storing the encrypted healthcare record in the SEHC.

\---

## Decryption Process

During decryption:

1. The encrypted healthcare record is retrieved.
2. The ECC shared secret is recovered using the receiver's private key.
3. CRT-based modular arithmetic is used during the reconstruction process.
4. The encrypted healthcare record is decrypted using the derived session key.
5. The original healthcare record is reconstructed.

Dynamic masking is maintained during intermediate ECC computations to reduce side-channel leakage.

\---

## Security Evaluation

The implementation evaluates the proposed framework against power-analysis-based side-channel attacks.

### Simple Power Analysis (SPA)

SPA experiments evaluate whether secret scalar information can be recovered from unprotected ECC computations. The proposed masked implementation is compared with an unprotected implementation.

### Differential / Correlation Power Analysis (DPA/CPA)

DPA/CPA experiments evaluate statistical correlation between hypothetical ECC leakage and simulated power traces.

The analysis investigates whether information about ECC intermediate computations can be recovered from multiple traces.

### Effect of Dynamic Masking

A fresh random mask is generated for each encryption session. Consequently, identical plaintext operations can produce different intermediate values, reducing the statistical correlation available to an attacker.

\---

## Evaluated Cryptographic Schemes

The implementation provides a seven-scheme benchmark:

1. **AES-256**
2. **RSA-2048**
3. **ECC-256 (ECDH baseline)**
4. **ECC (No Masking, No CRT)**
5. **Masked-ECC (No CRT)**
6. **ECC + CRT (No Masking)**
7. **Masked-ECC-CRT (Proposed)**

This configuration allows the contribution of masking and CRT to be evaluated separately as well as in combination.

\---

## Performance Metrics

The following performance metrics are evaluated:

* Encryption Time
* Decryption Time
* Processing Time
* Encryption Delay
* Decryption Delay
* Throughput
* Memory Usage
* Computational Overhead
* Energy Efficiency
* Processing Speed
* Real-Time Suitability

\---

## Security Metrics

The security evaluation includes:

* SPA Bit-Recovery
* SPA Mitigation Accuracy
* DPA Bit-Recovery
* DPA Mitigation Accuracy
* Information Leakage Reduction
* Overall SPA/DPA Mitigation

\---

## Dataset

### Hospital Dataset for Practice

The healthcare dataset used in the experimental evaluation is:

**Hospital Dataset for Practice (`hda.csv`)**

### Dataset Source

The dataset is publicly available through Kaggle:

**Kaggle – Hospital Dataset for Practice**

https://www.kaggle.com/datasets/blueblushed/hospital-dataset-for-practice

The dataset is used as a realistic healthcare-record payload source for the experimental evaluation, including payload-size and cryptographic performance analysis.

The implementation also contains a fallback mechanism that can generate synthetic healthcare records when the external dataset is not supplied.

### Dataset Attribution

The dataset is obtained from the original Kaggle repository. Users should refer to the original Kaggle page for the dataset description, licensing, attribution, and usage conditions.

\---

## Experimental Configuration

The supplied implementation uses the following configuration:

* Python version: **3.11.9**
* Elliptic curve: **NIST P-256**
* Random seed: **7**
* Main healthcare-record configuration: **200 records**
* SPA keys: **4000**
* DPA keys: **80**
* DPA traces: **300**
* Memory-measurement repetitions: **25**

These settings are included to support reproducible experimental comparisons.

\---

## Repository Structure

```text
SEHC-Masked-ECC-CRT/
│
├── README.md
├── sehc\_pipeline\_v4\_OPTIMIZED.py
├── sehc\_plot\_data.pkl
├── requirements.txt
├── .python-version
│
└── Results/
    ├── Fig1\_...png
    ├── Fig2\_...png
    ├── Fig3\_...png
    ├── ...
    ├── Fig26\_...png
    │
    ├── Table1\_...csv
    ├── Table2\_...csv
    ├── Table3\_...csv
    ├── ...
    └── Table10\_...csv
```

\---

## Main Implementation

The main implementation is:

```text
sehc\_pipeline\_v4\_OPTIMIZED.py
```

The implementation includes:

* NIST P-256 point arithmetic
* ECC/ECDH baseline evaluation
* AES-256 evaluation
* RSA-2048 evaluation
* ECC without masking and CRT
* Masked-ECC without CRT
* ECC + CRT without masking
* Masked-ECC-CRT proposed scheme
* SPA side-channel simulation
* DPA/CPA side-channel simulation
* Performance measurement
* Memory measurement
* Payload-size analysis
* Figure generation
* CSV table generation

\---

## Results

The repository contains the experimental results generated from the implementation.

### Result Files

The `Results/` directory contains:

* **26 PNG figures**
* **10 CSV tables**

The results cover:

* Overall proposed-model performance
* Encryption-time comparison
* Decryption-time comparison
* Processing-time analysis
* Encryption-delay analysis
* Decryption-delay analysis
* Throughput analysis
* Memory-usage analysis
* Computational-efficiency comparison
* Security evaluation
* SPA mitigation
* DPA mitigation
* Information-leakage analysis
* Confidence-interval analysis
* Payload-size analysis

\---

## Result Tables

The repository contains the following result categories:

```text
Table 1  - Proposed Performance Metrics
Table 2  - Comparative Performance Analysis
Table 3  - Computational Efficiency Comparison
Table 4  - Security Metrics: SPA and DPA
Table 5  - Performance with 95% Confidence Intervals
Table 6  - Security versus Complexity
Table 7  - Memory Usage
Table 8  - Seven-Scheme Performance Benchmark
Table 9  - DPA Success Rate versus Traces
Table 10 - Payload Size Sweep
```

The implementation uses separate comparative analyses for the publication results and the broader seven-scheme benchmark. The numerical values in these analyses should therefore be interpreted according to their corresponding tables.

\---

## Figures

The repository contains 26 generated figures covering:

* Proposed model performance
* Encryption time
* Decryption time
* Processing time
* Encryption delay
* Decryption delay
* Throughput
* Memory usage
* Computational efficiency
* SPA security analysis
* DPA security analysis
* Information leakage
* Confidence intervals
* Payload-size analysis
* Throughput analysis
* Additional comparative analyses

All figures are available in the `Results/` directory.

\---

## Installation

### Requirements

Recommended Python version:

```text
Python 3.11.9
```

Create a virtual environment.

### Windows

```bash
python -m venv .venv
.venv\\Scripts\\activate
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

\---

## Running the Project

Place the following files in the project directory:

```text
sehc\_pipeline\_v4\_OPTIMIZED.py
sehc\_plot\_data.pkl
```

If the healthcare dataset is being used locally, place:

```text
hda.csv
```

in the appropriate project directory.

Run the implementation using:

```bash
python sehc\_pipeline\_v4\_OPTIMIZED.py
```

The implementation generates the experimental figures and CSV tables in:

```text
Results/
```

\---

## Running in Google Colab

The main Python implementation is designed to be Google Colab compatible.

### Step 1: Clone the repository

```python
!git clone https://github.com/marysubaja/Hybrid-ECC-CRT-Healthcare-Security.git
```

### Step 2: Enter the repository

```python
%cd Hybrid-ECC-CRT-Healthcare-Security
```

### Step 3: Install dependencies

```python
!pip install -r requirements.txt
```

### Step 4: Run the implementation

```python
!python sehc\_pipeline\_v4\_OPTIMIZED.py
```

The generated figures and tables are stored in the `Results/` directory.

> \*\*Note:\*\* Update the repository URL above if the final GitHub repository name differs from the URL shown here.

\---

## Reproducibility

The repository provides:

* Source implementation
* Dependency specification
* Python version information
* Experimental result data
* Generated figures
* Generated result tables
* Dataset source information
* Experimental configuration

The `sehc\_plot\_data.pkl` file is provided with the repository to support generation of the publication figures and result tables.

The main Python implementation contains the plotting and CSV-generation code used to produce the supplied experimental outputs.

\---

## Data Availability

The healthcare dataset used for the payload-related evaluation is publicly available from Kaggle:

https://www.kaggle.com/datasets/blueblushed/hospital-dataset-for-practice

Please refer to the original Kaggle dataset page for the applicable license and usage conditions.

\---

## Code Availability

The source code and experimental results associated with this research are available in this GitHub repository.

The repository is provided to support research transparency, verification, and reproducibility.

## Research Context

The proposed framework focuses on improving the security of Smart Electronic Health Cards through ECC-CRT-based cryptographic processing.

The study considers the security risks associated with invalid-curve attacks and side-channel leakage in ECC implementations.

The framework combines cryptographic protection with security evaluation to investigate the security-performance trade-off in healthcare environments.

\---

## Limitations

The implementation is an experimental research framework and should not be considered a production-ready healthcare security system without additional validation.

In particular:

* The implementation should be evaluated on target healthcare hardware before deployment.
* CRT-based optimization introduces additional implementation complexity.
* Masking introduces computational overhead.
* Side-channel resistance depends on the implementation environment.
* Real-world hardware power traces may differ from simulated traces.
* Dataset licensing and redistribution conditions must be respected.

\---

## Disclaimer

This repository is provided for academic research, experimentation, and reproducibility purposes.

The implementation should not be deployed directly in a production healthcare environment without appropriate security validation, hardware testing, privacy assessment, and regulatory compliance review.

\---

## Acknowledgement

The authors acknowledge the publicly available Kaggle dataset used as the healthcare-record payload source for the experimental evaluation.

**Dataset:**

https://www.kaggle.com/datasets/blueblushed/hospital-dataset-for-practice

