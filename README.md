Masked-ECC-CRT Framework for Secure Encrypted Health Communication (SEHC)
This repository contains the source code and experimental results for
the Masked-ECC-CRT Framework for Secure Encrypted Health Communication
(SEHC).
The implementation provides cryptographic benchmarking, side-channel
analysis, and publication-ready result generation for the evaluated
encryption schemes.
Repository contents
``` text
SEHC-Masked-ECC-CRT/
│
├── README.md
├── sehc_pipeline_v4_OPTIMIZED.py
├── sehc_plot_data.pkl
├── hda.csv
├── requirements.txt
├── .python-version
│
└── Results/
    ├── Fig1_...png
    ├── ...
    ├── Fig26_...png
    ├── Table1_...csv
    ├── ...
    └── Table10_...csv
```
Main implementation
The main script, `sehc_pipeline_v4_OPTIMIZED.py`, includes:
NIST P-256 elliptic-curve arithmetic
ECC/ECDH baseline evaluation
AES-256 evaluation
RSA-2048 evaluation
ECC without masking and CRT
Masked-ECC without CRT
ECC + CRT without masking
Masked-ECC-CRT as the proposed scheme
SPA and DPA/CPA side-channel simulations
performance and memory measurements
generation of 26 PNG figures
generation of 10 CSV tables
The implementation uses scalar masking by adding a random multiple of
the P-256 group order to the scalar before scalar multiplication.
Evaluated schemes
The seven-scheme benchmark contains:
AES-256
RSA-2048
ECC-256 (ECDH baseline)
ECC (No Mask, No CRT)
Masked-ECC (No CRT)
ECC + CRT (No Masking)
Masked-ECC-CRT (Proposed)
Experimental configuration
The supplied implementation uses:
Python 3.11.9 as the tested version
random seed: `7`
200 health-record entries for the main record-processing
configuration
4000 SPA keys
80 DPA keys
300 DPA traces
25 memory-measurement repetitions
The script loads `hda.csv` when it is available. If the file is not
available, it contains a fallback that generates synthetic patient
records.
Important data note
Before making this repository public, verify that `hda.csv` contains
only data that you are authorized to redistribute and that it contains
no real patient or personally identifiable information.
If the dataset is not approved for public release, remove it from the
public repository and document the approved data-generation/replacement
procedure instead.
Installation
Recommended Python version:
``` text
Python 3.11.9
```
Create and activate a virtual environment:
Windows
``` bash
python -m venv .venv
.venv\Scripts\activate
```
Linux/macOS
``` bash
python3 -m venv .venv
source .venv/bin/activate
```
Install the dependencies:
``` bash
pip install -r requirements.txt
```
Required Python packages
The supplied `requirements.txt` specifies:
`cryptography`
`numpy`
`pandas`
`scipy`
`scikit-learn`
`matplotlib`
`seaborn`
`tabulate`
`openpyxl`
Running the experiment
Place the following files in the same directory as the main script:
``` text
sehc_pipeline_v4_OPTIMIZED.py
sehc_plot_data.pkl
```
If using the supplied health-record input:
``` text
hda.csv
```
Run:
``` bash
python sehc_pipeline_v4_OPTIMIZED.py
```
The script creates the `Results` directory if it does not already exist
and generates the publication result files there.
Results
The supplied `Results` directory contains:
26 PNG figures
10 CSV tables
Performance results
The supplied three-model comparative tables report the following values
for the proposed Masked-ECC-CRT configuration:
Metric                     Value
---
Encryption time          2.15 ms
Decryption time          1.28 ms
Processing time          3.43 ms
Encryption delay         2.33 ms
Decryption delay         1.46 ms
Throughput           145.82 Mbps
Memory usage             4.10 KB
Side-channel results
The supplied security table reports:
Security metric                        Value
---
SPA bit-recovery --- unprotected     100.00%
SPA bit-recovery --- proposed         49.80%
SPA mitigation accuracy               99.60%
DPA bit-recovery --- unprotected     100.00%
DPA bit-recovery --- proposed         50.89%
DPA mitigation accuracy               98.22%
Information leakage reduction         78.63%
Overall SPA+DPA mitigation            98.91%
Confidence intervals
The repository also includes 95% confidence-interval results in:
``` text
Results/Table5_Performance_with_95CI.csv
```
Payload-size analysis
`Table10_Payload_Size_Sweep.csv` contains encryption/decryption
measurements for payload sizes of:
``` text
128, 512, 1024, 2048, and 4096 bytes
```
for the evaluated schemes included in that table.
Important note about the result tables
The repository contains both:
a three-model comparative analysis used by Tables 1--7, and
a seven-scheme benchmark used by Tables 8--10.
These datasets serve different analysis purposes. Therefore, values in
the seven-scheme benchmark should not be assumed to be identical to the
three-model publication summary.
Reproducing the supplied figures and tables
The main script contains the plotting and CSV-generation code. It uses
the supplied `sehc_plot_data.pkl` file for the publication datasets and
writes the generated files to `Results/`.
The script is configured to generate:
``` text
26 figures
10 tables
```
The generated filenames correspond to the files already supplied in the
`Results` directory.
Reproducibility notes
For reproducible comparisons:
Use the recommended Python version.
Install the dependencies from `requirements.txt`.
Keep `sehc_plot_data.pkl` with the main script.
Use the same input dataset or the documented synthetic-data
fallback.
Keep the random seed and experimental configuration unchanged unless
intentionally performing a new experiment.
Record the hardware and software environment when reporting new
benchmark measurements.
Cryptographic timing and memory measurements can vary with CPU,
operating system, Python version, library versions, and system load. The
supplied result files should therefore be treated as the recorded
experimental results accompanying this implementation.
