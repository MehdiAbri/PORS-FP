# PORS+FP



## Installation

###  Option 1 — Directly from GitHub 

```bash
pip install git+https://github.com/***/PORS-FP.git
```
### Option 2 — From local source
```bash
git clone https://github.com/***/PORS-FP.git
cd PORS-FP
pip install -e .
```
After installation, the command-line tool spx-fp becomes available.



## Usage Options
### 1) report
Compute all metrics (signing, verification, signature size, security) for a specific `m_max` value.

**Example:**
```bash
spx-fp report --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024 --m-max 118
```
**Output:**
```yaml
{
  "m_max": 118,
  "log2_Ework": 10.620663707309621,
  "expected_trials": 1574.4843556188698,
  "spx_fp_signing_calls": 99621.48435561887,
  "signing_delta_pct": 1.6213933772838172,
  "spx_fp_verification_calls": 728.0,
  "verification_delta_pct": -2.4128686327077746,
  "spx_fp_signature_size_bytes": 3492,
  "signature_size_delta_pct": -13.735177865612648,
  "spx_fp_security_bits": 131.3980649189629
}
```

### 2) sweep
Evaluate metrics for all possible `m_max` values to analyze trade-offs between cost and size.
