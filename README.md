# PORS+FP



## Installation

###  Option 1 — Directly from GitHub 

```bash
pip install git+https://github.com/MehdiAbri/PORS-FP.git
```
### Option 2 — From local source
```bash
git clone https://github.com/MehdiAbri/PORS-FP.git
cd PORS-FP
pip install -e .
```
After installation, the command-line tool spx-fp becomes available.



## Usage Options
### 1️⃣ report
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

### 2️⃣ sweep
Evaluate metrics for all possible `m_max` values to analyze trade-offs between cost and size.
**Example:**
```bash
spx-fp sweep --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024
```
Save results to a JSON file:
```bash
spx-fp sweep --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024 -o sweep.json
```


### 3️⃣ choose-sign
Find the largest `m_max` that keeps the signing time increase ≤ a given percentage.

**Example:**
```bash
spx-fp choose-sign --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024 --cap 2.5
```

### 4️⃣ choose-size
Find the largest `m_max` that achieves a target signature size reduction (in %).

**Example:**
```bash
spx-fp choose-size --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024 --target 13.6
```

### 🧪 Python API
You can also use the same functions in Python:

**Example:**
```python
from src import Params, spx_fp_report, sweep_all, choose_by_signing_cap, choose_by_size_target

p = Params(16, 16, 12, 2, 2**9, 17, 2**10)
print(spx_fp_report(p, m_max=118))

```

