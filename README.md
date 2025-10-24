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
### report
Compute all metrics (signing, verification, signature size, security) for a specific `m_max` value.

**Example:**
```bash
spx-fp report --n 16 --w 16 --h 12 --d 2 --t 512 --k 17 --q 1024 --m-max 118
```
