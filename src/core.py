import math
from dataclasses import dataclass
from .octopus_pmf import interleave_cost_table
from decimal import Decimal, getcontext

getcontext().prec = 200

# ---------------- params ----------------

@dataclass(frozen=True)
class Params:
    n: int      # bytes
    w: int
    h: int
    d: int
    t: int
    k: int
    q: int

    def validate(self) -> "Params":
        assert self.n > 0
        assert self.w >= 2 and (self.w & (self.w - 1)) == 0  # power of two
        assert 1 <= self.d <= self.h and (self.h % self.d) == 0
        assert self.t >= 2 and self.k >= 1 and self.q >= 1
        return self

# -------------- helpers --------------

def _wots_len(n, w):
    len1 = math.ceil((8 * n) / math.log2(w))
    len2 = math.floor(math.log2(len1 * (w - 1)) / math.log2(w)) + 1
    return len1 + len2

def _pct_delta(new, base):
    return 100.0 * (new - base) / base if base else float("inf")

# -------------- baseline SPX (uses FORS) --------------

def spx_signing_calls(n, w, h, d, t, k):
    L = _wots_len(n, w)
    h_merkle = h // d
    node_tree = 2 ** h_merkle
    cost_wots = 1 + L * w
    cost_hypertree = d * ((cost_wots + 1) * node_tree - 1)
    cost_fors = k * (3 * t - 1)
    return 3 + cost_hypertree + cost_fors

def spx_verification_calls(n, w, h, d, t, k):
    L = _wots_len(n, w)
    h_merkle = h // d
    cost_wots = 1 + L * w / 2
    cost_hypertree = d * (cost_wots + h_merkle)
    cost_fors = k * (math.ceil(math.log2(t)) + 1)
    return 2 + cost_hypertree + cost_fors

def spx_signature_size(n, w, h, d, t, k):
    L = _wots_len(n, w)
    h_merkle = h // d
    cost_wots = L
    cost_hypertree = d * (cost_wots + h_merkle)
    cost_fors = k * (math.ceil(math.log2(t)) + 1)
    return (1 + cost_hypertree + cost_fors) * n

def spx_security_bits(q, h, t, k):
    prob = Decimal(0)
    for i in range(1, 200):
        a = Decimal(math.comb(q, i))
        b = (Decimal(1) - (Decimal(1) / (Decimal(2) ** h))) ** (q - i)
        c = (Decimal(1) / (Decimal(2) ** h)) ** i
        d = (Decimal(1) - (Decimal(1) - (Decimal(1) / Decimal(t))) ** i) ** k
        prob += a * b * c * d
    return float(-(prob.ln() / Decimal(2).ln()))

# -------------- SPX (uses PORS+FP) --------------

def spx_fp_signing_calls(n, w, h, d, t, k, add_work):
    L = _wots_len(n, w)
    h_merkle = h // d
    node_tree = 2 ** h_merkle
    cost_wots = 1 + L * w
    cost_hypertree = d * ((cost_wots + 1) * node_tree - 1)
    cost_pors_fp = 3 * k * t - 1 + add_work
    return 3 + cost_hypertree + cost_pors_fp

def spx_fp_verification_calls(n, w, h, d, t, k, m_max):
    L = _wots_len(n, w)
    h_merkle = h // d
    cost_wots = 1 + L * w / 2
    cost_hypertree = d * (cost_wots + h_merkle)
    cost_pors_fp = 2 * k + m_max
    return 2 + cost_hypertree + cost_pors_fp

def spx_fp_signature_size(n, w, h, d, t, k, m_max):
    L = _wots_len(n, w)
    h_merkle = h // d
    cost_wots = L
    cost_hypertree = d * (cost_wots + h_merkle)
    cost_pors_fp = k + m_max
    return (1 + cost_hypertree + cost_pors_fp) * n + 4  # +4 bytes counter

def spx_fp_security_bits(q, h, t, k):
    prob = Decimal(0)
    for i in range(1, 200):
        a = Decimal(math.comb(q, i))
        b = (Decimal(1) - (Decimal(1) / (Decimal(2) ** h))) ** (q - i)
        c = (Decimal(1) / (Decimal(2) ** h)) ** i
        x = min(t * k, k * i)
        num = Decimal(math.comb(x, k))
        den = Decimal(math.comb(t * k, k))
        d = num / den
        prob += a * b * c * d
    return float(-(prob.ln() / Decimal(2).ln()))

# -------------- bridge: m_max -> add_work --------------

def _log2_ework_from_mmax(t: int, k: int, m_max: int) -> float:
    table = dict(interleave_cost_table(n=k * t, k=k))
    if m_max in table:
        return table[m_max]
    lowers = [m for m in table if m <= m_max]
    if not lowers:
        raise ValueError("m_max below supported range for these (t,k).")
    return table[max(lowers)]

def _add_work_from_mmax(t: int, k: int, m_max: int) -> float:
    lg = _log2_ework_from_mmax(t, k, m_max)
    return (2.0 ** lg) - 1.0

# -------------- feature 1: one-shot report for a given m_max --------------

def spx_fp_report(p: Params, m_max: int):
    p = p.validate()
    base_sign = spx_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_vrfy = spx_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_size = spx_signature_size(p.n, p.w, p.h, p.d, p.t, p.k)

    add_work = _add_work_from_mmax(p.t, p.k, m_max)

    fp_sign = spx_fp_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k, add_work)
    fp_vrfy = spx_fp_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
    fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
    fp_bits = spx_fp_security_bits(p.q, p.h, p.t, p.k)

    return {
        "m_max": int(m_max),
        "log2_Ework": float(_log2_ework_from_mmax(p.t, p.k, m_max)),
        "expected_trials": float((2.0 ** _log2_ework_from_mmax(p.t, p.k, m_max))),
        "spx_fp_signing_calls": float(fp_sign),
        "signing_delta_pct": _pct_delta(fp_sign, base_sign),
        "spx_fp_verification_calls": float(fp_vrfy),
        "verification_delta_pct": _pct_delta(fp_vrfy, base_vrfy),
        "spx_fp_signature_size_bytes": int(fp_size),
        "signature_size_delta_pct": _pct_delta(fp_size, base_size),
        "spx_fp_security_bits": float(fp_bits),
    }

# -------------- feature 2: sweep all m_max --------------

def sweep_all(p: Params):
    p = p.validate()
    base_sign = spx_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_vrfy = spx_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_size = spx_signature_size(p.n, p.w, p.h, p.d, p.t, p.k)

    table = interleave_cost_table(n=p.k * p.t, k=p.k)  # list[(m_max, log2 E[work])]
    rows = []
    for m_max, lg in table:
        add_work = (2.0 ** lg) - 1.0
        fp_sign = spx_fp_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k, add_work)
        fp_vrfy = spx_fp_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        rows.append({
            "m_max": int(m_max),
            "log2_Ework": float(lg),
            "expected_trials": float(2.0 ** lg),
            "spx_fp_signing_calls": float(fp_sign),
            "signing_delta_pct": _pct_delta(fp_sign, base_sign),
            "spx_fp_verification_calls": float(fp_vrfy),
            "verification_delta_pct": _pct_delta(fp_vrfy, base_vrfy),
            "spx_fp_signature_size_bytes": int(fp_size),
            "signature_size_delta_pct": _pct_delta(fp_size, base_size),
        })
    
    security_bits = spx_fp_security_bits(p.q, p.h, p.t, p.k)
    return {"security_bits": security_bits, "rows": rows}

# -------------- feature 3: choose by signing cap --------------

def choose_by_signing_cap(p: Params, signing_increase_pct: float):
    p = p.validate()
    base_sign = spx_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_vrfy = spx_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_size = spx_signature_size(p.n, p.w, p.h, p.d, p.t, p.k)

    table = sorted(interleave_cost_table(n=p.k * p.t, k=p.k), key=lambda x: x[0])

    chosen = None
    for m_max, lg in table:  
        add_work = (2.0 ** lg) - 1.0
        fp_sign = spx_fp_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k, add_work)
        if _pct_delta(fp_sign, base_sign) <= signing_increase_pct + 1e-12:
            fp_vrfy = spx_fp_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
            fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
            chosen = {
                "m_max": int(m_max),
                "log2_Ework": float(lg),
                "expected_trials": float(2.0 ** lg),
                "spx_fp_signing_calls": float(fp_sign),
                "signing_delta_pct": _pct_delta(fp_sign, base_sign),
                "spx_fp_verification_calls": float(fp_vrfy),
                "verification_delta_pct": _pct_delta(fp_vrfy, base_vrfy),
                "spx_fp_signature_size_bytes": int(fp_size),
                "signature_size_delta_pct": _pct_delta(fp_size, base_size),
                "status": "OK",
            }
            break
    if chosen is None:  # cap infeasible -> pick largest m_max (best for signing)
        m_max, lg = max(table, key=lambda x: x[0])
        add_work = (2.0 ** lg) - 1.0
        fp_sign = spx_fp_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k, add_work)
        fp_vrfy = spx_fp_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        chosen = {
            "m_max": int(m_max),
            "log2_Ework": float(lg),
            "expected_trials": float(2.0 ** lg),
            "spx_fp_signing_calls": float(fp_sign),
            "signing_delta_pct": _pct_delta(fp_sign, base_sign),
            "spx_fp_verification_calls": float(fp_vrfy),
            "verification_delta_pct": _pct_delta(fp_vrfy, base_vrfy),
            "spx_fp_signature_size_bytes": int(fp_size),
            "signature_size_delta_pct": _pct_delta(fp_size, base_size),
            "status": "Cap infeasible; using largest m_max",
        }

    chosen["security_bits"] = spx_fp_security_bits(p.q, p.h, p.t, p.k)
    return chosen

# -------------- feature 4: choose by size target --------------

def choose_by_size_target(p: Params, size_decrease_pct: float):
    p = p.validate()
    base_sign = spx_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_vrfy = spx_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k)
    base_size = spx_signature_size(p.n, p.w, p.h, p.d, p.t, p.k)
    target = base_size * (1.0 - size_decrease_pct / 100.0)

    table = interleave_cost_table(n=p.k * p.t, k=p.k)

    feasible = []
    for m_max, lg in table:
        fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        if fp_size <= target + 1e-9:
            feasible.append((m_max, lg, fp_size))

    if feasible:
        m_max, lg, fp_size = max(feasible, key=lambda x: x[0])  # largest m_max
        status = "OK"
    else:
        m_max, lg = min(table, key=lambda x: x[0])
        fp_size = spx_fp_signature_size(p.n, p.w, p.h, p.d, p.t, p.k, m_max)
        status = "Target infeasible; using minimal m_max"

    add_work = (2.0 ** lg) - 1.0
    fp_sign = spx_fp_signing_calls(p.n, p.w, p.h, p.d, p.t, p.k, add_work)
    fp_vrfy = spx_fp_verification_calls(p.n, p.w, p.h, p.d, p.t, p.k, m_max)

    return {
        "status": status,
        "requested_size_decrease_pct": float(size_decrease_pct),
        "baseline_signature_size_bytes": int(base_size),
        "target_signature_size_bytes": int(target),
        "m_max": int(m_max),
        "log2_Ework": float(lg),
        "expected_trials": float(2.0 ** lg),
        "spx_fp_signature_size_bytes": int(fp_size),
        "signature_size_delta_pct": _pct_delta(fp_size, base_size),
        "spx_fp_signing_calls": float(fp_sign),
        "signing_delta_pct": _pct_delta(fp_sign, base_sign),
        "spx_fp_verification_calls": float(fp_vrfy),
        "verification_delta_pct": _pct_delta(fp_vrfy, base_vrfy),
        "security_bits": spx_fp_security_bits(p.q, p.h, p.t, p.k),
    }
