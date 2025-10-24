import argparse, json
from .core import Params, sweep_all, choose_by_signing_cap, choose_by_size_target, spx_fp_report

def main():
    p = argparse.ArgumentParser(prog="spx-fp", description="SPX/FP cost & m_max tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--n", type=int, required=True)
        sp.add_argument("--w", type=int, required=True)
        sp.add_argument("--h", type=int, required=True)
        sp.add_argument("--d", type=int, required=True)
        sp.add_argument("--t", type=int, required=True)
        sp.add_argument("--k", type=int, required=True)
        sp.add_argument("--q", type=int, required=True)
        sp.add_argument("-o", "--output", help="Write JSON result to file")

    # report (ONE m_max)
    sp1 = sub.add_parser("report", help="compute metrics for a specific m_max")
    add_common(sp1)
    sp1.add_argument("--m-max", type=int, required=True)

    # existing
    sp2 = sub.add_parser("sweep", help="list metrics for all m_max")
    add_common(sp2)

    sp3 = sub.add_parser("choose-sign", help="pick m_max by signing increase cap (%)")
    add_common(sp3)
    sp3.add_argument("--cap", type=float, required=True)

    sp4 = sub.add_parser("choose-size", help="pick m_max by size decrease target (%)")
    add_common(sp4)
    sp4.add_argument("--target", type=float, required=True)

    args = p.parse_args()
    params = Params(args.n, args.w, args.h, args.d, args.t, args.k, args.q).validate()

    if args.cmd == "report":
        result = spx_fp_report(params, args.m_max)
    elif args.cmd == "sweep":
        result = sweep_all(params)
    elif args.cmd == "choose-sign":
        result = choose_by_signing_cap(params, args.cap)
    else:
        result = choose_by_size_target(params, args.target)

    if getattr(args, "output", None):
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))
