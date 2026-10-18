#!/usr/bin/env python3
"""Per-check activation rates from an ELFMint JSONL run.

For every check the denominator is the number of files to which the check applies
(outcome Pass or Fail); NotApplicable and Unparsable files are counted separately.
Usage: summarise_jsonl.py RUN.jsonl [--by context_key]
"""
import json, sys, collections

def main(path, by=None):
    tot = collections.Counter(); fail = collections.Counter(); na = collections.Counter(); unp = collections.Counter()
    n = 0
    for line in open(path):
        v = json.loads(line)
        if "checks" not in v: continue
        key = v["context"].get(by, "?") if by else ""
        n += 1
        for c in v["checks"]:
            k = (c["id"], key)
            if c["outcome"] == "Pass": tot[k] += 1
            elif c["outcome"] == "Fail": tot[k] += 1; fail[k] += 1
            elif c["outcome"] == "NotApplicable": na[k] += 1
            else: unp[k] += 1
    print(f"files: {n}")
    print("check\t" + ("stratum\t" if by else "") + "applicable\tfailed\trate%\tn/a\tunparsable")
    for k in sorted(tot | na | unp, key=lambda k: (k[1], k[0])):
        rate = 100.0 * fail[k] / tot[k] if tot[k] else float("nan")
        print(f"{k[0]}\t" + (f"{k[1]}\t" if by else "") + f"{tot[k]}\t{fail[k]}\t{rate:.2f}\t{na[k]}\t{unp[k]}")

if __name__ == "__main__":
    args = sys.argv[1:]
    by = args[args.index("--by") + 1] if "--by" in args else None
    main(args[0], by)
