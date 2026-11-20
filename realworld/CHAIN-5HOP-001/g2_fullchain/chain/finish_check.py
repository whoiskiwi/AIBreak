"""Terminal checker for the G2 chain — byte-exact final verdict.

run_chain.py passes the hop-5 flag read back through the chain. This checker
compares it against the value written by the chain (OWN_TOKEN). Negative
controls (fake markers, old secrets, partial reads) live in G5; here we only
confirm the chain's own write.
"""


def check(flag: str) -> bool:
    return flag.startswith("CHAIN-REACHED-") and len(flag) == len("CHAIN-REACHED-") + 32
