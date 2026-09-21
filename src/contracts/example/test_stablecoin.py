#!/usr/bin/env python3
"""test_stablecoin.py — Python mirror of the SIP-20 custodial stablecoin.

Ports src/contracts/sip20.go semantics (mint/burn/burn_self/transfer,
owner gate, underflow checks, total_supply invariant) and runs the same
lifecycle as sip20_stablecoin_test.go. Also exercises the C build via
subprocess when available, so one command validates both implementations.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


class Stablecoin:
    def __init__(self, admin):
        self.admin = admin
        self.balances = {}
        self.total = 0

    def bal(self, o):
        return self.balances.get(o, 0)

    def mint(self, caller, to, amount):
        if caller != self.admin:
            raise PermissionError("mint requires token owner")
        if not to or amount <= 0:
            raise ValueError("bad args")
        self.balances[to] = self.bal(to) + amount
        self.total += amount

    def burn(self, caller, frm, amount):
        if caller != self.admin:
            raise PermissionError("burn requires token owner")
        if not frm or amount <= 0:
            raise ValueError("bad args")
        if self.bal(frm) < amount:
            raise ValueError("insufficient token balance")
        self.balances[frm] -= amount
        self.total -= amount

    def burn_self(self, caller, amount):
        if amount <= 0:
            raise ValueError("bad args")
        if self.bal(caller) < amount:
            raise ValueError("insufficient token balance")
        self.balances[caller] -= amount
        self.total -= amount

    def transfer(self, frm, to, amount):
        if not to or amount <= 0:
            raise ValueError("bad args")
        if self.bal(frm) < amount:
            raise ValueError("insufficient token balance")
        self.balances[frm] -= amount
        self.balances[to] = self.bal(to) + amount

    def check_invariant(self):
        assert self.total == sum(self.balances.values()), (
            f"supply invariant broken: total={self.total} "
            f"sum={sum(self.balances.values())}"
        )


fails = []


def check(cond, name, detail=""):
    print(("PASS" if cond else "FAIL") + f": {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        fails.append(name)


def expect_raise(fn, exc, name):
    try:
        fn()
    except exc:
        print(f"PASS: {name}")
        return
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: {name} — wrong exc {type(e).__name__}: {e}")
        fails.append(name)
        return
    print(f"FAIL: {name} — no exception raised")
    fails.append(name)


def main():
    sc = Stablecoin("admin")

    sc.mint("admin", "alice", 1000)
    check(sc.bal("alice") == 1000, "py mint", f"alice={sc.bal('alice')} want 1000")
    check(sc.total == 1000, "py total after mint", f"{sc.total} want 1000")
    sc.check_invariant()
    print("PASS: py invariant after mint")

    expect_raise(lambda: sc.mint("eve", "eve", 500), PermissionError, "py reject unauthorized mint")
    check(sc.total == 1000, "py total unchanged", f"{sc.total} want 1000")
    check(sc.bal("eve") == 0, "py eve==0", f"{sc.bal('eve')} want 0")

    sc.transfer("alice", "bob", 300)
    check(sc.bal("alice") == 700, "py alice==700", f"{sc.bal('alice')}")
    check(sc.bal("bob") == 300, "py bob==300", f"{sc.bal('bob')}")
    check(sc.total == 1000, "py total unchanged after transfer", f"{sc.total}")
    sc.check_invariant()
    print("PASS: py invariant after transfer")

    expect_raise(lambda: sc.transfer("alice", "bob", 9999), ValueError, "py reject overdraft")
    check(sc.bal("alice") == 700 and sc.bal("bob") == 300, "py no partial change", f"a={sc.bal('alice')} b={sc.bal('bob')}")

    sc.burn("admin", "alice", 200)
    check(sc.bal("alice") == 500, "py alice==500 after burn", f"{sc.bal('alice')}")
    check(sc.total == 800, "py total==800 after burn", f"{sc.total}")
    sc.check_invariant()
    print("PASS: py invariant after admin burn")

    expect_raise(lambda: sc.burn("eve", "alice", 10), PermissionError, "py reject unauthorized burn")
    check(sc.bal("alice") == 500, "py alice unchanged", f"{sc.bal('alice')}")

    sc.burn_self("bob", 100)
    check(sc.bal("bob") == 200, "py bob==200 after self-burn", f"{sc.bal('bob')}")
    check(sc.total == 700, "py total==700 after self-burn", f"{sc.total}")
    sc.check_invariant()
    print("PASS: py invariant after self-burn")

    expect_raise(lambda: sc.burn_self("bob", 9999), ValueError, "py reject self-burn overdraft")
    check(sc.bal("bob") == 200, "py bob unchanged", f"{sc.bal('bob')}")

    sc2 = Stablecoin("admin2")
    sc2.check_invariant()
    sc2.mint("admin2", "a", 5000)
    sc2.check_invariant()
    sc2.transfer("a", "b", 2000)
    sc2.check_invariant()
    sc2.burn("admin2", "b", 500)
    sc2.check_invariant()
    sc2.burn_self("a", 250)
    sc2.check_invariant()
    check(sc2.total == 4250, "py final total==4250", f"{sc2.total}")
    check(sc2.bal("a") == 2750, "py final a==2750", f"{sc2.bal('a')}")
    check(sc2.bal("b") == 1500, "py final b==1500", f"{sc2.bal('b')}")
    print("PASS: py supply invariant sequence (#6)")

    # Cross-check the compiled C binary if present
    cbin = HERE / "test_stablecoin_c"
    src = HERE / "test_stablecoin.c"
    try:
        subprocess.run(["clang", "-o", str(cbin), str(src)], check=True, capture_output=True)
        r = subprocess.run([str(cbin)], capture_output=True, text=True)
        ok = r.returncode == 0 and "ALL C TESTS PASSED" in r.stdout
        check(ok, "c binary cross-check", f"rc={r.returncode}")
    except FileNotFoundError:
        print("SKIP: c binary cross-check — clang not found")
    except subprocess.CalledProcessError as e:
        check(False, "c binary cross-check", e.stderr[:200])

    if fails:
        print(f"{len(fails)} FAILURES: {fails}")
        return 1
    print("ALL PYTHON TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
