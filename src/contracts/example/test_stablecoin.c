// test_stablecoin.c — native unit tests for stablecoin.c (clang/gcc).
// Covers the same cases as sip20_stablecoin_test.go: mint, unauthorized
// mint, transfer, overdraft, admin burn, unauthorized burn, self-burn,
// self-burn overdraft, supply invariant after every step.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define sc_admin stablecoin_admin
char stablecoin_admin[64];

#include "stablecoin_impl.h"

static int failures = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("PASS: %s\n", name); } \
    else { printf("FAIL: %s (%s:%d)\n", name, __FILE__, __LINE__); failures++; } \
} while (0)

int main(void) {
    sc_init("admin");

    CHECK(sc_mint("admin", "alice", 1000) == 0, "mint 1000 to alice");
    CHECK(sc_balance("alice") == 1000, "balance alice == 1000");
    CHECK(sc_total() == 1000, "total == 1000 after mint");
    CHECK(sc_check_invariant() == 0, "invariant after mint");

    CHECK(sc_mint("eve", "eve", 500) == -1, "reject unauthorized mint");
    CHECK(sc_total() == 1000, "total unchanged after rejected mint");
    CHECK(sc_balance("eve") == 0, "eve balance 0 after rejected mint");

    CHECK(sc_transfer("alice", "bob", 300) == 0, "transfer alice->bob 300");
    CHECK(sc_balance("alice") == 700, "alice == 700 after transfer");
    CHECK(sc_balance("bob") == 300, "bob == 300 after transfer");
    CHECK(sc_total() == 1000, "total unchanged after transfer");
    CHECK(sc_check_invariant() == 0, "invariant after transfer");

    CHECK(sc_transfer("alice", "bob", 9999) == -2, "reject overdraft transfer");
    CHECK(sc_balance("alice") == 700, "alice unchanged after rejected transfer");
    CHECK(sc_balance("bob") == 300, "bob unchanged after rejected transfer");

    CHECK(sc_burn("admin", "alice", 200) == 0, "admin burn 200 from alice");
    CHECK(sc_balance("alice") == 500, "alice == 500 after admin burn");
    CHECK(sc_total() == 800, "total == 800 after admin burn");
    CHECK(sc_check_invariant() == 0, "invariant after admin burn");

    CHECK(sc_burn("eve", "alice", 10) == -1, "reject unauthorized admin burn");
    CHECK(sc_balance("alice") == 500, "alice unchanged after rejected burn");

    CHECK(sc_burn_self("bob", 100) == 0, "self-burn 100 by bob");
    CHECK(sc_balance("bob") == 200, "bob == 200 after self-burn");
    CHECK(sc_total() == 700, "total == 700 after self-burn");
    CHECK(sc_check_invariant() == 0, "invariant after self-burn");

    CHECK(sc_burn_self("bob", 9999) == -2, "reject self-burn overdraft");
    CHECK(sc_balance("bob") == 200, "bob unchanged after rejected self-burn");

    sc_init("admin2");
    CHECK(sc_check_invariant() == 0, "invariant empty");
    sc_mint("admin2", "a", 5000);
    CHECK(sc_check_invariant() == 0, "invariant after mint 5000");
    sc_transfer("a", "b", 2000);
    CHECK(sc_check_invariant() == 0, "invariant after transfer 2000");
    sc_burn("admin2", "b", 500);
    CHECK(sc_check_invariant() == 0, "invariant after burn 500");
    sc_burn_self("a", 250);
    CHECK(sc_check_invariant() == 0, "invariant after self-burn 250");
    CHECK(sc_total() == 4250, "final total == 4250");
    CHECK(sc_balance("a") == 2750, "final a == 2750");
    CHECK(sc_balance("b") == 1500, "final b == 1500");

    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("ALL C TESTS PASSED\n");
    return 0;
}
