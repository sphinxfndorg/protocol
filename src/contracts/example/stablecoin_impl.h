// stablecoin_impl.h — shared native logic for stablecoin.c / test_stablecoin.c.
// The WASM on-chain entry lives in stablecoin.c under SPHINX_WASM;
// this header holds the testable native model. sc_admin storage is owned
// by the including TU: define STABLECOIN_IMPL_OWNER in exactly one TU.
#ifndef STABLECOIN_IMPL_H
#define STABLECOIN_IMPL_H

#include <stdint.h>
#include <string.h>

#define SC_MAX_ACCTS 64
typedef struct { char owner[64]; uint64_t bal; int used; } ScAcct;
static ScAcct sc_accts[SC_MAX_ACCTS];
static uint64_t sc_total_supply;
static int sc_admin_set;

extern char sc_admin[64];

static ScAcct *sc_find(const char *o) {
    for (int i = 0; i < SC_MAX_ACCTS; i++)
        if (sc_accts[i].used && strcmp(sc_accts[i].owner, o) == 0) return &sc_accts[i];
    return NULL;
}
static ScAcct *sc_get(const char *o) {
    ScAcct *a = sc_find(o);
    if (a) return a;
    for (int i = 0; i < SC_MAX_ACCTS; i++)
        if (!sc_accts[i].used) {
            sc_accts[i].used = 1;
            strncpy(sc_accts[i].owner, o, sizeof(sc_accts[i].owner) - 1);
            sc_accts[i].owner[sizeof(sc_accts[i].owner) - 1] = '\0';
            sc_accts[i].bal = 0;
            return &sc_accts[i];
        }
    return NULL;
}

// returns 0 ok, -1 auth, -2 funds, -3 arg
static int sc_mint(const char *caller, const char *to, uint64_t amount) {
    if (!sc_admin_set) return -3;
    if (strcmp(caller, sc_admin) != 0) return -1;
    if (!to || !*to || amount == 0) return -3;
    ScAcct *a = sc_get(to);
    if (!a) return -3;
    if (a->bal + amount < a->bal) return -2;
    if (sc_total_supply + amount < sc_total_supply) return -2;
    a->bal += amount;
    sc_total_supply += amount;
    return 0;
}
// returns 0 ok, -1 auth, -2 funds, -3 arg
static int sc_burn(const char *caller, const char *from, uint64_t amount) {
    if (!sc_admin_set) return -3;
    if (strcmp(caller, sc_admin) != 0) return -1;
    if (!from || !*from || amount == 0) return -3;
    ScAcct *a = sc_find(from);
    if (!a || a->bal < amount) return -2;
    a->bal -= amount;
    sc_total_supply -= amount;
    return 0;
}
// returns 0 ok, -2 funds, -3 arg
static int sc_burn_self(const char *caller, uint64_t amount) {
    if (amount == 0) return -3;
    ScAcct *a = sc_find(caller);
    if (!a || a->bal < amount) return -2;
    a->bal -= amount;
    sc_total_supply -= amount;
    return 0;
}
// returns 0 ok, -2 funds, -3 arg
static int sc_transfer(const char *from, const char *to, uint64_t amount) {
    if (!to || !*to || amount == 0) return -3;
    ScAcct *f = sc_find(from);
    if (!f || f->bal < amount) return -2;
    ScAcct *t = sc_get(to);
    if (!t) return -3;
    if (t->bal + amount < t->bal) return -2;
    f->bal -= amount;
    t->bal += amount;
    return 0;
}
static uint64_t sc_balance(const char *o) { ScAcct *a = sc_find(o); return a ? a->bal : 0; }
static void sc_init(const char *admin) {
    memset(sc_accts, 0, sizeof(sc_accts));
    sc_total_supply = 0;
    if (admin) {
        memset(sc_admin, 0, 64);
        strncpy(sc_admin, admin, 63);
        sc_admin[63] = '\0';
        sc_admin_set = 1;
    } else {
        sc_admin[0] = '\0';
        sc_admin_set = 0;
    }
}
static uint64_t sc_total(void) { return sc_total_supply; }

// supply invariant: total == sum(balances)
static int sc_check_invariant(void) {
    uint64_t sum = 0;
    for (int i = 0; i < SC_MAX_ACCTS; i++)
        if (sc_accts[i].used) sum += sc_accts[i].bal;
    return sum == sc_total_supply ? 0 : -1;
}

#endif
