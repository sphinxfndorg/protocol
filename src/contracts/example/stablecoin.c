// stablecoin.c — Sphinx SIP-20 stablecoin (custodial model), C port.
//
// Native model lives in stablecoin_impl.h (shared with test_stablecoin.c).
// This file adds the WASM on-chain entry (sphinx_main) compiled with
// -DSPHX_WASM for deploy; import surface only sphinx.storage_get /
// storage_set / calldata_word / caller / transferred_value / block_height
// / emit_event / transfer (src/contracts/wasm.go:73-89).
//
// Slot scheme (NO hashing — sequential allocator, collision-free):
//   SLOT_TOTAL   balances total
//   SLOT_ADMIN   admin caller-hash
//   SLOT_NEXT_ID next free owner id (starts at 1; 0 = unassigned)
//   SLOT_IDBASE+i  owner-hash -> id, for i in [0,NOWNER)
//   SLOT_BALBASE+id balance for owner id
// Owner identity on-chain is caller() (first 64 bits of sha256(sender),
// wasm.go:120-121). The NOWNER id-slots are probed with a flat if-chain
// (no loops — wasm_analysis.go:232-233 rejects them). First-touch mint
// allocates id=NEXT_ID and bumps the counter: one extra write per new
// address, reads stay single-slot after that.
#ifdef SPHINX_WASM
typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned int uint32_t;
extern uint64_t storage_get(uint64_t k);
extern void storage_set(uint64_t k, uint64_t v);
extern uint64_t calldata_word(uint64_t off);
extern uint64_t caller(void);
extern uint64_t transferred_value(void);
extern uint64_t block_height(void);
extern void emit_event(uint64_t topic, uint64_t value);

#define SLOT_TOTAL   0x54554f54414cULL
#define SLOT_ADMIN   0x41444d494eULL
#define SLOT_NEXT_ID 0x4e4558544944ULL
#define SLOT_IDBASE  0x0100000000000000ULL
#define SLOT_BALBASE 0x0200000000000000ULL
#define NOWNER 8

static uint64_t slot_of(uint64_t owner) {
    if (storage_get(SLOT_IDBASE + 0) == owner) return SLOT_BALBASE + 1;
    if (storage_get(SLOT_IDBASE + 1) == owner) return SLOT_BALBASE + 2;
    if (storage_get(SLOT_IDBASE + 2) == owner) return SLOT_BALBASE + 3;
    if (storage_get(SLOT_IDBASE + 3) == owner) return SLOT_BALBASE + 4;
    if (storage_get(SLOT_IDBASE + 4) == owner) return SLOT_BALBASE + 5;
    if (storage_get(SLOT_IDBASE + 5) == owner) return SLOT_BALBASE + 6;
    if (storage_get(SLOT_IDBASE + 6) == owner) return SLOT_BALBASE + 7;
    if (storage_get(SLOT_IDBASE + 7) == owner) return SLOT_BALBASE + 8;
    return 0;
}

static uint64_t slot_or_alloc(uint64_t owner) {
    uint64_t s = slot_of(owner);
    if (s) return s;
    uint64_t next = storage_get(SLOT_NEXT_ID);
    if (next == 0) next = 1;
    if (next > NOWNER) return 0;
    storage_set(SLOT_IDBASE + (next - 1), owner);
    storage_set(SLOT_NEXT_ID, next + 1);
    return SLOT_BALBASE + next;
}

// On-chain entry: selector in calldata_word(0):
// 1=mint(to_hash,amount) 2=burn(from_hash,amount) 3=burn_self(amount)
// 4=transfer(to_hash,amount). Caller identity via caller().
uint64_t sphinx_main(void) {
    uint64_t sel = calldata_word(0);
    uint64_t a = calldata_word(8);
    uint64_t b = calldata_word(16);
    uint64_t me = caller();
    if (sel == 1) {
        if (me != storage_get(SLOT_ADMIN)) return 1;
        uint64_t s = slot_or_alloc(a);
        if (!s) return 4;
        storage_set(s, storage_get(s) + b);
        storage_set(SLOT_TOTAL, storage_get(SLOT_TOTAL) + b);
        emit_event(0x4d494e54ULL, b);
        return 0;
    }
    if (sel == 2) {
        if (me != storage_get(SLOT_ADMIN)) return 1;
        uint64_t s = slot_of(a);
        if (!s) return 2;
        uint64_t bal = storage_get(s);
        if (bal < b) return 2;
        storage_set(s, bal - b);
        storage_set(SLOT_TOTAL, storage_get(SLOT_TOTAL) - b);
        emit_event(0x4255524eULL, b);
        return 0;
    }
    if (sel == 3) {
        uint64_t s = slot_of(me);
        if (!s) return 2;
        uint64_t bal = storage_get(s);
        if (bal < a) return 2;
        storage_set(s, bal - a);
        storage_set(SLOT_TOTAL, storage_get(SLOT_TOTAL) - a);
        emit_event(0x4255524eULL, a);
        return 0;
    }
    if (sel == 4) {
        uint64_t fs = slot_of(me);
        if (!fs) return 2;
        uint64_t bal = storage_get(fs);
        if (bal < b) return 2;
        uint64_t ts = slot_or_alloc(a);
        if (!ts) return 4;
        storage_set(fs, bal - b);
        storage_set(ts, storage_get(ts) + b);
        emit_event(0x5452414eULL, b);
        return 0;
    }
    return 3;
}
#endif


