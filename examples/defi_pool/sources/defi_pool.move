module defi_pool::amm_vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use sui::coin::{Self, Coin};
    use sui::dynamic_field;

    const E_INSUFFICIENT_BALANCE: u64 = 1;
    const E_NOT_AUTHORIZED: u64 = 2;

    struct AMM_VAULT has drop {}

    struct AdminCap has key, store {
        id: UID,
    }

    struct FlashReceipt {
        amount: u64,
        fee: u64,
    }

    struct Pool<phantom CoinA, phantom CoinB> has key {
        id: UID,
        reserve_a: u64,
        reserve_b: u64,
    }

    struct DepositEvent has copy, drop {
        depositor: address,
        amount_a: u64,
        amount_b: u64,
    }

    fun init(witness: AMM_VAULT, ctx: &mut TxContext) {
        let admin = AdminCap {
            id: object::new(ctx),
        };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    public fun create_pool<CoinA, CoinB>(ctx: &mut TxContext) {
        let pool = Pool<CoinA, CoinB> {
            id: object::new(ctx),
            reserve_a: 0,
            reserve_b: 0,
        };
        transfer::share_object(pool);
    }

    public fun deposit<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        amount_a: u64,
        amount_b: u64,
        ctx: &mut TxContext
    ) {
        assert!(amount_a > 0, E_INSUFFICIENT_BALANCE);
        pool.reserve_a = pool.reserve_a + amount_a;
        pool.reserve_b = pool.reserve_b + amount_b;

        event::emit(DepositEvent {
            depositor: tx_context::sender(ctx),
            amount_a,
            amount_b,
        });
    }

    public fun flash_borrow<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        amount: u64,
    ): FlashReceipt {
        assert!(pool.reserve_a >= amount, E_INSUFFICIENT_BALANCE);
        pool.reserve_a = pool.reserve_a - amount;
        FlashReceipt { amount, fee: 10 }
    }

    public fun flash_repay<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        receipt: FlashReceipt,
    ) {
        let FlashReceipt { amount, fee } = receipt;
        pool.reserve_a = pool.reserve_a + amount + fee;
    }
}
