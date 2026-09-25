#![cfg(test)]

use crate::{DataKey, DistributionType, PropertyMeta, PropertyToken, PropertyTokenClient};
use compliance_engine::{ComplianceEngine, ComplianceEngineClient, ComplianceRules};
use kyc_registry::{KycRegistry, KycRegistryClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Env, String,
};

const SCALE: i128 = 10_000_000;

struct Harness {
    env: Env,
    token: PropertyTokenClient<'static>,
    kyc: KycRegistryClient<'static>,
    compliance: ComplianceEngineClient<'static>,
    verifier: Address,
    admin: Address,
}

fn meta(env: &Env) -> PropertyMeta {
    PropertyMeta {
        property_id: String::from_str(env, "PROP-1"),
        legal_name: String::from_str(env, "123 Main St LLC"),
        jurisdiction: String::from_str(env, "US-NY"),
        address: String::from_str(env, "123 Main St"),
        total_valuation_usd: 10_000_000_000_000, // 1,000,000 USD at 7 decimals
        total_shares: 1_000,
        property_type: String::from_str(env, "residential"),
        ipfs_title_hash: String::from_str(env, ""),
        kyc_tier_required: 1,
    }
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let kyc_id = env.register(KycRegistry, ());
    let kyc = KycRegistryClient::new(&env, &kyc_id);
    kyc.initialize(&admin);
    let verifier = Address::generate(&env);
    kyc.add_verifier(&admin, &verifier);

    let compliance_id = env.register(ComplianceEngine, ());
    let compliance = ComplianceEngineClient::new(&env, &compliance_id);
    compliance.initialize(&admin, &kyc_id, &0u64);

    // Property token — constructor args passed atomically at register time
    let token_id = env.register(
        PropertyToken,
        (
            admin.clone(),
            kyc_id.clone(),
            compliance_id.clone(),
            meta(&env),
        ),
    );
    let token = PropertyTokenClient::new(&env, &token_id);

    Harness {
        env,
        token,
        kyc,
        compliance,
        verifier,
        admin,
    }
}

impl Harness {
    fn approve_kyc(&self, addr: &Address) {
        self.approve_kyc_with_tier(addr, 1);
    }

    fn approve_kyc_with_tier(&self, addr: &Address, tier: u32) {
        self.kyc.approve(
            &self.verifier,
            addr,
            &tier,
            &0,
            &String::from_str(&self.env, "US"),
        );
    }
}

fn setup_with_shares(total_shares: i128) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let kyc_id = env.register(KycRegistry, ());
    let kyc = KycRegistryClient::new(&env, &kyc_id);
    kyc.initialize(&admin);
    let verifier = Address::generate(&env);
    kyc.add_verifier(&admin, &verifier);

    let compliance_id = env.register(ComplianceEngine, ());
    let compliance = ComplianceEngineClient::new(&env, &compliance_id);
    compliance.initialize(&admin, &kyc_id, &0u64);

    let custom_meta = PropertyMeta {
        property_id: String::from_str(&env, "PROP-X"),
        legal_name: String::from_str(&env, "Custom Shares LLC"),
        jurisdiction: String::from_str(&env, "US"),
        address: String::from_str(&env, "1 Custom St"),
        total_valuation_usd: 1_000_000,
        total_shares,
        property_type: String::from_str(&env, "residential"),
        ipfs_title_hash: String::from_str(&env, ""),
        kyc_tier_required: 0,
    };

    let token_id = env.register(
        PropertyToken,
        (
            admin.clone(),
            kyc_id.clone(),
            compliance_id.clone(),
            custom_meta,
        ),
    );
    let token = PropertyTokenClient::new(&env, &token_id);

    Harness {
        env,
        token,
        kyc,
        compliance,
        verifier,
        admin,
    }
}

#[test]
fn test_metadata() {
    let h = setup();
    assert_eq!(h.token.decimals(), 0);
    assert_eq!(h.token.total_shares(), 1_000);
    assert_eq!(
        h.token.get_meta().property_id,
        String::from_str(&h.env, "PROP-1")
    );
}

#[test]
fn test_mint_and_transfer() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    assert!(h.token.try_mint(&Address::generate(&h.env), &10).is_err());

    h.token.mint(&alice, &100);
    assert_eq!(h.token.balance(&alice), 100);

    h.token.transfer(&alice, &bob, &40);
    assert_eq!(h.token.balance(&alice), 60);
    assert_eq!(h.token.balance(&bob), 40);
}

#[test]
fn test_mint_rejects_recipient_below_required_tier() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 0);

    assert!(h.token.try_mint(&alice, &100).is_err());
}

#[test]
fn test_mint_rejects_blocklisted_recipient() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.compliance.add_to_blocklist(&alice);

    assert!(h.token.try_mint(&alice, &100).is_err());
}

#[test]
fn test_mint_rejects_when_compliance_paused() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.compliance.pause();

    assert!(h.token.try_mint(&alice, &100).is_err());
}

#[test]
fn test_transfer_insufficient_shares() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.mint(&alice, &10);
    assert!(h.token.try_transfer(&alice, &bob, &11).is_err());
}

#[test]
fn test_dividend_distribution() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &100);

    // Deposit 1000 stroops over 1000 total shares => 1 per share.
    h.token.deposit_dividend(&1_000, &2);
    assert_eq!(h.token.pending_dividend(&alice), 100);

    let claimed = h.token.claim_dividend(&alice);
    assert_eq!(claimed, 100);
    assert_eq!(h.token.pending_dividend(&alice), 0);

    // Claiming again yields nothing.
    assert_eq!(h.token.claim_dividend(&alice), 0);
}

#[test]
fn test_multi_round_dividend_with_partial_transfer() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &1_000);

    // First dividend round: Alice owns all 1000 shares.
    h.token.deposit_dividend(&1_000, &2);

    // Transfer 400 shares to Bob after the first round.
    h.token.transfer(&alice, &bob, &400);

    // Second dividend round: Alice owns 600, Bob owns 400.
    h.token.deposit_dividend(&1_000, &2);

    let alice_claimed = h.token.claim_dividend(&alice);
    let bob_claimed = h.token.claim_dividend(&bob);

    assert_eq!(alice_claimed, 1_600);
    assert_eq!(bob_claimed, 400);
}

#[test]
fn test_deposit_dividend_requires_shares() {
    let h = setup();
    // total_shares is 1000 from meta, so deposit works even before mint.
    h.token.deposit_dividend(&1_000, &2);
    let alice = Address::generate(&h.env);
    assert_eq!(h.token.pending_dividend(&alice), 0);
}

#[test]
fn test_non_deployer_cannot_reinitialize() {
    let h = setup();
    let attacker = Address::generate(&h.env);
    let kyc_id = Address::generate(&h.env);
    let ce_id = Address::generate(&h.env);
    // initialize must always panic — the constructor has already run
    let result = h
        .token
        .try_initialize(&attacker, &kyc_id, &ce_id, &meta(&h.env));
    assert!(result.is_err());
}

#[test]
fn test_transfer_blocked_by_holding_period() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    // Configure a one-hour minimum holding period on the real compliance engine.
    h.compliance.set_rules(&ComplianceRules {
        max_transfer_amount: 0,
        min_holding_period: 3600,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    });

    // Minting registers alice as a holder at the current ledger timestamp.
    h.token.mint(&alice, &100);

    // A transfer immediately after minting is blocked: the holding period has
    // not elapsed.
    assert!(h.token.try_transfer(&alice, &bob, &10).is_err());

    // Advance past the holding period; the transfer now succeeds.
    h.env
        .ledger()
        .set_timestamp(h.env.ledger().timestamp() + 3601);
    h.token.transfer(&alice, &bob, &10);
    assert_eq!(h.token.balance(&bob), 10);
    assert_eq!(h.token.balance(&alice), 90);
}

#[test]
fn test_transfer_snapshots_dividends() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.mint(&alice, &100);

    h.token.deposit_dividend(&1_000, &2); // 1 per share
                                          // Alice accrued 100 before transferring all her shares.
    h.token.transfer(&alice, &bob, &100);

    // Bob just received shares; he must not inherit Alice's accrued dividend.
    assert_eq!(h.token.pending_dividend(&bob), 0);
    // Alice keeps the 100 she accrued while she held the shares.
    assert_eq!(h.token.pending_dividend(&alice), 100);
    assert_eq!(h.token.claim_dividend(&alice), 100);

    // A dividend declared after the transfer accrues to Bob, not Alice.
    h.token.deposit_dividend(&1_000, &2);
    assert_eq!(h.token.pending_dividend(&bob), 100);
    assert_eq!(h.token.pending_dividend(&alice), 0);
}

// ── Holder list tests ─────────────────────────────────────────────────────────

#[test]
fn test_holder_list_updated_on_mint() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    assert_eq!(h.token.holder_count(), 0);

    h.token.mint(&alice, &100);
    assert_eq!(h.token.holder_count(), 1);
    assert!(h.token.is_holder(&alice));

    h.token.mint(&bob, &50);
    assert_eq!(h.token.holder_count(), 2);
    assert!(h.token.is_holder(&bob));

    // Minting again to alice is idempotent — count stays at 2.
    h.token.mint(&alice, &10);
    assert_eq!(h.token.holder_count(), 2);
}

#[test]
fn test_holder_removed_when_balance_hits_zero() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &100);
    assert_eq!(h.token.holder_count(), 1);
    assert!(h.token.is_holder(&alice));

    // Transfer entire balance — alice drops to 0, bob is added.
    h.token.transfer(&alice, &bob, &100);
    assert_eq!(h.token.holder_count(), 1);
    assert!(!h.token.is_holder(&alice));
    assert!(h.token.is_holder(&bob));
}

#[test]
fn test_get_holders_pagination() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let carol = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.approve_kyc(&carol);

    h.token.mint(&alice, &10);
    h.token.mint(&bob, &10);
    h.token.mint(&carol, &10);
    // O(1) IsHolder tracking — holder_count correct.
    assert_eq!(h.token.holder_count(), 3);
    assert!(h.token.is_holder(&alice));
    assert!(h.token.is_holder(&bob));
    assert!(h.token.is_holder(&carol));
    // get_holders reflects HolderList (populated by migration, not new mints).
    assert_eq!(h.token.get_holders(&0, &50).len(), 0);
}

#[test]
fn test_transfer_rejects_recipient_below_required_tier() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    // alice has tier 1 (meets requirement), bob has tier 0 (below requirement)
    h.approve_kyc_with_tier(&alice, 1);
    h.approve_kyc_with_tier(&bob, 0);
    h.token.mint(&alice, &100);
    // Transfer to bob must fail because his tier (0) is below kyc_tier_required (1)
    assert!(h.token.try_transfer(&alice, &bob, &50).is_err());
}

// ── transfer_from tier enforcement tests (#254) ───────────────────────────────

#[test]
fn test_transfer_from_rejects_recipient_below_required_tier() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let spender = Address::generate(&h.env);
    // alice has tier 1, bob has tier 0 (below kyc_tier_required=1)
    h.approve_kyc_with_tier(&alice, 1);
    h.approve_kyc_with_tier(&bob, 0);
    h.approve_kyc_with_tier(&spender, 1);
    h.token.mint(&alice, &100);
    h.token
        .approve(&alice, &spender, &50, &(h.env.ledger().sequence() + 100));
    assert!(h
        .token
        .try_transfer_from(&spender, &alice, &bob, &50)
        .is_err());
}

#[test]
fn test_transfer_from_accepts_recipient_with_sufficient_tier() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    let spender = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.approve_kyc_with_tier(&bob, 1);
    h.approve_kyc_with_tier(&spender, 1);
    h.token.mint(&alice, &100);
    h.token
        .approve(&alice, &spender, &50, &(h.env.ledger().sequence() + 100));
    h.token.transfer_from(&spender, &alice, &bob, &50);
    assert_eq!(h.token.balance(&bob), 50);
}

// ── property_type validation tests (#256) ─────────────────────────────────────

#[test]
#[should_panic]
fn test_invalid_property_type_panics_in_constructor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = Address::generate(&env);
    let ce_id = Address::generate(&env);
    let mut bad_meta = meta(&env);
    bad_meta.property_type = String::from_str(&env, "warehouse");
    env.register(PropertyToken, (admin, kyc_id, ce_id, bad_meta));
}

#[test]
fn test_valid_property_types_accepted_in_constructor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    for pt in ["residential", "commercial", "land"] {
        let kyc_id = env.register(KycRegistry, ());
        let kyc = KycRegistryClient::new(&env, &kyc_id);
        kyc.initialize(&admin);
        let compliance_id = env.register(ComplianceEngine, ());
        let compliance = ComplianceEngineClient::new(&env, &compliance_id);
        compliance.initialize(&admin, &kyc_id, &0u64);
        let mut m = meta(&env);
        m.property_type = String::from_str(&env, pt);
        let token_id = env.register(PropertyToken, (admin.clone(), kyc_id, compliance_id, m));
        let token = PropertyTokenClient::new(&env, &token_id);
        assert_eq!(token.get_meta().property_type, String::from_str(&env, pt));
    }
}

#[test]
fn test_invalid_property_type_panics_in_update_meta() {
    let h = setup();
    let mut bad_meta = h.token.get_meta();
    bad_meta.property_type = String::from_str(&h.env, "warehouse");
    assert!(h.token.try_update_meta(&bad_meta).is_err());
}

#[test]
fn test_valid_property_type_accepted_in_update_meta() {
    let h = setup();
    let mut new_meta = h.token.get_meta();
    new_meta.property_type = String::from_str(&h.env, "commercial");
    h.token.update_meta(&new_meta);
    assert_eq!(
        h.token.get_meta().property_type,
        String::from_str(&h.env, "commercial")
    );
}

// ── update_kyc_registry / update_compliance_engine tests ─────────────────────

#[test]
fn test_update_kyc_registry_admin_only() {
    let h = setup();
    let new_kyc = Address::generate(&h.env);

    // Non-admin: separate env, no auths mocked
    {
        let env2 = Env::default();
        let non_admin = Address::generate(&env2);
        let token_id2 = env2.register(
            PropertyToken,
            (
                non_admin.clone(),
                Address::generate(&env2),
                Address::generate(&env2),
                meta(&env2),
            ),
        );
        let client2 = PropertyTokenClient::new(&env2, &token_id2);
        assert!(client2
            .try_update_kyc_registry(&Address::generate(&env2))
            .is_err());
    }

    // Admin succeeds
    h.token.update_kyc_registry(&new_kyc);

    // Minting now fails because the new registry has no approvals
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice); // approved in OLD registry only
    assert!(h.token.try_mint(&alice, &10).is_err());
}

#[test]
fn test_update_compliance_engine_admin_only() {
    let h = setup();

    // Non-admin: separate env, no auths mocked
    {
        let env2 = Env::default();
        let non_admin = Address::generate(&env2);
        let token_id2 = env2.register(
            PropertyToken,
            (
                non_admin.clone(),
                Address::generate(&env2),
                Address::generate(&env2),
                meta(&env2),
            ),
        );
        let client2 = PropertyTokenClient::new(&env2, &token_id2);
        assert!(client2
            .try_update_compliance_engine(&Address::generate(&env2))
            .is_err());
    }

    // Deploy a second compliance engine and pause it
    let ce2_id = h.env.register(ComplianceEngine, ());
    let ce2 = ComplianceEngineClient::new(&h.env, &ce2_id);
    let dummy_kyc = h.env.register(kyc_registry::KycRegistry, ());
    ce2.initialize(&h.admin, &dummy_kyc, &0u64);
    ce2.pause();

    // Admin can update
    h.token.update_compliance_engine(&ce2_id);

    // Mints through the paused engine are now blocked
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    assert!(h.token.try_mint(&alice, &10).is_err());
}

// ── Buyback tests ─────────────────────────────────────────────────────────────

#[test]
fn test_buyback_successful() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);

    // Mint 100 shares to alice
    h.token.mint(&alice, &100);
    assert_eq!(h.token.balance(&alice), 100);
    assert_eq!(h.token.total_shares(), 1_000);

    // Deposit dividend before buyback
    h.token.deposit_dividend(&1_000, &2); // 1 per share
    assert_eq!(h.token.pending_dividend(&alice), 100);

    // Admin buys back 50 shares
    h.token.buyback(&alice, &50);

    // Balance and total shares decreased
    assert_eq!(h.token.balance(&alice), 50);
    assert_eq!(h.token.total_shares(), 950);

    // Alice still has her accrued dividend from before buyback
    assert_eq!(h.token.pending_dividend(&alice), 100);

    // She can still claim it
    let claimed = h.token.claim_dividend(&alice);
    assert_eq!(claimed, 100);
}

#[test]
fn test_buyback_insufficient_shares() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);

    h.token.mint(&alice, &50);
    // Try to buy back 51 shares — should fail
    assert!(h.token.try_buyback(&alice, &51).is_err());
}

#[test]
fn test_buyback_removes_holder_on_zero_balance() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &50);
    h.token.mint(&bob, &30);
    assert_eq!(h.token.holder_count(), 2);

    // Buy back all of alice's shares
    h.token.buyback(&alice, &50);

    // Alice is removed from holder tracking
    assert_eq!(h.token.holder_count(), 1);
    assert!(!h.token.is_holder(&alice));
    assert!(h.token.is_holder(&bob));
}

#[test]
fn test_buyback_non_admin_rejected() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let attacker = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&attacker);

    h.token.mint(&alice, &100);

    // Attacker cannot buyback
    let env2 = Env::default();
    let non_admin = Address::generate(&env2);
    let token_id2 = env2.register(
        PropertyToken,
        (
            Address::generate(&env2),
            Address::generate(&env2),
            Address::generate(&env2),
            meta(&env2),
        ),
    );
    let client2 = PropertyTokenClient::new(&env2, &token_id2);

    // Should fail because non_admin is not the admin
    assert!(client2.try_buyback(&non_admin, &50).is_err());
}

#[test]
fn test_buyback_rejects_kyc_unapproved_holder() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);

    h.token.mint(&alice, &100);

    // Revoke alice's KYC by spinning up a new registry with no approvals
    let new_kyc_id = h.env.register(KycRegistry, ());
    let new_kyc = KycRegistryClient::new(&h.env, &new_kyc_id);
    new_kyc.initialize(&h.admin);
    h.token.update_kyc_registry(&new_kyc_id);

    // Buyback should now fail — alice no longer has active KYC
    assert!(h.token.try_buyback(&alice, &50).is_err());
}

#[test]
fn test_version_returns_nonempty() {
    let h = setup();
    let v = h.token.version();
    assert!(!v.is_empty());
}

#[test]
fn test_dividend_history_records_deposits() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &500);

    assert_eq!(h.token.dividend_deposit_count(), 0);

    h.token.deposit_dividend(&1_000, &2);
    h.token.deposit_dividend(&2_000, &2);

    assert_eq!(h.token.dividend_deposit_count(), 2);

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.len(), 2);

    let first = history.get(0).unwrap();
    assert_eq!(first.amount, 1_000);

    let second = history.get(1).unwrap();
    assert_eq!(second.amount, 2_000);
}

#[test]
fn test_dividend_history_running_total_dps_legacy() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    // deposit(1000) on 1000 shares → per_share_scaled = 10_000_000.
    // deposit(2000) on 1000 shares → per_share_scaled = 20_000_000 → cumulative = 30_000_000.
    h.token.deposit_dividend(&1_000, &2);
    h.token.deposit_dividend(&2_000, &2);

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.get(0).unwrap().running_total_dps, SCALE);
    assert_eq!(history.get(1).unwrap().running_total_dps, 3 * SCALE);
}

// ── Checkpointed dividend accounting (#509) ──────────────────────────────────

#[test]
fn test_distribution_checkpoint_reconciles_rounding() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    // deposit(1250) on 1000 total_shares.
    // per_share_scaled = floor(1250 * 10^7 / 1000) = 12_500_000 (exact).
    // alice (1000 shares) gets floor(1000 * 12_500_000 / 10^7) = 1250 (full amount).
    h.token.deposit_dividend(&1_250, &0);

    assert_eq!(h.token.dividend_accounting_version(), 1);
    let checkpoint = h.token.get_distribution(&0).unwrap();
    assert_eq!(checkpoint.id, 0);
    assert_eq!(checkpoint.amount, 1_250);
    assert_eq!(checkpoint.total_shares, 1_000);
    // per_share = per_share_scaled / SCALE = 12_500_000 / 10_000_000 = 1 (unscaled audit field).
    assert_eq!(checkpoint.per_share, 1);
    // per_share_scaled = (1250 * 10^7) / 1000 = 12_500_000.
    assert_eq!(checkpoint.per_share_scaled, 12_500_000);
    // allocated_amount uses scaled calculation: 12_500_000 * 1000 / 10^7 = 1250.
    assert_eq!(checkpoint.allocated_amount, 1_250);
    // remainder = amount - per_share * total_shares (unscaled audit field) = 1250 - 1000 = 250.
    assert_eq!(checkpoint.remainder, 250);
    // dust_reserve = amount - allocated_amount (scaled) = 0 (fully allocated by SCALE_FACTOR).
    assert_eq!(h.token.dust_reserve(), 0);
    // cumulative_per_share is now scaled.
    assert_eq!(checkpoint.cumulative_per_share, 12_500_000);
    assert_eq!(checkpoint.rent_cumulative_per_share, 12_500_000);
    assert_eq!(checkpoint.capital_cumulative_per_share, 0);
    assert_eq!(checkpoint.other_cumulative_per_share, 0);
    assert_eq!(checkpoint.type_cumulative_per_share, 12_500_000);
    assert_eq!(checkpoint.distribution_type, 0);

    let page = h.token.get_distributions(&0, &10);
    assert_eq!(page.len(), 1);
    assert_eq!(page.get(0).unwrap().id, 0);

    // Alice holds all 1000 shares — receives the full 1250.
    let unclaimed = h.token.unclaimed_balance(&alice);
    assert_eq!(unclaimed.total, 1_250);
    assert_eq!(unclaimed.rent, 1_250);
    assert_eq!(unclaimed.capital, 0);
    assert_eq!(unclaimed.other, 0);
    assert_eq!(unclaimed.distribution_count, 1);
}

#[test]
fn test_claim_all_clears_typed_claims_and_cannot_overdraw_pool() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    h.token.deposit_dividend(&1_000, &0);
    h.token.deposit_dividend(&2_000, &1);
    h.token.deposit_dividend(&3_000, &2);

    assert_eq!(h.token.claim_dividend(&alice), 6_000);
    assert_eq!(h.token.pending_dividend(&alice), 0);
    assert_eq!(h.token.claim_rent_yield(&alice), 0);
    assert_eq!(h.token.claim_capital_return(&alice), 0);
    // Dust reserve may hold any SCALE_FACTOR truncation remainder; subtract it.
    let dust = h.token.dust_reserve();
    assert_eq!(h.token.dividend_pool(), dust);
}

#[test]
fn test_claims_derive_indexes_from_distribution_journal() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);
    h.token.deposit_dividend(&1_000, &0);
    h.token.deposit_dividend(&2_000, &1);

    // The immutable latest distribution checkpoint is the source of truth for
    // post-upgrade accrual. Legacy mutable index keys are only a migration
    // fallback and cannot alter a checkpoint-backed claim.
    h.env.as_contract(&h.token.address, || {
        h.env
            .storage()
            .instance()
            .set(&DataKey::DividendPerShare, &0i128);
        h.env
            .storage()
            .instance()
            .set(&DataKey::DividendPerShareRent, &0i128);
        h.env
            .storage()
            .instance()
            .set(&DataKey::DividendPerShareCapital, &0i128);
    });
    // Deposits: 1000 rent + 2000 capital on 1000 shares (all exact).
    // per_share_scaled for rent = 10M, capital = 20M → unclaimed_rent = 1000, capital = 2000.

    let unclaimed = h.token.unclaimed_balance(&alice);
    assert_eq!(unclaimed.total, 3_000);
    assert_eq!(unclaimed.rent, 1_000);
    assert_eq!(unclaimed.capital, 2_000);
    assert_eq!(h.token.claim_dividend(&alice), 3_000);
    assert_eq!(h.token.dividend_pool(), 0);
}

#[test]
fn test_legacy_claim_all_state_cannot_restore_stale_typed_claims() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    h.token.deposit_dividend(&1_000, &0);
    assert_eq!(h.token.claim_dividend(&alice), 1_000);
    assert_eq!(h.token.dividend_pool(), 0);

    // Recreate the pre-checkpoint bug: claim-all cleared the aggregate amount
    // and pool, but left a stale typed rent counter.
    // Also remove LegacyMigrationComplete so the lazy bridge runs.
    h.env.as_contract(&h.token.address, || {
        h.env
            .storage()
            .persistent()
            .remove(&DataKey::HolderDividendCheckpoint(alice.clone()));
        h.env
            .storage()
            .persistent()
            .remove(&DataKey::LegacyMigrationComplete(alice.clone()));
        h.env
            .storage()
            .instance()
            .set(&DataKey::UnclaimedRent(alice.clone()), &1_000i128);
    });

    let migrated = h.token.unclaimed_balance(&alice);
    assert_eq!(migrated.total, 0);
    assert_eq!(migrated.rent, 0);
    assert_eq!(migrated.capital, 0);
    assert_eq!(h.token.claim_rent_yield(&alice), 0);
    let dust = h.token.dust_reserve();
    assert_eq!(h.token.dividend_pool(), dust);
}

#[test]
fn test_typed_claim_reconciles_aggregate_claimable() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    h.token.deposit_dividend(&1_000, &0);
    h.token.deposit_dividend(&2_000, &1);

    assert_eq!(h.token.claim_rent_yield(&alice), 1_000);
    let after_rent = h.token.unclaimed_balance(&alice);
    assert_eq!(after_rent.total, 2_000);
    assert_eq!(after_rent.rent, 0);
    assert_eq!(after_rent.capital, 2_000);

    assert_eq!(h.token.claim_dividend(&alice), 2_000);
    assert_eq!(h.token.claim_capital_return(&alice), 0);
    assert_eq!(h.token.dividend_pool(), 0);
}

#[test]
fn test_forced_transfer_preserves_both_holders_accrual() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);
    h.token.mint(&alice, &600);
    h.token.mint(&bob, &400);

    h.token.deposit_dividend(&1_000, &0);
    h.token.forced_transfer(&alice, &bob, &200);
    h.token.deposit_dividend(&1_000, &1);

    let alice_unclaimed = h.token.unclaimed_balance(&alice);
    assert_eq!(alice_unclaimed.total, 1_000);
    assert_eq!(alice_unclaimed.rent, 600);
    assert_eq!(alice_unclaimed.capital, 400);

    let bob_unclaimed = h.token.unclaimed_balance(&bob);
    assert_eq!(bob_unclaimed.total, 1_000);
    assert_eq!(bob_unclaimed.rent, 400);
    assert_eq!(bob_unclaimed.capital, 600);

    assert_eq!(h.token.claim_dividend(&alice), 1_000);
    assert_eq!(h.token.claim_dividend(&bob), 1_000);
    assert_eq!(h.token.dividend_pool(), 0);
}

#[test]
fn test_deterministic_random_claim_transfer_model_preserves_invariants() {
    fn next(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *seed
    }

    let h = setup();
    let holders = [
        Address::generate(&h.env),
        Address::generate(&h.env),
        Address::generate(&h.env),
        Address::generate(&h.env),
    ];
    for holder in &holders {
        h.approve_kyc(holder);
    }
    h.token.mint(&holders[0], &1_000);

    let mut balances = [1_000i128, 0i128, 0i128, 0i128];
    let mut expected_total = [0i128; 4];
    let mut expected_rent = [0i128; 4];
    let mut expected_capital = [0i128; 4];
    let mut distributions = 0u32;
    let mut expected_pool = 0i128;
    let mut seed = 0x5eed_0509_dead_beefu64;

    for step in 0usize..180 {
        let operation = next(&mut seed) % 7;
        if operation == 0 || distributions == 0 {
            let distribution_type = (next(&mut seed) % 3) as u32;
            h.token.deposit_dividend(&1_000, &distribution_type);
            for index in 0..holders.len() {
                expected_total[index] += balances[index];
                if distribution_type == DistributionType::Rent as u32 {
                    expected_rent[index] += balances[index];
                } else if distribution_type == DistributionType::Capital as u32 {
                    expected_capital[index] += balances[index];
                }
            }
            distributions += 1;
            expected_pool += 1_000;
        } else if operation == 1 || operation == 2 {
            let start = (next(&mut seed) as usize) % holders.len();
            let mut from_index = start;
            for offset in 0..holders.len() {
                let candidate = (start + offset) % holders.len();
                if balances[candidate] > 0 {
                    from_index = candidate;
                    break;
                }
            }
            let to_index =
                (from_index + 1 + (next(&mut seed) as usize % (holders.len() - 1))) % holders.len();
            let amount = if step % 11 == 0 {
                balances[from_index]
            } else {
                1 + i128::from(next(&mut seed) % balances[from_index] as u64)
            };
            if operation == 1 {
                h.token
                    .transfer(&holders[from_index], &holders[to_index], &amount);
            } else {
                h.token
                    .forced_transfer(&holders[from_index], &holders[to_index], &amount);
            }
            balances[from_index] -= amount;
            balances[to_index] += amount;
        } else {
            let holder_index = (next(&mut seed) as usize) % holders.len();
            let claimed = if operation == 3 {
                let amount = h.token.claim_dividend(&holders[holder_index]);
                assert_eq!(amount, expected_total[holder_index]);
                expected_total[holder_index] = 0;
                expected_rent[holder_index] = 0;
                expected_capital[holder_index] = 0;
                amount
            } else if operation == 4 {
                let amount = h.token.claim_rent_yield(&holders[holder_index]);
                assert_eq!(amount, expected_rent[holder_index]);
                expected_total[holder_index] -= amount;
                expected_rent[holder_index] = 0;
                amount
            } else {
                let amount = h.token.claim_capital_return(&holders[holder_index]);
                assert_eq!(amount, expected_capital[holder_index]);
                expected_total[holder_index] -= amount;
                expected_capital[holder_index] = 0;
                amount
            };
            expected_pool -= claimed;
        }

        for index in 0..holders.len() {
            assert_eq!(h.token.balance(&holders[index]), balances[index]);
            assert_eq!(
                h.token.pending_dividend(&holders[index]),
                expected_total[index]
            );
            let unclaimed = h.token.unclaimed_balance(&holders[index]);
            assert_eq!(unclaimed.total, expected_total[index]);
            assert_eq!(unclaimed.rent, expected_rent[index]);
            assert_eq!(unclaimed.capital, expected_capital[index]);
            assert_eq!(
                unclaimed.other,
                expected_total[index] - expected_rent[index] - expected_capital[index]
            );
        }
        let expected_holder_count = balances.iter().filter(|balance| **balance > 0).count() as u32;
        assert_eq!(h.token.holder_count(), expected_holder_count);
        assert_eq!(h.token.dividend_pool(), expected_pool);
        assert_eq!(h.token.dividend_deposit_count(), distributions);
    }

    for index in 0..holders.len() {
        assert_eq!(
            h.token.claim_dividend(&holders[index]),
            expected_total[index]
        );
    }
    assert_eq!(h.token.dividend_pool(), 0);
}

#[test]
fn test_rejects_invalid_distribution_inputs() {
    let h = setup();
    assert!(h.token.try_deposit_dividend(&0, &0).is_err());
    assert!(h.token.try_deposit_dividend(&-1, &0).is_err());
    assert!(h.token.try_deposit_dividend(&1_000, &3).is_err());
}

#[test]
fn test_dividend_history_pagination() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    for _ in 0..5 {
        h.token.deposit_dividend(&100, &2);
    }

    let page = h.token.get_dividend_history(&2, &2);
    assert_eq!(page.len(), 2);
    assert_eq!(page.get(0).unwrap().amount, 100);
}

#[test]
fn test_dividend_history_empty_before_deposit() {
    let h = setup();
    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.len(), 0);
    assert_eq!(h.token.dividend_deposit_count(), 0);
}

// ── #278 Rent yield tracking tests ───────────────────────────────────────────

#[test]
fn test_claim_rent_yield_only_claims_rent() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &1_000);

    // Deposit 1000 as Rent (type 0) and 2000 as Capital (type 1)
    h.token.deposit_dividend(&1_000, &0); // rent: 1 per share
    h.token.deposit_dividend(&2_000, &1); // capital: 2 per share

    let rent = h.token.claim_rent_yield(&alice);
    assert_eq!(rent, 1_000); // 1 per share * 1000 shares

    // Capital untouched
    let capital = h.token.claim_capital_return(&alice);
    assert_eq!(capital, 2_000); // 2 per share * 1000 shares
}

#[test]
fn test_claim_capital_return_only_claims_capital() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &500);

    // total_shares from meta = 1000, so DPS = amount / 1000
    // deposit 1000 rent => DPS_rent = 1; deposit 2000 capital => DPS_cap = 2
    h.token.deposit_dividend(&1_000, &0); // rent DPS = 1
    h.token.deposit_dividend(&2_000, &1); // capital DPS = 2

    let capital = h.token.claim_capital_return(&alice);
    assert_eq!(capital, 1_000); // DPS=2 * 500 shares

    // Rent untouched
    let rent = h.token.claim_rent_yield(&alice);
    assert_eq!(rent, 500); // DPS=1 * 500 shares
}

#[test]
fn test_claim_dividend_claims_all_types() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &100);

    // total_shares = 1000, so need multiples of 1000 for integer DPS > 0
    // deposit 1000 => DPS=1; 2000 => DPS=2; 3000 => DPS=3
    h.token.deposit_dividend(&1_000, &0); // rent DPS = 1
    h.token.deposit_dividend(&2_000, &1); // capital DPS = 2
    h.token.deposit_dividend(&3_000, &2); // other DPS = 3

    let total = h.token.claim_dividend(&alice);
    // total DPS = 6, 100 shares => 600
    assert_eq!(total, 600);
}

#[test]
fn test_mixed_deposits_independent_claiming() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &600);
    h.token.mint(&bob, &400);

    // Round 1: rent
    h.token.deposit_dividend(&1_000, &0);
    // Round 2: capital
    h.token.deposit_dividend(&1_000, &1);

    // Alice: 60% of rent + 60% of capital
    assert_eq!(h.token.claim_rent_yield(&alice), 600);
    assert_eq!(h.token.claim_capital_return(&alice), 600);

    // Bob: 40% of each
    assert_eq!(h.token.claim_rent_yield(&bob), 400);
    assert_eq!(h.token.claim_capital_return(&bob), 400);
}

#[test]
fn test_second_claim_yields_nothing() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &100);

    h.token.deposit_dividend(&1_000, &0);

    h.token.claim_rent_yield(&alice);
    assert_eq!(h.token.claim_rent_yield(&alice), 0);

    h.token.deposit_dividend(&1_000, &1);
    h.token.claim_capital_return(&alice);
    assert_eq!(h.token.claim_capital_return(&alice), 0);
}

// ── Dividend auditability tests (#355) ───────────────────────────────────────

#[test]
fn test_dividend_deposit_count_increments_checkpoint_audit() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    assert_eq!(h.token.dividend_deposit_count(), 0);

    h.token.deposit_dividend(&1_000, &0); // Rent
    assert_eq!(h.token.dividend_deposit_count(), 1);

    h.token.deposit_dividend(&2_000, &1); // Capital
    assert_eq!(h.token.dividend_deposit_count(), 2);

    h.token.deposit_dividend(&500, &2); // Other
    assert_eq!(h.token.dividend_deposit_count(), 3);
}

#[test]
fn test_get_dividend_history_returns_events_checkpoint_audit() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    h.token.deposit_dividend(&1_000, &0); // Rent
    h.token.deposit_dividend(&2_000, &1); // Capital

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.len(), 2);

    let first = history.get(0).unwrap();
    assert_eq!(first.amount, 1_000);
    assert_eq!(first.distribution_type, 0); // Rent

    let second = history.get(1).unwrap();
    assert_eq!(second.amount, 2_000);
    assert_eq!(second.distribution_type, 1); // Capital
}

#[test]
fn test_get_dividend_history_pagination_checkpoint_audit() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    // Deposit 5 events
    for _ in 0..5 {
        h.token.deposit_dividend(&100, &2);
    }
    assert_eq!(h.token.dividend_deposit_count(), 5);

    // First page: 3 entries starting at 0
    let page1 = h.token.get_dividend_history(&0, &3);
    assert_eq!(page1.len(), 3);

    // Second page: remaining 2 entries
    let page2 = h.token.get_dividend_history(&3, &3);
    assert_eq!(page2.len(), 2);

    // Past end: empty
    let past_end = h.token.get_dividend_history(&5, &3);
    assert_eq!(past_end.len(), 0);
}

#[test]
fn test_dividend_history_running_total_dps_checkpoint_audit() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &1_000); // 1000 shares

    // Deposit 1000 → dps += per_share_scaled = 10_000_000
    h.token.deposit_dividend(&1_000, &0);
    // Deposit 2000 → dps += 20_000_000 (cumulative = 30_000_000)
    h.token.deposit_dividend(&2_000, &0);

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.get(0).unwrap().running_total_dps, SCALE);
    assert_eq!(history.get(1).unwrap().running_total_dps, 3 * SCALE);
}

// ── Dividend auditability tests (#355) ───────────────────────────────────────

#[test]
fn test_dividend_deposit_count_increments() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    assert_eq!(h.token.dividend_deposit_count(), 0);

    h.token.deposit_dividend(&1_000, &0); // Rent
    assert_eq!(h.token.dividend_deposit_count(), 1);

    h.token.deposit_dividend(&2_000, &1); // Capital
    assert_eq!(h.token.dividend_deposit_count(), 2);

    h.token.deposit_dividend(&500, &2); // Other
    assert_eq!(h.token.dividend_deposit_count(), 3);
}

#[test]
fn test_get_dividend_history_returns_events() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    h.token.deposit_dividend(&1_000, &0); // Rent
    h.token.deposit_dividend(&2_000, &1); // Capital

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.len(), 2);

    let first = history.get(0).unwrap();
    assert_eq!(first.amount, 1_000);
    assert_eq!(first.distribution_type, 0); // Rent

    let second = history.get(1).unwrap();
    assert_eq!(second.amount, 2_000);
    assert_eq!(second.distribution_type, 1); // Capital
}

#[test]
fn test_get_dividend_history_pagination() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &100);

    for _ in 0..5 {
        h.token.deposit_dividend(&100, &2);
    }
    assert_eq!(h.token.dividend_deposit_count(), 5);

    let page1 = h.token.get_dividend_history(&0, &3);
    assert_eq!(page1.len(), 3);

    let page2 = h.token.get_dividend_history(&3, &3);
    assert_eq!(page2.len(), 2);

    let past_end = h.token.get_dividend_history(&5, &3);
    assert_eq!(past_end.len(), 0);
}

#[test]
fn test_dividend_history_running_total_dps() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc_with_tier(&alice, 1);
    h.token.mint(&alice, &1_000); // 1000 shares

    // Deposit 1000 → per_share_scaled = 10_000_000
    h.token.deposit_dividend(&1_000, &0);
    // Deposit 2000 → per_share_scaled = 20_000_000 (cumulative = 30_000_000)
    h.token.deposit_dividend(&2_000, &0);

    let history = h.token.get_dividend_history(&0, &10);
    assert_eq!(history.get(0).unwrap().running_total_dps, SCALE);
    assert_eq!(history.get(1).unwrap().running_total_dps, 3 * SCALE);
}

// ── O(1) holder tracking tests ────────────────────────────────────────────────

#[test]
fn test_is_holder_add_dedup() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);

    assert!(!h.token.is_holder(&alice));
    assert_eq!(h.token.holder_count(), 0);

    h.token.mint(&alice, &100);
    assert!(h.token.is_holder(&alice));
    assert_eq!(h.token.holder_count(), 1);

    // Minting more shares is idempotent for IsHolder.
    h.token.mint(&alice, &10);
    assert_eq!(h.token.holder_count(), 1);
}

#[test]
fn test_is_holder_remove_on_zero_balance() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &100);
    assert!(h.token.is_holder(&alice));
    assert_eq!(h.token.holder_count(), 1);

    h.token.transfer(&alice, &bob, &100);
    assert!(!h.token.is_holder(&alice));
    assert!(h.token.is_holder(&bob));
    assert_eq!(h.token.holder_count(), 1);
}

#[test]
fn test_holder_count_consistent_after_buyback() {
    let h = setup();
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.approve_kyc(&bob);

    h.token.mint(&alice, &50);
    h.token.mint(&bob, &30);
    assert_eq!(h.token.holder_count(), 2);

    h.token.buyback(&alice, &50);
    assert_eq!(h.token.holder_count(), 1);
    assert!(!h.token.is_holder(&alice));
    assert!(h.token.is_holder(&bob));
}

// ── Fixed-point dividend arithmetic tests ─────────────────────────────────────

#[test]
fn test_per_share_scaled_prime_total_shares() {
    // Use 7 shares (prime) — classic precision killer for integer division.
    // deposit(1_000_000) / 7: per_share_scaled = floor(10^7 * 10^6 / 7) = 1_428_571_428
    // alice (7 shares): floor(7 * 1_428_571_428 / 10^7) = 999_999. dust = 1.
    let h = setup_with_shares(7);
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &7);

    h.token.deposit_dividend(&1_000_000, &2);

    assert_eq!(h.token.pending_dividend(&alice), 999_999);
    assert_eq!(h.token.dust_reserve(), 1);
    assert_eq!(
        h.token.pending_dividend(&alice) + h.token.dust_reserve(),
        1_000_000
    );
}

#[test]
fn test_dust_reserve_accumulates_across_distributions() {
    // 3 shares, deposit(10): per_share_scaled = floor(10^8/3) = 33_333_333
    // alice(3): floor(3 * 33_333_333 / 10^7) = 9. dust = 1 per distribution.
    let h = setup_with_shares(3);
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &3);

    h.token.deposit_dividend(&10, &2);
    assert_eq!(h.token.dust_reserve(), 1);

    h.token.deposit_dividend(&10, &2);
    assert_eq!(h.token.dust_reserve(), 2);
}

#[test]
fn test_collect_dust_reserve_admin_only() {
    let h = setup_with_shares(3);
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &3);
    h.token.deposit_dividend(&10, &2); // dust = 1

    assert_eq!(h.token.dust_reserve(), 1);
    let collected = h.token.collect_dust_reserve(&h.admin);
    assert_eq!(collected, 1);
    assert_eq!(h.token.dust_reserve(), 0);
}

// ── Force-migrate holder checkpoint test ─────────────────────────────────────

#[test]
fn test_force_migrate_holder_checkpoint() {
    let h = setup();
    let alice = Address::generate(&h.env);
    h.approve_kyc(&alice);
    h.token.mint(&alice, &500);
    h.token.deposit_dividend(&1_000, &2);

    // Before any claim or access, force_migrate_holder_checkpoint eagerly settles.
    h.token.force_migrate_holder_checkpoint(&h.admin, &alice);

    // Pending should still be correct post-migration.
    assert_eq!(h.token.pending_dividend(&alice), 500);
}

// ── Regression tests for validation fixes ────────────────────────────────────

// Fix 1: validate_property_type — empty string must be rejected
#[test]
#[should_panic]
fn test_empty_property_type_rejected_in_constructor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = Address::generate(&env);
    let ce_id = Address::generate(&env);
    let mut bad_meta = meta(&env);
    // An empty property_type is indistinguishable from an unset field; must
    // be caught before any state is written.
    bad_meta.property_type = String::from_str(&env, "");
    env.register(PropertyToken, (admin, kyc_id, ce_id, bad_meta));
}

// Fix 1 (update path): empty property_type also rejected in update_meta
#[test]
fn test_empty_property_type_rejected_in_update_meta() {
    let h = setup();
    let mut bad_meta = h.token.get_meta();
    bad_meta.property_type = String::from_str(&h.env, "");
    assert!(
        h.token.try_update_meta(&bad_meta).is_err(),
        "empty property_type must be rejected in update_meta"
    );
}

// Fix 2: deposit_dividend — zero amount must be rejected before any state write
#[test]
fn test_deposit_dividend_rejects_zero_amount() {
    let h = setup();
    // Amount of zero is meaningless; no checkpoint or pool update should occur.
    assert!(
        h.token.try_deposit_dividend(&0, &0).is_err(),
        "zero dividend amount must be rejected"
    );
    // Distribution count must not have advanced.
    assert_eq!(h.token.dividend_deposit_count(), 0);
}

// Fix 3: deposit_dividend — unrecognized distribution type must be rejected
#[test]
fn test_deposit_dividend_rejects_unknown_distribution_type() {
    let h = setup();
    // Type 3 is out-of-range (valid values: 0=Rent, 1=Capital, 2=Other).
    assert!(
        h.token.try_deposit_dividend(&1_000, &3).is_err(),
        "unknown distribution type must be rejected before checkpoint is written"
    );
    // No checkpoint must have been recorded.
    assert_eq!(h.token.dividend_deposit_count(), 0);
}

// Fix 4: validate_property_meta — whitespace-only legal_name must be rejected
#[test]
#[should_panic]
fn test_whitespace_only_legal_name_rejected_in_constructor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = Address::generate(&env);
    let ce_id = Address::generate(&env);
    let mut bad_meta = meta(&env);
    // Five spaces: len > 0, so is_valid_legal_entity passes without the whitespace fix.
    // The whitespace guard must catch this before state is written.
    bad_meta.legal_name = String::from_str(&env, "     ");
    env.register(PropertyToken, (admin, kyc_id, ce_id, bad_meta));
}
