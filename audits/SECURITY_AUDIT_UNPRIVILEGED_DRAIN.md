# SparkLend Advanced - Security Audit Report
## Unprivileged Actor TVL Drain Analysis

**Audit Date:** 2026-02-12
**Scope:** All 18 source contracts in `sparklend-advanced/src/`
**Methodology:** Manual code review + automated PoC exploit testing (Foundry)
**PoC Tests:** `test/SecurityAudit.t.sol` (25 tests, all passing)

---

## Executive Summary

This audit analyzed the SparkLend Advanced peripheral contracts (oracles, interest rate strategies, rate sources) from an **unprivileged actor's perspective**, seeking chained attack sequences that could reach TVL drain.

**Key architectural observation:** These contracts do not hold assets directly. TVL resides in the SparkLend Pool's aToken contracts. However, these peripherals are **critical pricing and rate infrastructure** -- manipulating them can induce the Pool to release funds to attackers via over-borrowing, unfair liquidations, or interest rate exploitation.

### Findings Summary

| ID | Severity | Title | Exploitable by Unprivileged Actor |
|----|----------|-------|-----------------------------------|
| H-1 | **HIGH** | ERC-4626 Donation Attack on SPETHExchangeRateOracle | Yes (conditional on vault impl) |
| M-1 | **MEDIUM** | Renzo TVL Manipulation on EZETHExchangeRateOracle | Yes (conditional on TVL source) |
| M-2 | **MEDIUM** | Mutable Decimals Rate Amplification / DoS | Yes (requires proxy-upgradable rate source) |
| M-3 | **MEDIUM** | PotRateSource / SSRRateSource Underflow DoS | External dependency trigger |
| L-1 | **LOW** | CappedOracle Missing Lower Bound | Yes (requires Chainlink failure) |
| L-2 | **LOW** | No Staleness Checks on Price Sources | External dependency trigger |
| L-3 | **LOW** | MorphoUpgradableOracle Zero Metadata | Informational for consumers |
| I-1 | **INFO** | MorphoUpgradableOracle Centralization Risk | Privileged actor only |
| I-2 | **INFO** | Exchange Rate int256 Overflow DoS | Theoretical edge case |
| I-3 | **INFO** | No Circuit Breaker for Extreme Rate Changes | Design limitation |

---

## TVL Location Map

```
SparkLend Pool (0xC13e21B648A5Ee794902342038FF3aDAB66BE987)
    |
    +-- aToken contracts (hold underlying ERC20 tokens)
    |       |-- aDAI   -> holds DAI
    |       |-- aWETH  -> holds WETH
    |       |-- aUSDC  -> holds USDC
    |       |-- aUSDT  -> holds USDT
    |       +-- a*     -> holds respective underlying
    |
    +-- Interest Rate Strategies (THIS REPO)
    |       |-- VariableBorrowInterestRateStrategy
    |       |-- RateTargetBaseInterestRateStrategy
    |       +-- RateTargetKinkInterestRateStrategy
    |
    +-- Oracles (THIS REPO, via AaveOracle)
            |-- Exchange Rate Oracles (wstETH, rETH, weETH, rsETH, ezETH, spETH)
            |-- Ratio Oracles (cbBTC, rETH, weETH)
            |-- CappedOracle, FixedPriceOracle, MorphoUpgradableOracle
            +-- Rate Sources (PotRateSource, SSRRateSource, CappedFallbackRateSource)
```

**Attack surface:** Oracles determine collateral valuations. Interest rate strategies determine borrow costs. Both feed into Pool operations (supply, borrow, withdraw, liquidate) that move real assets.

---

## Detailed Findings

---

### [H-1] ERC-4626 Donation Attack on SPETHExchangeRateOracle

**Severity:** HIGH (conditional)
**Contract:** `src/SPETHExchangeRateOracle.sol:37`
**PoC:** `test_PoC1_donationInflatesVulnerableVaultExchangeRate`, `test_PoC1_fullAttackChainSimulation`

#### Vulnerability

`SPETHExchangeRateOracle.latestAnswer()` computes the spETH price using:

```solidity
int256 exchangeRate = int256(IERC4626Like(speth).convertToAssets(1e18));
return (exchangeRate * ethUsd) / 1e18;
```

If the spETH ERC-4626 vault implements `totalAssets()` using `IERC20(asset).balanceOf(address(this))` (raw balance accounting), an unprivileged attacker can **donate** the underlying asset (WETH) directly to the vault contract, inflating `convertToAssets()` and thus the oracle price.

#### Attack Chain (Flash Loan + Donation + Over-Borrow)

```
1. Flash loan 999 WETH from SparkLend Pool (fee = 0 for Spark)
2. Transfer 999 WETH directly to spETH vault (donation, not deposit)
3. spETH vault: totalAssets() = balanceOf(this) = 1000 WETH (was 1 WETH)
4. SPETHExchangeRateOracle: convertToAssets(1e18) = 1000e18 (was 1e18)
5. Oracle reports spETH price = $3,000,000 (was $3,000) -- 1000x inflation
6. Attacker supplies 1 spETH as collateral -- valued at $3M
7. Attacker borrows $2.4M worth of DAI/USDC (80% LTV)
8. Repay flash loan (999 WETH)
9. Attacker profit: ~$2.4M in stables, leaves worthless collateral
```

#### PoC Results

```
Fair collateral value (USD, 8 dec): 300000000000      ($3,000)
Inflated collateral value (USD, 8 dec): 300000000000000  ($3,000,000)
Inflation multiplier: 1000
```

#### Condition

This attack requires that the spETH vault (0xfE6eb3b609a7C8352A241f7F3A21CEA4e9209B8f) uses `balanceOf` in its `totalAssets()` function rather than internal accounting. The ERC-4626 standard does not mandate either approach. Many vaults (e.g., OpenZeppelin's implementation) DO use `balanceOf`.

#### Recommendation

1. Verify the spETH vault implementation of `totalAssets()`
2. If vulnerable, wrap `SPETHExchangeRateOracle` in a `CappedOracle` with a reasonable max price
3. Consider implementing a TWAP or multi-block oracle for ERC-4626 vault rates
4. Add a maximum exchange rate change check (circuit breaker)

---

### [M-1] Renzo TVL Manipulation on EZETHExchangeRateOracle

**Severity:** MEDIUM (conditional)
**Contract:** `src/EZETHExchangeRateOracle.sol:43`
**PoC:** `test_PoC6_tvlInflationInflatesPrice`, `test_PoC6_lowSupplyAmplification`

#### Vulnerability

```solidity
( ,, uint256 tvl ) = oracle.calculateTVLs();
int256 exchangeRate = int256(tvl * 1e18 / ezETH.totalSupply());
```

The exchange rate is computed as `TVL / totalSupply`. If Renzo's `calculateTVLs()` includes flash-depositable or donatable assets in its TVL calculation, an attacker can inflate the TVL in a single transaction.

#### PoC Results

```
Normal price: $3,000 (1:1 TVL ratio)
After 2x TVL inflation: $6,000
After 10x TVL inflation: $30,000
Low supply (1 token) + 100 ETH deposit: $300,000 (100x)
```

Additionally, `totalSupply == 0` causes a division-by-zero revert (DoS).

#### Recommendation

1. Verify Renzo's `calculateTVLs()` is not manipulable within a single transaction
2. Add minimum `totalSupply` check to prevent division by very small numbers
3. Consider a TWAP-based exchange rate

---

### [M-2] Mutable Decimals Rate Amplification / DoS

**Severity:** MEDIUM
**Contracts:** `src/RateTargetBaseInterestRateStrategy.sol:52`, `src/RateTargetKinkInterestRateStrategy.sol:55`
**PoC:** `test_PoC3_decimalsDecreaseCausesRateAmplification`, `test_PoC3_decimalsIncreaseAbove27CausesRevert`

#### Vulnerability

Both rate-target strategies compute the rate as:

```solidity
uint256 apr = RATE_SOURCE.getAPR() * 10 ** (27 - RATE_SOURCE.decimals());
```

`decimals()` is validated only at construction time (`require(RATE_SOURCE.decimals() <= 27)`). If the rate source is a proxy or wrapper whose `decimals()` can change post-deployment:

- **Decimals increase > 27:** `27 - decimals` underflows in uint, reverting all rate calculations (DoS)
- **Decimals decrease:** The exponent `10 ** (27 - newDecimals)` becomes much larger, amplifying the rate astronomically

#### PoC Results

```
Normal rate (18 dec source): 0.055e27 (~5.5%)
After decimals drop 18->9:  50000000005000000000000000000000000 (~5e34)
```

A 5e34 ray rate means borrowers are charged absurd interest, likely bricking the protocol.

#### Recommendation

Cache the `decimals()` value at construction time as an immutable, or re-validate it on every call.

---

### [M-3] PotRateSource / SSRRateSource Underflow DoS

**Severity:** MEDIUM
**Contracts:** `src/PotRateSource.sol:18-19`, `src/SSRRateSource.sol:18-19`
**PoC:** `test_PoC2_potRateSourceUnderflowDoS`, `test_PoC2_ssrRateSourceUnderflowDoS`

#### Vulnerability

```solidity
function getAPR() external override view returns (uint256) {
    return (pot.dsr() - 1e27) * 365 days;
}
```

If MakerDAO's DSR (`pot.dsr()`) or Sky's SSR (`susds.ssr()`) drops below `1e27` (representing a 0% per-second rate), the subtraction underflows and reverts. This causes all dependent interest rate strategies to brick, halting pool operations.

#### Impact Chain

```
DSR < 1e27 -> PotRateSource.getAPR() reverts
  -> RateTargetBase/KinkStrategy.calculateInterestRates() reverts
    -> Pool.supply/borrow/repay/withdraw reverts
      -> ALL protocol operations frozen
```

#### Mitigation Status

`CappedFallbackRateSource` can mitigate this by catching the revert and returning a default rate. The integration test shows ETH uses `CappedFallbackRateSource`, but DAI does NOT (uses `SSRRateSource` directly). Any reserve using an unwrapped PotRateSource/SSRRateSource is vulnerable.

#### Recommendation

Always wrap PotRateSource/SSRRateSource in CappedFallbackRateSource, or add `if (dsr < 1e27) return 0;` guard.

---

### [L-1] CappedOracle Missing Lower Bound

**Severity:** LOW
**Contract:** `src/CappedOracle.sol:20-24`
**PoC:** `test_PoC4_zeroPricePassthrough`, `test_PoC4_negativePricePassthrough`

#### Vulnerability

```solidity
function latestAnswer() external view returns (int256) {
    int256 price = source.latestAnswer();
    return price < maxPrice ? price : maxPrice;
}
```

Only caps upward. If the source returns 0 (Chainlink failure) or negative values, they pass through uncapped. Zero price means all collateral valued at $0, triggering mass liquidations.

#### Recommendation

Add a `minPrice` parameter or at minimum `require(price > 0)`.

---

### [L-2] No Staleness Checks on Price Sources

**Severity:** LOW
**Contracts:** All exchange rate oracles

#### Vulnerability

All oracles call `ethSource.latestAnswer()` without checking when the price was last updated. If the Chainlink ETH/USD feed stops updating (e.g., sequencer downtime, feed deprecation), the protocol continues using stale prices, which could diverge significantly from market reality.

The `IPriceSource` interface only exposes `latestAnswer()` and `decimals()`, with no access to `updatedAt` timestamps.

#### Recommendation

Use `latestRoundData()` instead and validate `updatedAt` against a maximum acceptable delay.

---

### [L-3] MorphoUpgradableOracle Zero Metadata

**Severity:** LOW
**Contract:** `src/MorphoUpgradableOracle.sol:34-42`
**PoC:** `test_PoC5_latestRoundDataReturnsZeroMetadata`

#### Vulnerability

```solidity
function latestRoundData() external view returns (...) {
    (, answer,,,) = source.latestRoundData();
    // roundId=0, startedAt=0, updatedAt=0, answeredInRound=0
}
```

Only `answer` is forwarded; all metadata is zeroed. Consumers performing freshness checks (`require(updatedAt > 0)`) will reject this oracle as stale.

#### Recommendation

Forward all fields from the underlying source's `latestRoundData()`.

---

### [I-1] MorphoUpgradableOracle Centralization Risk

**Contract:** `src/MorphoUpgradableOracle.sol:25-28`
**PoC:** `test_PoC5_ownerCanSetArbitrarySource`

The owner can change the oracle source at any time with no timelock, no validation, and no lower/upper bound checks on the new source's answer. This is a trusted operator assumption, not an unprivileged attack vector, but worth noting.

---

### [I-2] Exchange Rate int256 Overflow DoS

**Contracts:** All exchange rate oracles

All oracles cast `uint256` exchange rates to `int256`:
```solidity
int256 exchangeRate = int256(reth.getExchangeRate());
```

If any external protocol's exchange rate exceeds `type(int256).max` (~5.78e76), the cast reverts in Solidity 0.8+, permanently bricking the oracle. This is theoretical since rates are near 1e18, but represents an unguarded edge case.

---

### [I-3] No Circuit Breaker for Extreme Rate Changes

**Contracts:** All exchange rate and ratio oracles

No oracle implements a maximum single-block rate change check. If an underlying protocol's exchange rate spikes (due to exploit, bug, or oracle manipulation), the SparkLend oracle immediately reflects the change. A circuit breaker or TWAP would dampen such spikes.

---

## Attack Chain Matrix

| Chain | Steps | Severity | Unprivileged | Condition |
|-------|-------|----------|-------------|-----------|
| Flash Loan + spETH Donation + Over-Borrow | 1. Flash loan WETH 2. Donate to vault 3. Supply inflated spETH 4. Over-borrow 5. Repay flash loan | **HIGH** | Yes | spETH uses balanceOf in totalAssets |
| Flash Loan + Renzo TVL + Over-Borrow | 1. Flash loan ETH 2. Inflate Renzo TVL 3. Supply ezETH 4. Over-borrow | **MEDIUM** | Yes | Renzo TVL is manipulable |
| DSR Crash + Protocol Freeze | 1. DSR drops < 1e27 2. PotRateSource reverts 3. All DAI ops freeze | **MEDIUM** | External trigger | DAI IRM uses unwrapped PotRateSource |
| Decimals Shift + Rate Amplification | 1. Rate source proxy upgrade 2. Decimals changes 3. Rates amplify to ~5e34 | **MEDIUM** | Requires upstream change | Proxy-upgradable rate source |
| Chainlink Failure + Zero Collateral | 1. Chainlink returns 0 2. CappedOracle passes 0 3. Mass liquidations | **LOW** | External trigger | Chainlink feed failure |

---

## Contracts Reviewed

| Contract | Lines | Risk Level | Notes |
|----------|-------|------------|-------|
| VariableBorrowInterestRateStrategy.sol | 216 | Low | Clean implementation of 2-slope model |
| RateTargetBaseInterestRateStrategy.sol | 60 | Medium | Mutable decimals risk (M-2) |
| RateTargetKinkInterestRateStrategy.sol | 63 | Medium | Mutable decimals risk (M-2) |
| CappedFallbackRateSource.sol | 52 | Low | OOG protection well-implemented |
| CappedOracle.sol | 30 | Low | Missing lower bound (L-1) |
| MorphoUpgradableOracle.sol | 44 | Low | Zero metadata (L-3), centralization (I-1) |
| FixedPriceOracle.sol | 22 | Minimal | Immutable, no attack surface |
| SPETHExchangeRateOracle.sol | 46 | **High** | ERC-4626 donation attack (H-1) |
| EZETHExchangeRateOracle.sol | 56 | Medium | TVL manipulation (M-1) |
| WSTETHExchangeRateOracle.sol | 46 | Low | Internal accounting (safe) |
| RETHExchangeRateOracle.sol | 46 | Low | Internal accounting (safe) |
| WEETHExchangeRateOracle.sol | 46 | Low | Internal accounting (safe) |
| RSETHExchangeRateOracle.sol | 46 | Low | External oracle (safe) |
| CBBTCRatioOracle.sol | 54 | Low | Division-by-zero guarded |
| RETHRatioOracle.sol | 53 | Low | Division-by-zero guarded |
| WEETHRatioOracle.sol | 53 | Low | Division-by-zero guarded |
| PotRateSource.sol | 26 | Medium | Underflow DoS (M-3) |
| SSRRateSource.sol | 26 | Medium | Underflow DoS (M-3) |

---

## PoC Test Results

```
Ran 10 test suites: 25 tests passed, 0 failed, 0 skipped

Suite: PoC_ERC4626_DonationAttack       - 3/3 passed
Suite: PoC_RateSource_UnderflowDoS      - 4/4 passed
Suite: PoC_MutableDecimals              - 3/3 passed
Suite: PoC_CappedOracle_NoLowerBound    - 3/3 passed
Suite: PoC_MorphoOracle_ZeroMetadata    - 2/2 passed
Suite: PoC_EZETH_TVLManipulation        - 3/3 passed
Suite: PoC_InterestRateEdgeCases        - 2/2 passed
Suite: PoC_CappedFallback_GasEdge       - 1/1 passed
Suite: PoC_Int256Overflow               - 1/1 passed
Suite: PoC_RatioOracle_EdgeCases        - 3/3 passed
```
