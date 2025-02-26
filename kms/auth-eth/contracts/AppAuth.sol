// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./IAppAuth.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract AppAuth is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    IAppAuth
{
    // App ID this contract is managing
    address public appId;

    // Mapping of allowed compose hashes for this app
    mapping(bytes32 => bool) public allowedComposeHashes;

    // State variable to track if upgrades are disabled
    bool private _upgradesDisabled;

    // Events
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event UpgradesDisabled();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract
    function initialize(
        address initialOwner,
        address _appId,
        bool _disableUpgrades
    ) public initializer {
        require(initialOwner != address(0), "Invalid owner address");
        require(_appId != address(0), "Invalid app ID");
        appId = _appId;
        _upgradesDisabled = _disableUpgrades;
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(address) internal view override onlyOwner {
        require(!_upgradesDisabled, "Upgrades are permanently disabled");
    }

    // Add a compose hash to allowed list
    function addComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = true;
        emit ComposeHashAdded(composeHash);
    }

    // Remove a compose hash from allowed list
    function removeComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = false;
        emit ComposeHashRemoved(composeHash);
    }

    // Check if an app is allowed to boot
    function isAppAllowed(
        IAppAuth.AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if this controller is responsible for the app
        if (bootInfo.appId != appId) {
            return (false, "Wrong app controller");
        }

        // Check if compose hash is allowed
        if (!allowedComposeHashes[bootInfo.composeHash]) {
            return (false, "Compose hash not allowed");
        }

        return (true, "");
    }

    // Function to permanently disable upgrades
    function disableUpgrades() external onlyOwner {
        _upgradesDisabled = true;
        emit UpgradesDisabled();
    }

    // Add storage gap for upgradeable contracts
    uint256[50] private __gap;
}
