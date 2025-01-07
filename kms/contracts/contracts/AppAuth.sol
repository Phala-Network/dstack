// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AppAuth {
    // Contract owner
    address public owner;
    // The app ID this contract controls
    address public appId;

    // Struct to store boot information for an app
    struct AppBootInfo {
        address appId;
        bytes32 composeHash;
        address instanceId;
        bytes32 deviceId;
        bytes32 mrEnclave;
        bytes32 mrImage;
    }

    // Mapping of allowed compose hashes
    mapping(bytes32 => bool) public allowedComposeHashes;

    // Events
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);

    constructor(address _appId) {
        owner = msg.sender;
        appId = _appId;
    }

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    /**
     * @dev Add an allowed compose hash
     * @param composeHash The compose hash to allow
     */
    function addComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = true;
        emit ComposeHashAdded(composeHash);
    }

    /**
     * @dev Remove an allowed compose hash
     * @param composeHash The compose hash to remove
     */
    function removeComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = false;
        emit ComposeHashRemoved(composeHash);
    }

    /**
     * @dev Check if the app is allowed to run based on its boot information
     * @param bootInfo The boot information of the app
     * @return bool True if the app is allowed to run, false otherwise
     */
    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view returns (bool, string memory) {
        // Check if this is the correct app ID
        if (bootInfo.appId != appId) {
            return (false, "Invalid app ID");
        }

        // Check if the compose hash is allowed
        if (!allowedComposeHashes[bootInfo.composeHash]) {
            return (false, "Compose hash not allowed");
        }

        return (true, "");
    }
}
