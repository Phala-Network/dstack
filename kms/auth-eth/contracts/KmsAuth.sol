// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IAppAuth.sol";

contract KmsAuth is IAppAuth {
    // Contract owner
    address public owner;

    // Struct for KMS information
    struct KmsInfo {
        bytes k256Pubkey;
        bytes caPubkey;
        bytes quote;
    }

    // KMS information
    KmsInfo public kmsInfo;

    // Struct to store App configuration
    struct AppConfig {
        bool isRegistered;
        address controller;
    }

    // Mapping of registered apps
    mapping(address => AppConfig) public apps;

    // Mapping of allowed enclave measurements
    mapping(bytes32 => bool) public allowedEnclaves;

    // Mapping of allowed image measurements
    mapping(bytes32 => bool) public allowedImages;

    // Mapping of allowed KMS compose hashes
    mapping(bytes32 => bool) public allowedKmsComposeHashes;

    // Mapping of allowed KMS device IDs
    mapping(bytes32 => bool) public allowedKmsDeviceIds;

    // Events
    event AppRegistered(address appId);
    event KmsInfoSet(bytes k256Pubkey);
    event EnclaveRegistered(bytes32 mrEnclave);
    event EnclaveDeregistered(bytes32 mrEnclave);
    event ImageRegistered(bytes32 mrImage);
    event ImageDeregistered(bytes32 mrImage);
    event KmsComposeHashRegistered(bytes32 composeHash);
    event KmsComposeHashDeregistered(bytes32 composeHash);
    event KmsDeviceIdRegistered(bytes32 deviceId);
    event KmsDeviceIdDeregistered(bytes32 deviceId);

    // Constructor
    constructor() {
        owner = msg.sender;
    }

    // Modifier to restrict access to owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Function to set KMS information
    function setKmsInfo(KmsInfo memory info) external onlyOwner {
        kmsInfo = info;
        emit KmsInfoSet(info.k256Pubkey);
    }

    // Function to calculate the app ID
    function calculateAppId(
        address sender,
        bytes32 salt
    ) public pure returns (address appId) {
        bytes32 fullHash = keccak256(abi.encodePacked(sender, salt));
        return address(uint160(uint256(fullHash)));
    }

    // Function to register an app
    function registerApp(bytes32 salt, address controller) external {
        address appId = calculateAppId(msg.sender, salt);
        require(!apps[appId].isRegistered, "App already registered");
        apps[appId].isRegistered = true;
        apps[appId].controller = controller;
        emit AppRegistered(appId);
    }

    // Function to register an enclave measurement
    function registerEnclave(bytes32 mrEnclave) external onlyOwner {
        allowedEnclaves[mrEnclave] = true;
        emit EnclaveRegistered(mrEnclave);
    }

    // Function to deregister an enclave measurement
    function deregisterEnclave(bytes32 mrEnclave) external onlyOwner {
        allowedEnclaves[mrEnclave] = false;
        emit EnclaveDeregistered(mrEnclave);
    }

    // Function to register an image measurement
    function registerImage(bytes32 mrImage) external onlyOwner {
        allowedImages[mrImage] = true;
        emit ImageRegistered(mrImage);
    }

    // Function to deregister an image measurement
    function deregisterImage(bytes32 mrImage) external onlyOwner {
        allowedImages[mrImage] = false;
        emit ImageDeregistered(mrImage);
    }

    // Function to register a KMS compose hash
    function registerKmsComposeHash(bytes32 composeHash) external onlyOwner {
        allowedKmsComposeHashes[composeHash] = true;
        emit KmsComposeHashRegistered(composeHash);
    }

    // Function to deregister a KMS compose hash
    function deregisterKmsComposeHash(bytes32 composeHash) external onlyOwner {
        allowedKmsComposeHashes[composeHash] = false;
        emit KmsComposeHashDeregistered(composeHash);
    }

    // Function to register a KMS device ID
    function registerKmsDeviceId(bytes32 deviceId) external onlyOwner {
        allowedKmsDeviceIds[deviceId] = true;
        emit KmsDeviceIdRegistered(deviceId);
    }

    // Function to deregister a KMS device ID
    function deregisterKmsDeviceId(bytes32 deviceId) external onlyOwner {
        allowedKmsDeviceIds[deviceId] = false;
        emit KmsDeviceIdDeregistered(deviceId);
    }

    // Function to get app controller
    function appController(
        address appId
    ) external view returns (address controller) {
        return apps[appId].controller;
    }

    // Function to check if KMS is allowed to boot
    function isKmsAllowed(
        AppBootInfo calldata bootInfo
    ) external view returns (bool isAllowed, string memory reason) {
        // Check if the enclave is allowed
        if (!allowedEnclaves[bootInfo.mrEnclave]) {
            return (false, "Enclave not allowed");
        }

        // Check if the KMS compose hash is allowed
        if (!allowedKmsComposeHashes[bootInfo.composeHash]) {
            return (false, "KMS compose hash not allowed");
        }

        // Check if the KMS device ID is allowed
        if (!allowedKmsDeviceIds[bootInfo.deviceId]) {
            return (false, "KMS is not allowed to boot on this device");
        }

        return (true, "");
    }

    // Function to check if an app is allowed to boot
    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if app is registered
        if (!apps[bootInfo.appId].isRegistered) {
            return (false, "App not registered");
        }

        // Check enclave and image measurements
        if (
            !allowedEnclaves[bootInfo.mrEnclave] &&
            !allowedImages[bootInfo.mrImage]
        ) {
            return (false, "Neither enclave nor image is allowed");
        }

        // Ask the app controller if the app is allowed to boot
        address controller = apps[bootInfo.appId].controller;
        if (controller == address(0)) {
            return (false, "App controller not set");
        }
        return IAppAuth(controller).isAppAllowed(bootInfo);
    }

    // Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        owner = newOwner;
    }
}
