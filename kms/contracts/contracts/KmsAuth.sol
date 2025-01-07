// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KmsAuth {
    // Contract owner
    address public owner;

    struct KmsInfo {
        // App ID of the KMS
        address appId;
        // Root Certificate of the KMS in PEM format
        string rootCa;
        // Root key of the KMS
        bytes32 publicKey;
        // The remote attestation report of the cert and key
        string raReport;
    }

    // KMS information
    KmsInfo public kmsInfo;

    // Struct to store App configuration
    struct AppConfig {
        bool isRegistered;
        address controller;
    }

    // Mapping of allowed MRTD and image hashes
    mapping(bytes32 => bool) public allowedEnclaves;
    mapping(bytes32 => bool) public allowedImages;
    // Mapping of app ID to its configuration
    mapping(address => AppConfig) public apps;

    // Events
    event EnclaveRegistered(bytes32 indexed mrEnclave);
    event EnclaveDeregistered(bytes32 indexed mrEnclave);
    event ImageRegistered(bytes32 indexed mrImage);
    event ImageDeregistered(bytes32 indexed mrImage);
    event AppRegistered(address indexed appId);
    event KmsInfoSet(address indexed appId, bytes32 publicKey);

    constructor() {
        owner = msg.sender;
    }

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Set KMS information
    function setKmsInfo(
        address appId,
        bytes32 publicKey,
        string memory rootCa,
        string memory raReport
    ) external onlyOwner {
        kmsInfo.appId = appId;
        kmsInfo.publicKey = publicKey;
        kmsInfo.rootCa = rootCa;
        kmsInfo.raReport = raReport;
        // allow the app id to run
        apps[appId].isRegistered = true;
        apps[appId].controller = address(this);
        emit KmsInfoSet(appId, publicKey);
    }

    // Register a new MRTD
    function registerEnclave(bytes32 mrEnclave) external onlyOwner {
        allowedEnclaves[mrEnclave] = true;
        emit EnclaveRegistered(mrEnclave);
    }

    // Deregister an MRTD
    function deregisterEnclave(bytes32 mrEnclave) external onlyOwner {
        allowedEnclaves[mrEnclave] = false;
        emit EnclaveDeregistered(mrEnclave);
    }

    // Register a new image hash
    function registerImage(bytes32 mrImage) external onlyOwner {
        allowedImages[mrImage] = true;
        emit ImageRegistered(mrImage);
    }

    // Deregister an image hash
    function deregisterImage(bytes32 mrImage) external onlyOwner {
        allowedImages[mrImage] = false;
        emit ImageDeregistered(mrImage);
    }

    // Register a new app
    function registerApp(bytes32 salt, address controller) external {
        bytes32 fullHash = keccak256(abi.encodePacked(msg.sender, salt));
        address appId = address(uint160(uint256(fullHash)));

        require(!apps[appId].isRegistered, "App already registered");

        apps[appId].isRegistered = true;
        apps[appId].controller = controller;
        emit AppRegistered(appId);
    }

    // Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        owner = newOwner;
    }

    // Add this struct definition with the function parameters
    struct AppBootInfo {
        address appId;
        bytes32 composeHash;
        address instanceId;
        bytes32 deviceId;
        bytes32 mrEnclave;
        bytes32 mrImage;
    }

    // Modified function using the struct
    function isAppAllowed(
        AppBootInfo memory params
    ) external view returns (bool allowed, string memory reason) {
        if (!allowedEnclaves[params.mrEnclave]) {
            return (false, "Enclave not allowed");
        }

        if (!allowedImages[params.mrImage]) {
            return (false, "Image hash not allowed");
        }

        AppConfig storage app = apps[params.appId];

        if (!app.isRegistered) {
            return (false, "App not registered");
        }

        return (true, "");
    }

    // Returns the KMS app ID
    function kmsAppId() external view returns (address) {
        return kmsInfo.appId;
    }

    // Get the controller of an app
    function appController(address appId) external view returns (address) {
        return apps[appId].controller;
    }
}
