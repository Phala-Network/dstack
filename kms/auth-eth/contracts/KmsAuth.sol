// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IAppAuth.sol";

contract KmsAuth is IAppAuth {
    // Contract owner
    address public owner;

    // Struct for KMS information
    struct KmsInfo {
        address appId;
        bytes32 publicKey;
        string rootCa;
        string raReport;
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

    // Events
    event AppRegistered(address appId);
    event KmsInfoSet(address appId, bytes32 publicKey);
    event EnclaveRegistered(bytes32 mrEnclave);
    event EnclaveDeregistered(bytes32 mrEnclave);
    event ImageRegistered(bytes32 mrImage);
    event ImageDeregistered(bytes32 mrImage);

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

    // Function to register an app
    function registerApp(bytes32 salt, address controller) external {
        bytes32 fullHash = keccak256(abi.encodePacked(msg.sender, salt));
        address appId = address(uint160(uint256(fullHash)));

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

    // Function to get app controller
    function appController(address appId) external view returns (address controller) {
        return apps[appId].controller;
    }

    // Function to get KMS app ID
    function kmsAppId() external view returns (address) {
        return kmsInfo.appId;
    }

    // Function to check if an app is allowed to boot
    function isAppAllowed(AppBootInfo calldata bootInfo) 
        external 
        view 
        override 
        returns (bool isAllowed, string memory reason) 
    {
        // Check if app is registered
        if (!apps[bootInfo.appId].isRegistered) {
            return (false, "App not registered");
        }

        // Check enclave measurement
        if (!allowedEnclaves[bootInfo.mrEnclave]) {
            return (false, "Enclave not allowed");
        }

        // Check image measurement
        if (!allowedImages[bootInfo.mrImage]) {
            return (false, "Image hash not allowed");
        }

        return (true, "");
    }

    // Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        owner = newOwner;
    }
}
