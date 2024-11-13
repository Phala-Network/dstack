// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AppRegistry {
    struct App {
        string name;
        bool isBanned;
        bool exists;
        address owner;
    }

    // Mapping from app ID to App struct
    mapping(bytes32 => App) public apps;

    // Admin address that can ban apps
    address public admin;

    // Events
    event AppNameUpdated(bytes32 indexed appId, string newName);
    event AppBanned(bytes32 indexed appId);
    event AppUnbanned(bytes32 indexed appId);
    event OwnerUpdated(bytes32 indexed appId, address newOwner);

    constructor() {
        admin = msg.sender;
    }

    // Modifier to check if app is not banned
    modifier notBanned(bytes32 appId) {
        require(!apps[appId].isBanned, "App is banned");
        _;
    }

    // Modifier for admin-only functions
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Add new modifier for owner checks
    modifier onlyOwner(bytes32 appId) {
        require(apps[appId].exists, "App does not exist");
        require(
            msg.sender == apps[appId].owner,
            "Only owner can perform this action"
        );
        _;
    }

    // Modifier for admin or owner
    modifier onlyAdminOrOwner(bytes32 appId) {
        require(
            msg.sender == admin || msg.sender == apps[appId].owner,
            "Only admin or owner can perform this action"
        );
        _;
    }

    // Function to verify TDX quote
    // Note: This is a placeholder - implement actual TDX verification logic
    function verifyTDXQuote(
        bytes memory quote,
        bytes32 appId,
        address owner
    ) internal pure returns (bool) {
        // TODO: Implement TDX quote verification logic here
        return true;
    }

    // Function to register a new app
    function register(
        bytes32 appId,
        string memory name,
        bytes memory tdxQuote
    ) external {
        require(!apps[appId].exists, "App already exists");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(
            verifyTDXQuote(tdxQuote, appId, msg.sender),
            "Invalid TDX quote"
        );

        apps[appId] = App({
            name: name,
            isBanned: false,
            exists: true,
            owner: msg.sender
        });

        emit AppNameUpdated(appId, name);
        emit OwnerUpdated(appId, msg.sender);
    }

    // Update updateAppName function
    function updateAppName(
        bytes32 appId,
        string memory newName
    ) external notBanned(appId) onlyOwner(appId) {
        require(bytes(newName).length > 0, "Name cannot be empty");

        apps[appId].name = newName;
        emit AppNameUpdated(appId, newName);
    }

    // Function to ban an app
    function banApp(bytes32 appId) external onlyAdminOrOwner(appId) {
        require(apps[appId].exists, "App does not exist");
        require(!apps[appId].isBanned, "App is already banned");

        apps[appId].isBanned = true;
        emit AppBanned(appId);
    }

    // Function to unban an app
    function unbanApp(bytes32 appId) external onlyAdmin {
        require(apps[appId].exists, "App does not exist");
        require(apps[appId].isBanned, "App is not banned");

        apps[appId].isBanned = false;
        emit AppUnbanned(appId);
    }

    // Update updateOwner function
    function updateOwner(
        bytes32 appId,
        address newOwner
    ) external notBanned(appId) onlyOwner(appId) {
        require(newOwner != address(0), "Invalid owner address");

        apps[appId].owner = newOwner;
        emit OwnerUpdated(appId, newOwner);
    }

    // Update getApp function to include ecdsaPubKey
    function getApp(
        bytes32 appId
    ) external view returns (string memory name, bool isBanned, address owner) {
        require(apps[appId].exists, "App does not exist");
        return (apps[appId].name, apps[appId].isBanned, apps[appId].owner);
    }
    
    // Check if app is banned
    function isAppBanned(bytes32 appId) external view returns (bool) {
        return apps[appId].isBanned;
    }
}
