import { HardhatUserConfig, task } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";

// Contract addresses from environment
const KMS_CONTRACT_ADDRESS = process.env.KMS_CONTRACT_ADDRESS || "0x680f2f2870ede0e8abd57386e09ee38bac4e51bf";
const APP_CONTRACT_ADDRESS = process.env.APP_CONTRACT_ADDRESS || "0x680f2f2870ede0e8abd57386e09ee38bac4e51bf";

// KMS Contract Tasks
task("kms:deploy", "Deploy a new KmsAuth contract")
  .setAction(async (_, { ethers }) => {
    console.log("Starting deployment process...");
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with account:", await deployer.getAddress());

    const KmsAuth = await ethers.getContractFactory("KmsAuth");
    const kmsAuth = await KmsAuth.deploy();
    await kmsAuth.waitForDeployment();

    const address = await kmsAuth.getAddress();
    console.log("KmsAuth deployed to:", address);
  });

task("kms:transfer-ownership")
  .addPositionalParam("newOwner", "New owner address")
  .setAction(async ({ newOwner }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.transferOwnership(newOwner);
    await tx.wait();
    console.log("Ownership transferred successfully");
  });

task("kms:set-info", "Set KMS information")
  .addParam("k256Pubkey", "K256 public key")
  .addParam("caPubkey", "CA public key")
  .addParam("quote", "Quote")
  .addParam("eventlog", "Event log")
  .setAction(async ({ k256Pubkey, caPubkey, quote, eventlog }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.setKmsInfo({ k256Pubkey, caPubkey, quote, eventlog });
    await tx.wait();
    console.log("KMS info set successfully");
  });

task("kms:set-tproxy")
  .addPositionalParam("appId", "TProxy App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.setTProxyAppId(appId);
    await tx.wait();
    console.log("TProxy App ID set successfully");
  });

// App Management Tasks
task("app:deploy")
  .addPositionalParam("salt", "Salt for app deployment")
  .setAction(async ({ salt }, { ethers }) => {
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();

    const appId = ethers.keccak256(
      ethers.solidityPacked(
        ['address', 'bytes32'],
        [deployerAddress, ethers.keccak256(ethers.toUtf8Bytes(salt))]
      )
    );

    const AppAuth = await ethers.getContractFactory("AppAuth");
    const appAuth = await AppAuth.deploy(appId);
    await appAuth.waitForDeployment();

    const address = await appAuth.getAddress();
    console.log("AppAuth deployed to:", address);

    const kmsContract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await kmsContract.registerApp(salt, address);
    await tx.wait();
    console.log("App registered in KMS successfully");
  });

task("app:add-hash")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ hash }, { ethers }) => {
    const contract = await ethers.getContractAt("AppAuth", APP_CONTRACT_ADDRESS);
    const tx = await contract.addComposeHash(hash);
    await tx.wait();
    console.log("Compose hash added successfully");
  });

task("app:remove-hash")
  .addPositionalParam("hash", "Compose hash to remove")
  .setAction(async ({ hash }, { ethers }) => {
    const contract = await ethers.getContractAt("AppAuth", APP_CONTRACT_ADDRESS);
    const tx = await contract.removeComposeHash(hash);
    await tx.wait();
    console.log("Compose hash removed successfully");
  });

// Enclave Management Tasks
task("enclave:register")
  .addPositionalParam("mrEnclave", "Enclave measurement")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.registerEnclave(mrEnclave);
    await tx.wait();
    console.log("Enclave registered successfully");
  });

task("enclave:deregister")
  .addPositionalParam("mrEnclave", "Enclave measurement")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.deregisterEnclave(mrEnclave);
    await tx.wait();
    console.log("Enclave deregistered successfully");
  });

// Image Management Tasks
task("image:register")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.registerImage(mrImage);
    await tx.wait();
    console.log("Image registered successfully");
  });

task("image:deregister")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const tx = await contract.deregisterImage(mrImage);
    await tx.wait();
    console.log("Image deregistered successfully");
  });

// Device Management Tasks
task("device:register")
  .addPositionalParam("deviceId", "Device ID to register")
  .setAction(async ({ deviceId }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await contract.registerKmsDeviceId(hashedId);
    await tx.wait();
    console.log("Device ID registered successfully");
  });

task("device:deregister")
  .addPositionalParam("deviceId", "Device ID to deregister")
  .setAction(async ({ deviceId }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await contract.deregisterKmsDeviceId(hashedId);
    await tx.wait();
    console.log("Device ID deregistered successfully");
  });

// Status Check Tasks
task("check:app", "Check if an app is allowed to boot")
  .addParam("appId", "App ID to check")
  .addParam("mrEnclave", "Enclave measurement")
  .addParam("mrImage", "Image measurement")
  .addParam("composeHash", "Compose hash")
  .setAction(async ({ appId, mrEnclave, mrImage, composeHash }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const [isAllowed, reason] = await contract.isAppAllowed({
      appId,
      mrEnclave,
      mrImage,
      composeHash,
      deviceId: ethers.ZeroHash,
      instanceId: ethers.ZeroAddress
    });
    console.log("Is allowed:", isAllowed);
    console.log("Reason:", reason);
  });

task("check:kms", "Check if KMS is allowed to boot")
  .addParam("mrEnclave", "Enclave measurement")
  .addParam("composeHash", "Compose hash")
  .addParam("deviceId", "Device ID")
  .setAction(async ({ mrEnclave, composeHash, deviceId }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const [isAllowed, reason] = await contract.isKmsAllowed({
      mrEnclave,
      composeHash,
      deviceId: hashedId,
      mrImage: ethers.ZeroHash,
      appId: ethers.ZeroAddress,
      instanceId: ethers.ZeroAddress
    });
    console.log("Is allowed:", isAllowed);
    console.log("Reason:", reason);
  });

// Additional Status Check Tasks
task("check:app-id")
  .addPositionalParam("appId", "App ID to check")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const isRegistered = (await contract.apps(appId)).isRegistered;
    console.log("App ID is registered:", isRegistered);
  });

task("check:enclave")
  .addPositionalParam("mrEnclave", "Enclave measurement to check")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const isRegistered = await contract.allowedEnclaves(mrEnclave);
    console.log("Enclave measurement is registered:", isRegistered);
  });

task("check:image")
  .addPositionalParam("mrImage", "Image measurement to check")
  .setAction(async ({ mrImage }, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const isRegistered = await contract.allowedImages(mrImage);
    console.log("Image measurement is registered:", isRegistered);
  });

task("check:app-hash")
  .addPositionalParam("hash", "Compose hash to check")
  .setAction(async ({ hash }, { ethers }) => {
    const contract = await ethers.getContractAt("AppAuth", APP_CONTRACT_ADDRESS);
    const isAllowed = await contract.allowedComposeHashes(hash);
    console.log("Compose hash is allowed:", isAllowed);
  });

// Info Query Tasks
task("info:owner", "Get current contract owner")
  .setAction(async (_, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const owner = await contract.owner();
    console.log("Contract owner:", owner);
  });

task("info:kms", "Get current KMS information")
  .setAction(async (_, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const kmsInfo = await contract.kmsInfo();
    console.log("KMS Info:", {
      k256Pubkey: kmsInfo.k256Pubkey,
      caPubkey: kmsInfo.caPubkey,
      quote: kmsInfo.quote
    });
  });

task("info:tproxy", "Get current TProxy App ID")
  .setAction(async (_, { ethers }) => {
    const contract = await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
    const appId = await contract.tproxyAppId();
    console.log("TProxy App ID:", appId);
  });

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x0000000000000000000000000000000000000000000000000000000000000000";

const config: HardhatUserConfig = {
  solidity: "0.8.19",
  defaultNetwork: "phala",
  networks: {
    hardhat: {
      chainId: 1337
    },
    sepolia: {
      url: `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: [PRIVATE_KEY],
    },
    phala: {
      url: 'https://rpc.phala.network',
      accounts: [PRIVATE_KEY],
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};

export default config;
