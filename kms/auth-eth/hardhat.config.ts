import { HardhatUserConfig, task } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";
import fs from 'fs';

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x0000000000000000000000000000000000000000000000000000000000000000";

const config: HardhatUserConfig = {
  solidity: "0.8.19",
  defaultNetwork: "phala",
  networks: {
    hardhat: {
      chainId: 1337
    },
    phala: {
      url: 'https://rpc.phala.network',
      accounts: [PRIVATE_KEY],
    },
    sepolia: {
      url: `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
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

// Contract addresses from environment
const KMS_CONTRACT_ADDRESS = process.env.KMS_CONTRACT_ADDRESS || "0x680f2f2870ede0e8abd57386e09ee38bac4e51bf";

async function waitTx(tx: any) {
  console.log(`Waiting for transaction ${tx.hash} to be confirmed...`);
  await tx.wait();
}

async function getKmsAuth(ethers: any) {
  return await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
}

async function getAppAuth(ethers: any, appId: string) {
  const kmsAuth = await getKmsAuth(ethers);
  const controller = (await kmsAuth.apps(appId)).controller;
  console.log("AppAuth address:", controller);
  return await ethers.getContractAt("AppAuth", controller);
}

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
    const contract = await getKmsAuth(ethers);
    const tx = await contract.transferOwnership(newOwner);
    await waitTx(tx);
    console.log("Ownership transferred successfully");
  });

task("kms:set-info", "Set KMS information")
  .addParam("k256Pubkey", "K256 public key")
  .addParam("caPubkey", "CA public key")
  .addParam("quote", "Quote")
  .addParam("eventlog", "Event log")
  .setAction(async ({ k256Pubkey, caPubkey, quote, eventlog }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const tx = await contract.setKmsInfo({ k256Pubkey, caPubkey, quote, eventlog });
    await waitTx(tx);
    console.log("KMS info set successfully");
  });
task("kms:set-info-file", "Set KMS information from file")
  .addPositionalParam("file", "File path")
  .setAction(async ({ file }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const fileContent = fs.readFileSync(file, 'utf8');
    const tx = await contract.setKmsInfo(JSON.parse(fileContent));
    await waitTx(tx);
    console.log("KMS info set successfully");
  });

task("kms:set-tproxy")
  .addPositionalParam("appId", "TProxy App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const tx = await contract.setTProxyAppId(appId);
    await waitTx(tx);
    console.log("TProxy App ID set successfully");
  });

// App Management Tasks
task("app:deploy")
  .addPositionalParam("salt", "Salt for app deployment")
  .setAction(async ({ salt }, { ethers }) => {
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();

    const saltHash = ethers.keccak256(ethers.toUtf8Bytes(salt));
    const fullHash = ethers.keccak256(
      ethers.solidityPacked(
        ['address', 'bytes32'],
        [deployerAddress, saltHash]
      )
    );
    const appId = ethers.getAddress('0x' + fullHash.slice(-40));
    console.log("App ID:", appId);

    const AppAuth = await ethers.getContractFactory("AppAuth");
    const appAuth = await AppAuth.deploy(appId);
    await appAuth.waitForDeployment();

    const address = await appAuth.getAddress();
    console.log("AppAuth deployed to:", address);

    const kmsContract = await getKmsAuth(ethers);
    const tx = await kmsContract.registerApp(saltHash, address);
    await waitTx(tx);
    console.log("App registered in KMS successfully");
  });

task("app:add-hash")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.addComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash added successfully");
  });

task("app:remove-hash")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to remove")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.removeComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash removed successfully");
  });

// Enclave Management Tasks
task("enclave:register")
  .addPositionalParam("mrEnclave", "Enclave measurement")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerEnclave(mrEnclave);
    await waitTx(tx);
    console.log("Enclave registered successfully");
  });

task("enclave:deregister")
  .addPositionalParam("mrEnclave", "Enclave measurement")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.deregisterEnclave(mrEnclave);
    await waitTx(tx);
    console.log("Enclave deregistered successfully");
  });

// Image Management Tasks
task("image:register")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerImage(mrImage);
    await waitTx(tx);
    console.log("Image registered successfully");
  });

task("image:deregister")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.deregisterImage(mrImage);
    await waitTx(tx);
    console.log("Image deregistered successfully");
  });

// Device Management Tasks
task("device:register")
  .addPositionalParam("deviceId", "Device ID to register")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await kmsAuth.registerKmsDeviceId(hashedId);
    await waitTx(tx);
    console.log("Device ID registered successfully");
  });

task("device:deregister")
  .addPositionalParam("deviceId", "Device ID to deregister")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await kmsAuth.deregisterKmsDeviceId(hashedId);
    await waitTx(tx);
    console.log("Device ID deregistered successfully");
  });

// Status Check Tasks
task("check:app", "Check if an app is allowed to boot")
  .addParam("appId", "App ID to check")
  .addParam("mrEnclave", "Enclave measurement")
  .addParam("mrImage", "Image measurement")
  .addParam("composeHash", "Compose hash")
  .setAction(async ({ appId, mrEnclave, mrImage, composeHash }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const [isAllowed, reason] = await kmsAuth.isAppAllowed({
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
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const [isAllowed, reason] = await kmsAuth.isKmsAllowed({
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
    const kmsAuth = await getKmsAuth(ethers);
    const isRegistered = (await kmsAuth.apps(appId)).isRegistered;
    console.log("App ID is registered:", isRegistered);
  });

task("check:enclave")
  .addPositionalParam("mrEnclave", "Enclave measurement to check")
  .setAction(async ({ mrEnclave }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const isRegistered = await kmsAuth.allowedEnclaves(mrEnclave);
    console.log("Enclave measurement is registered:", isRegistered);
  });

task("check:image")
  .addPositionalParam("mrImage", "Image measurement to check")
  .setAction(async ({ mrImage }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const isRegistered = await kmsAuth.allowedImages(mrImage);
    console.log("Image measurement is registered:", isRegistered);
  });

task("check:app-hash")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to check")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const isAllowed = await appAuth.allowedComposeHashes(hash);
    console.log("Compose hash is allowed:", isAllowed);
  });

// Info Query Tasks
task("info:owner", "Get current contract owner")
  .setAction(async (_, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const owner = await kmsAuth.owner();
    console.log("Contract owner:", owner);
  });

task("info:kms", "Get current KMS information")
  .setAction(async (_, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const kmsInfo = await kmsAuth.kmsInfo();
    console.log("KMS Info:", {
      k256Pubkey: kmsInfo.k256Pubkey,
      caPubkey: kmsInfo.caPubkey,
      quote: kmsInfo.quote
    });
  });

task("info:tproxy", "Get current TProxy App ID")
  .setAction(async (_, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const appId = await kmsAuth.tproxyAppId();
    console.log("TProxy App ID:", appId);
  });
