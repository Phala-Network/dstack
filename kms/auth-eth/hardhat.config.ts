import "@openzeppelin/hardhat-upgrades";
import { HardhatUserConfig, task, types } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";
import fs from 'fs';
import { deployContract } from "./scripts/deploy";
import { upgradeContract } from "./scripts/upgrade";
import { accountBalance } from "./lib/deployment-helpers";

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x0000000000000000000000000000000000000000000000000000000000000000";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.22",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  defaultNetwork: "hardhat",
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
  },
  etherscan: {
    apiKey: {
      'phala': 'empty',
      default: process.env.ETHERSCAN_API_KEY || ""
    },
    customChains: [
      {
        network: "phala",
        chainId: 2035,
        urls: {
          apiURL: "https://explorer-phala-mainnet-0.t.conduit.xyz/api",
          browserURL: "https://explorer-phala-mainnet-0.t.conduit.xyz:443"
        }
      }
    ]
  }
};

export default config;

// Contract addresses from environment
const KMS_CONTRACT_ADDRESS = process.env.KMS_CONTRACT_ADDRESS || "0x59E4a36B01a87fD9D1A4C12377253FE9a7b018Ba";

async function waitTx(tx: any) {
  console.log(`Waiting for transaction ${tx.hash} to be confirmed...`);
  return await tx.wait();
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
task("kms:deploy", "Deploy the KmsAuth contract")
  .setAction(async (_, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));
    await deployContract(hre, "KmsAuth", [deployerAddress]);
  });

task("kms:upgrade", "Upgrade the KmsAuth contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "KmsAuth", taskArgs.address, taskArgs.dryRun);
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

task("kms:set-tproxy", "Set the allowed TProxy App ID")
  .addPositionalParam("appId", "TProxy App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const tx = await contract.setTproxyAppId(appId);
    await waitTx(tx);
    console.log("TProxy App ID set successfully");
  });

task("app:add-hash", "Add a compose hash to the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.addComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash added successfully");
  });

task("app:remove-hash", "Remove a compose hash from the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to remove")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.removeComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash removed successfully");
  });

// Mr Management Tasks
task("kms:register-aggregated-mr", "Register an aggregated MR measurement")
  .addPositionalParam("mrAggregated", "Aggregated MR measurement")
  .setAction(async ({ mrAggregated }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerAggregatedMr(mrAggregated);
    await waitTx(tx);
    console.log("Aggregated MR registered successfully");
  });

task("kms:deregister-aggregated-mr", "Deregister an aggregated MR measurement")
  .addPositionalParam("mrAggregated", "Aggregated MR measurement")
  .setAction(async ({ mrAggregated }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.deregisterAggregatedMr(mrAggregated);
    await waitTx(tx);
    console.log("Aggregated MR deregistered successfully");
  });

// Image Management Tasks
task("kms:register-image", "Register an image measurement")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerImage(mrImage);
    await waitTx(tx);
    console.log("Image registered successfully");
  });

task("kms:deregister-image", "Deregister an image measurement")
  .addPositionalParam("mrImage", "Image measurement")
  .setAction(async ({ mrImage }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.deregisterImage(mrImage);
    await waitTx(tx);
    console.log("Image deregistered successfully");
  });

// Device Management Tasks
task("kms:register-device", "Register a device ID")
  .addPositionalParam("deviceId", "Device ID to register")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await kmsAuth.registerKmsDeviceId(hashedId);
    await waitTx(tx);
    console.log("Device ID registered successfully");
  });

task("kms:deregister-device", "Deregister a device ID")
  .addPositionalParam("deviceId", "Device ID to deregister")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const tx = await kmsAuth.deregisterKmsDeviceId(hashedId);
    await waitTx(tx);
    console.log("Device ID deregistered successfully");
  });

task("kms:add-hash", "Add a compose hash of an KMS instance")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ hash }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerKmsComposeHash(hash);
    await waitTx(tx);
    console.log("KMS compose hash added successfully");
  });

task("kms:add-device", "Add a device ID of an KMS instance")
  .addPositionalParam("deviceId", "Device ID")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.registerKmsDeviceId(deviceId);
    await waitTx(tx);
    console.log("Device compose hash added successfully");
  });

// Status Check Tasks
task("check:app", "Check if an app is allowed to boot")
  .addParam("appId", "App ID to check")
  .addParam("mrAggregated", "Aggregated MR measurement")
  .addParam("mrImage", "Image measurement")
  .addParam("composeHash", "Compose hash")
  .setAction(async ({ appId, mrAggregated, mrImage, composeHash }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const [isAllowed, reason] = await kmsAuth.isAppAllowed({
      appId,
      mrAggregated,
      mrImage,
      composeHash,
      deviceId: ethers.ZeroHash,
      instanceId: ethers.ZeroAddress
    });
    console.log("Is allowed:", isAllowed);
    console.log("Reason:", reason);
  });

task("check:kms", "Check if KMS is allowed to boot")
  .addParam("mrAggregated", "Aggregated MR measurement")
  .addParam("composeHash", "Compose hash")
  .addParam("deviceId", "Device ID")
  .setAction(async ({ mrAggregated, composeHash, deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const hashedId = ethers.keccak256(ethers.toUtf8Bytes(deviceId));
    const [isAllowed, reason] = await kmsAuth.isKmsAllowed({
      mrAggregated,
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

task("check:mr-aggregated")
  .addPositionalParam("mrAggregated", "MR Aggregated measurement to check")
  .setAction(async ({ mrAggregated }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const isRegistered = await kmsAuth.allowedEnclaves(mrAggregated);
    console.log("MR Aggregated measurement is registered:", isRegistered);
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

task("app:deploy", "Deploy AppAuth with a UUPS proxy")
  .addPositionalParam("salt", "Salt for app deployment")
  .setAction(async ({ salt }, hre) => {
    const { ethers, upgrades } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));

    // Calculate app ID
    const saltHash = ethers.keccak256(ethers.toUtf8Bytes(salt));
    const fullHash = ethers.keccak256(
      ethers.solidityPacked(
        ['address', 'bytes32'],
        [deployerAddress, saltHash]
      )
    );
    const appId = ethers.getAddress('0x' + fullHash.slice(-40));
    console.log("App ID:", appId);

    const appAuth = await deployContract(hre, "AppAuth", [deployerAddress, appId, false]);
    if (!appAuth) {
      return;
    }

    const proxyAddress = await appAuth.getAddress();
    const kmsContract = await getKmsAuth(ethers);
    const tx = await kmsContract.registerApp(saltHash, proxyAddress);
    const receipt = await waitTx(tx);
    // Parse the AppRegistered event from the logs
    const appRegisteredEvent = receipt.logs
      .filter((log: any) => log.fragment?.name === 'AppRegistered')
      .map((log: any) => {
        const { appId } = log.args;
        return { appId };
      })[0];

    if (appRegisteredEvent) {
      console.log("App registered in KMS successfully");
      console.log("Registered AppId:", appRegisteredEvent.appId);
    } else {
      console.log("App registered in KMS successfully (event not found)");
    }
  });

task("app:upgrade", "Upgrade the AppAuth contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "AppAuth", taskArgs.address, taskArgs.dryRun);
  });