import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import hre from "hardhat";
import { ethers } from "hardhat";
import { KmsAuth } from "../typechain-types/contracts/KmsAuth";
import { AppAuth } from "../typechain-types/contracts/AppAuth";
import { deployContract } from "../scripts/deploy";

declare global {
  var testContracts: {
    kmsAuth: KmsAuth;
    appAuth: AppAuth;
    appId: string;
    owner: SignerWithAddress;
  };
}

beforeAll(async () => {

  // Get signers
  const [owner] = await ethers.getSigners();

  // Deploy contracts
  const kmsAuth = await deployContract(hre, "KmsAuth", [owner.address], true) as KmsAuth;

  // Initialize the contract with an app and KMS info
  const salt = ethers.randomBytes(32);
  const appId = await kmsAuth.calculateAppId(owner.address, salt);

  const appAuth = await deployContract(hre, "AppAuth", [owner.address, appId, false], true) as AppAuth;

  await kmsAuth.registerApp(salt, await appAuth.getAddress());

  // Set up KMS info with the generated app ID
  await kmsAuth.setKmsInfo({
    quote: ethers.encodeBytes32String("1234"),
    caPubkey: ethers.encodeBytes32String("test-ca-pubkey"),
    k256Pubkey: ethers.encodeBytes32String("test-k256-pubkey"),
    eventlog: ethers.encodeBytes32String("test-eventlog")
  });

  // Register some test enclaves and images
  await kmsAuth.registerAggregatedMr(ethers.encodeBytes32String("11"));
  await kmsAuth.registerImage(ethers.encodeBytes32String("22"));
  await appAuth.addComposeHash(ethers.encodeBytes32String("33"));

  // Set up global test contracts
  global.testContracts = {
    kmsAuth,
    appAuth,
    appId,
    owner
  };
});
