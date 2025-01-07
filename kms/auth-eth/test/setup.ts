import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { KmsAuth } from "../typechain-types";

declare global {
  var testContracts: {
    kmsAuth: KmsAuth;
    owner: SignerWithAddress;
  };
}

beforeAll(async () => {
  // Get signers
  const [owner] = await ethers.getSigners();

  // Deploy contracts
  const KmsAuth = await ethers.getContractFactory("KmsAuth");
  const kmsAuth = await KmsAuth.deploy();
  await kmsAuth.waitForDeployment();

  // Initialize the contract with an app and KMS info
  const salt = ethers.randomBytes(32);
  await kmsAuth.registerApp(salt, owner.address);
  
  // Calculate the app ID that was generated
  const fullHash = ethers.keccak256(
    ethers.solidityPacked(['address', 'bytes32'], [owner.address, salt])
  );
  const contractAppId = ethers.getAddress('0x' + fullHash.slice(26));

  // Set up KMS info with the generated app ID
  await kmsAuth.setKmsInfo(
    contractAppId,
    ethers.encodeBytes32String("1234"),
    "test-root-ca",
    "test-ra-report"
  );

  // Register some test enclaves and images
  await kmsAuth.registerEnclave(ethers.encodeBytes32String("1234"));
  await kmsAuth.registerImage(ethers.encodeBytes32String("5678"));

  // Set up global test contracts
  global.testContracts = {
    kmsAuth,
    owner
  };
});
