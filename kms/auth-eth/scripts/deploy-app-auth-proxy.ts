import { ethers, upgrades } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  const deployerAddress = await deployer.getAddress();
  
  // You would typically get these parameters from command line or config
  const salt = "your_salt_value"; // Replace with actual salt
  const saltHash = ethers.keccak256(ethers.toUtf8Bytes(salt));
  
  // Calculate the app ID
  const fullHash = ethers.keccak256(
    ethers.solidityPacked(
      ['address', 'bytes32'],
      [deployerAddress, saltHash]
    )
  );
  const appId = ethers.getAddress('0x' + fullHash.slice(-40));
  console.log("Calculated App ID:", appId);
  
  console.log("Deploying AppAuth with proxy...");
  
  // Get the contract factory
  const AppAuth = await ethers.getContractFactory("AppAuth");
  
  // Deploy the proxy with the implementation
  const appAuth = await upgrades.deployProxy(
    AppAuth, 
    [appId, deployerAddress], // Pass appId and owner address to initialize
    { kind: 'uups' } // Specify UUPS proxy pattern
  );
  
  // Wait for the deployment to complete
  await appAuth.waitForDeployment();
  
  // Get the deployed addresses
  const proxyAddress = await appAuth.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(
    proxyAddress
  );
  
  console.log("Proxy deployed to:", proxyAddress);
  console.log("Implementation deployed to:", implementationAddress);
  
  // Get KmsAuth contract (make sure KMS_CONTRACT_ADDRESS is set or passed as parameter)
  const kmsContractAddress = process.env.KMS_CONTRACT_ADDRESS;
  if (kmsContractAddress) {
    const kmsAuth = await ethers.getContractAt("KmsAuth", kmsContractAddress);
    
    // Register the app with KmsAuth
    console.log("Registering app with KmsAuth...");
    const tx = await kmsAuth.registerApp(saltHash, proxyAddress);
    console.log("Transaction hash:", tx.hash);
    await tx.wait();
    console.log("App registered successfully");
  } else {
    console.log("KMS contract address not provided. Manual registration required.");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}); 