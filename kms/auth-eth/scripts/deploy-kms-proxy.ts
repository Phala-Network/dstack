import { ethers, upgrades } from "hardhat";

async function main() {
  console.log("Deploying KmsAuth with proxy...");
  
  // Get the contract factory
  const KmsAuth = await ethers.getContractFactory("KmsAuth");
  
  // Deploy the proxy with the implementation
  const kmsAuth = await upgrades.deployProxy(
    KmsAuth, 
    [await (await ethers.getSigners())[0].getAddress()], // Pass the owner address to initialize
    { kind: 'uups' } // Specify UUPS proxy pattern
  );
  
  // Wait for the deployment to complete
  await kmsAuth.waitForDeployment();
  
  // Get the deployed addresses
  const proxyAddress = await kmsAuth.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(
    proxyAddress
  );
  
  console.log("Proxy deployed to:", proxyAddress);
  console.log("Implementation deployed to:", implementationAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}); 