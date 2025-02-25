import { ethers, upgrades } from "hardhat";

async function main() {
  const proxyAddress = "YOUR_PROXY_ADDRESS"; // Replace with your actual proxy address
  
  console.log("Upgrading KmsAuth...");
  
  // Get the new implementation contract factory
  const KmsAuthV2 = await ethers.getContractFactory("KmsAuth"); // Should be your new implementation
  
  // Upgrade the proxy to the new implementation
  const upgraded = await upgrades.upgradeProxy(proxyAddress, KmsAuthV2);
  
  console.log("KmsAuth upgraded at proxy address:", await upgraded.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}); 