import { ethers, run } from "hardhat";

async function main() {
  const KmsAuth = await ethers.getContractFactory("KmsAuth");
  const kmsAuth = await KmsAuth.deploy();
  await kmsAuth.waitForDeployment();
  
  const address = await kmsAuth.getAddress();
  console.log("KmsAuth deployed to:", address);

  // Wait for a few block confirmations to ensure the contract is deployed
  await kmsAuth.deploymentTransaction()?.wait(5);
  
  // Verify the contract on Etherscan
  console.log("Verifying contract on Etherscan...");
  try {
    await run("verify:verify", {
      address: address,
      constructorArguments: [],
    });
    console.log("Contract verified successfully");
  } catch (error: any) {
    if (error.message.toLowerCase().includes("already verified")) {
      console.log("Contract is already verified!");
    } else {
      console.error("Error verifying contract:", error);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});