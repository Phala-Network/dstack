import { HardhatRuntimeEnvironment } from "hardhat/types";
import * as helpers from "../lib/deployment-helpers";

// This function should be called directly by Hardhat tasks
export async function deployContract(hre: HardhatRuntimeEnvironment, contractName: string, initializerArgs: any[] = []) {
  try {
    console.log(`Starting ${contractName} deployment process...`);

    // Get network info
    await helpers.logNetworkInfo(hre);

    console.log("Getting contract factory...");
    const contractFactory = await hre.ethers.getContractFactory(contractName);

    // Estimate gas for deployment
    await helpers.estimateDeploymentCost(
      hre,
      contractName,
      initializerArgs
    );

    // Prompt for confirmation
    if (!(await helpers.confirmAction('Do you want to proceed with deployment?'))) {
      console.log('Deployment cancelled');
      return;
    }

    // Deploy using proxy pattern
    console.log("Deploying proxy...");
    const contract = await hre.upgrades.deployProxy(contractFactory,
      initializerArgs,
      { kind: 'uups' }
    );
    console.log("Waiting for deployment...");
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    console.log(`${contractName} Proxy deployed to:`, address);

    // Verify deployment
    await helpers.verifyDeployment(hre, address);

    const tx = await contract.deploymentTransaction();
    console.log("Transaction hash:", tx?.hash);
    // Wait for a few block confirmations to ensure the contract is deployed
    await tx?.wait(5);
    console.log("Deployment completed successfully");

    return contract;
  } catch (error) {
    console.error("Error during deployment:", error);
    throw error;
  }
}

// For backward compatibility when running the script directly
async function main() {
  const hre = require("hardhat");
  const deployer = await helpers.getSigner(hre);
  const address = await deployer.getAddress();
  console.log("Deploying with account:", address);
  console.log("Account balance:", await helpers.accountBalance(hre.ethers, address));
  await deployContract(hre, "KmsAuth", [address]);
}

// Only execute if directly run
if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}