async function verify(address, constructorArguments = []) {
  try {
    await hre.run("verify:verify", {
      address: address,
      constructorArguments: constructorArguments,
      force: true
    });
  } catch (error) {
    if (error.message.toLowerCase().includes("already verified")) {
      console.log("Contract already verified!");
    } else {
      console.error(error);
    }
  }
}

async function main() {
  // Get the contract address from command line arguments
  const contractAddress = process.env.ADDRESS;
  
  if (!contractAddress) {
    throw new Error("Please provide the contract address using the ADDRESS environment variable");
  }

  console.log("Verifying contract at:", contractAddress);
  await verify(contractAddress);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 