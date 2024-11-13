async function main() {
  const AppRegistry = await ethers.getContractFactory("AppRegistry");
  const appRegistry = await AppRegistry.deploy();
  await appRegistry.waitForDeployment();

  const address = await appRegistry.getAddress();
  console.log("AppRegistry deployed to:", address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 