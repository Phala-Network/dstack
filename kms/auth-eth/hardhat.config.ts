import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-toolbox";
import process from "process";

let accounts: string[] = [];
if (process.env.PRIVATE_KEY) {
  accounts = [process.env.PRIVATE_KEY];
}

const config: HardhatUserConfig = {
  solidity: "0.8.19",
  networks: {
    hardhat: {
      chainId: 1337
    },
    sepolia: {
      url: `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts,
    }
  },
  etherscan: {
    apiKey: {
      sepolia: 'J5JH45HXJJHHXIQ8QDP466MG15Y6X6TQJD'
    }
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};

export default config;
