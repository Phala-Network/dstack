import { ethers } from "hardhat";
import { KmsAuth } from "../typechain-types";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import process from "process";

const contractAddress =
    process.env.KMS_CONTRACT_ADDRESS ||
    "0x5FbDB2315678afecb367f032d93F642f64180aa3";

async function getContract(contractAddress: string) {
    return await ethers.getContractAt("KmsAuth", contractAddress);
}

async function main() {
    const argv = await yargs(hideBin(process.argv))
        .option("contract", {
            alias: "c",
            type: "string",
            description: "Contract address",
            demandOption: true
        })
        .command("set-kms", "Set KMS information", (yargs) => {
            return yargs
                .option("appId", { type: "string", required: true })
                .option("k256Pubkey", { type: "string", required: true })
                .option("caPubkey", { type: "string", required: true })
                .option("quote", { type: "string", required: true });
        })
        .command("register-app", "Register a new app", (yargs) => {
            return yargs
                .option("salt", { type: "string", required: true })
                .option("controller", { type: "string", required: true });
        })
        .command("register-enclave", "Register an enclave measurement", (yargs) => {
            return yargs.option("mrEnclave", { type: "string", required: true });
        })
        .command("register-image", "Register an image measurement", (yargs) => {
            return yargs.option("mrImage", { type: "string", required: true });
        })
        .command("register-hash", "Register a KMS compose hash", (yargs) => {
            return yargs.option("hash", { type: "string", required: true });
        })
        .command("check-app", "Check if an app is allowed to boot", (yargs) => {
            return yargs
                .option("appId", { type: "string", required: true })
                .option("mrEnclave", { type: "string", required: true })
                .option("mrImage", { type: "string", required: true })
                .option("composeHash", { type: "string", required: true });
        })
        .demandCommand(1)
        .strict()
        .argv;

    const contract = await getContract(contractAddress);

    try {
        switch (argv._[0]) {
            case "set-kms": {
                const tx = await contract.setKmsInfo({
                    appId: argv.appId,
                    k256Pubkey: argv.k256Pubkey,
                    caPubkey: argv.caPubkey,
                    quote: argv.quote
                });
                await tx.wait();
                console.log("KMS info set successfully");
                break;
            }

            case "register-app": {
                const tx = await contract.registerApp(argv.salt, argv.controller);
                await tx.wait();
                console.log("App registered successfully");
                break;
            }

            case "register-enclave": {
                const tx = await contract.registerEnclave(argv.mrEnclave);
                await tx.wait();
                console.log("Enclave registered successfully");
                break;
            }

            case "register-image": {
                const tx = await contract.registerImage(argv.mrImage);
                await tx.wait();
                console.log("Image registered successfully");
                break;
            }

            case "register-kms-compose-hash": {
                const tx = await contract.registerKmsComposeHash(argv.hash);
                await tx.wait();
                console.log("KMS compose hash registered successfully");
                break;
            }

            case "check-app": {
                const [isAllowed, reason] = await contract.isAppAllowed({
                    appId: argv.appId,
                    mrEnclave: argv.mrEnclave,
                    mrImage: argv.mrImage,
                    composeHash: argv.composeHash
                });
                console.log("Is allowed:", isAllowed);
                console.log("Reason:", reason);
                break;
            }
        }
    } catch (error) {
        console.error("Error:", error);
        process.exitCode = 1;
    }
}

main();