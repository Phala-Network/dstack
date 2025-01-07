import { expect } from "chai";
import { ethers } from "hardhat";
import { KmsAuth } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("KmsAuth", function () {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let user: SignerWithAddress;
  
  beforeEach(async function () {
    [owner, user] = await ethers.getSigners();
    
    const KmsAuth = await ethers.getContractFactory("KmsAuth");
    kmsAuth = await KmsAuth.deploy();
    await kmsAuth.waitForDeployment();
  });

  describe("Basic functionality", function () {
    it("Should set the correct owner", async function () {
      expect(await kmsAuth.owner()).to.equal(owner.address);
    });

    it("Should allow setting KMS info", async function () {
      const appId = ethers.Wallet.createRandom().address;
      const publicKey = ethers.randomBytes(32);
      const rootCa = "test-root-ca";
      const raReport = "test-ra-report";

      await kmsAuth.setKmsInfo(appId, publicKey, rootCa, raReport);
      
      const kmsInfo = await kmsAuth.kmsInfo();
      expect(kmsInfo.appId).to.equal(appId);
      expect(ethers.hexlify(kmsInfo.publicKey)).to.equal(ethers.hexlify(publicKey));
      expect(kmsInfo.rootCa).to.equal(rootCa);
      expect(kmsInfo.raReport).to.equal(raReport);
    });
  });

  describe("Enclave and Image management", function () {
    const testEnclave = ethers.randomBytes(32);
    const testImage = ethers.randomBytes(32);

    it("Should register and deregister enclaves", async function () {
      await kmsAuth.registerEnclave(testEnclave);
      expect(await kmsAuth.allowedEnclaves(testEnclave)).to.be.true;

      await kmsAuth.deregisterEnclave(testEnclave);
      expect(await kmsAuth.allowedEnclaves(testEnclave)).to.be.false;
    });

    it("Should register and deregister images", async function () {
      await kmsAuth.registerImage(testImage);
      expect(await kmsAuth.allowedImages(testImage)).to.be.true;

      await kmsAuth.deregisterImage(testImage);
      expect(await kmsAuth.allowedImages(testImage)).to.be.false;
    });
  });

  describe("App registration", function () {
    it("Should register a new app", async function () {
      const salt = ethers.randomBytes(32);
      const controller = ethers.Wallet.createRandom().address;
      
      await kmsAuth.registerApp(salt, controller);
      
      const fullHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32'],
          [owner.address, salt]
        )
      );
      const appId = ethers.getAddress("0x" + fullHash.slice(26));
      
      const appConfig = await kmsAuth.apps(appId);
      expect(appConfig.isRegistered).to.be.true;
      expect(appConfig.controller).to.equal(controller);
    });

    it("Should not allow registering the same app twice", async function () {
      const salt = ethers.randomBytes(32);
      const controller = ethers.Wallet.createRandom().address;
      
      await kmsAuth.registerApp(salt, controller);
      
      const fullHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32'],
          [owner.address, salt]
        )
      );
      const appId = ethers.getAddress("0x" + fullHash.slice(26));
      
      await expect(
        kmsAuth.registerApp(salt, controller)
      ).to.be.revertedWith("App already registered");
    });
  });

  describe("isAppAllowed", function () {
    it("Should validate app boot info correctly", async function () {
      // Setup
      const salt = ethers.randomBytes(32);
      const controller = ethers.Wallet.createRandom().address;
      await kmsAuth.registerApp(salt, controller);
      
      const fullHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32'],
          [owner.address, salt]
        )
      );
      const appId = ethers.getAddress("0x" + fullHash.slice(26));
      
      const mrEnclave = ethers.randomBytes(32);
      const mrImage = ethers.randomBytes(32);
      
      // Register everything needed
      await kmsAuth.registerEnclave(mrEnclave);
      await kmsAuth.registerImage(mrImage);
      
      const bootInfo = {
        appId: appId,
        composeHash: ethers.randomBytes(32),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrEnclave: mrEnclave,
        mrImage: mrImage
      };

      const [allowed, reason] = await kmsAuth.isAppAllowed(bootInfo);
      expect(allowed).to.be.true;
      expect(reason).to.equal("");
    });

    it("Should reject unregistered enclave", async function () {
      const bootInfo = {
        appId: ethers.Wallet.createRandom().address,
        composeHash: ethers.randomBytes(32),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrEnclave: ethers.randomBytes(32),
        mrImage: ethers.randomBytes(32)
      };

      const [allowed, reason] = await kmsAuth.isAppAllowed(bootInfo);
      expect(allowed).to.be.false;
      expect(reason).to.equal("Enclave not allowed");
    });

    it("Should reject unregistered image", async function () {
      const mrEnclave = ethers.randomBytes(32);
      await kmsAuth.registerEnclave(mrEnclave);

      const bootInfo = {
        appId: ethers.Wallet.createRandom().address,
        composeHash: ethers.randomBytes(32),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrEnclave: mrEnclave,
        mrImage: ethers.randomBytes(32)
      };

      const [allowed, reason] = await kmsAuth.isAppAllowed(bootInfo);
      expect(allowed).to.be.false;
      expect(reason).to.equal("Image hash not allowed");
    });
  });

  describe("Access control", function () {
    it("Should prevent non-owners from setting KMS info", async function () {
      const appId = ethers.Wallet.createRandom().address;
      const publicKey = ethers.randomBytes(32);
      
      await expect(
        kmsAuth.connect(user).setKmsInfo(appId, publicKey, "", "")
      ).to.be.revertedWith("Only owner can call this function");
    });

    it("Should prevent non-owners from registering enclaves", async function () {
      const enclave = ethers.randomBytes(32);
      
      await expect(
        kmsAuth.connect(user).registerEnclave(enclave)
      ).to.be.revertedWith("Only owner can call this function");
    });

    it("Should prevent non-owners from registering images", async function () {
      const image = ethers.randomBytes(32);
      
      await expect(
        kmsAuth.connect(user).registerImage(image)
      ).to.be.revertedWith("Only owner can call this function");
    });

    it("Should prevent non-owners from deregistering enclaves", async function () {
      const enclave = ethers.randomBytes(32);
      await kmsAuth.registerEnclave(enclave);
      
      await expect(
        kmsAuth.connect(user).deregisterEnclave(enclave)
      ).to.be.revertedWith("Only owner can call this function");
    });

    it("Should prevent non-owners from deregistering images", async function () {
      const image = ethers.randomBytes(32);
      await kmsAuth.registerImage(image);
      
      await expect(
        kmsAuth.connect(user).deregisterImage(image)
      ).to.be.revertedWith("Only owner can call this function");
    });
  });
});