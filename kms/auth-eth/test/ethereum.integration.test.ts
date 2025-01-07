import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/KmsAuth";
import { IAppAuth } from "../typechain-types/IAppAuth";

describe('Integration Tests', () => {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let backend: EthereumBackend;
  let kmsAppId: string;

  beforeAll(async () => {
    owner = global.testContracts.owner;
    kmsAuth = global.testContracts.kmsAuth;

    // Initialize backend with the same provider
    const provider = owner.provider;
    if (!provider) {
      throw new Error('Provider not found');
    }
    const contractAddress = await kmsAuth.getAddress();
    backend = new EthereumBackend(provider, contractAddress);
  });

  describe('KmsAuth Contract', () => {
    let mockBootInfo: IAppAuth.AppBootInfoStruct;

    beforeEach(async () => {
      // Get the current KMS app ID
      const kmsAppIdHex = await kmsAuth.kmsAppId();
      kmsAppId = kmsAppIdHex;

      mockBootInfo = {
        appId: kmsAppId,
        composeHash: ethers.encodeBytes32String('1234567890abcdef'),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.encodeBytes32String('123'),
        mrEnclave: ethers.encodeBytes32String('1234'),
        mrImage: ethers.encodeBytes32String('5678')
      };
    });

    it('should return true when all checks pass', async () => {
      const [isAllowed, reason] = await kmsAuth.isAppAllowed(mockBootInfo);
      expect(reason).toBe('');
      expect(isAllowed).toBe(true);
    });

    it('should return false when enclave is not registered', async () => {
      const badMrEnclave = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        mrEnclave: badMrEnclave
      });

      expect(isAllowed).toBe(false);
      expect(reason).toBe('Enclave not allowed');
    });

    it('should return false when image is not registered', async () => {
      const badMrImage = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        mrImage: badMrImage
      });

      expect(reason).toBe('Image hash not allowed');
      expect(isAllowed).toBe(false);
    });
  });

  describe('EthereumBackend', () => {
    let mockBootInfo: BootInfo;

    beforeEach(async () => {
      // Get the current KMS app ID
      const kmsAppIdHex = await kmsAuth.kmsAppId();
      kmsAppId = kmsAppIdHex;

      mockBootInfo = {
        appId: kmsAppId, 
        composeHash: ethers.encodeBytes32String("1234567890abcdef"),
        instanceId: ethers.Wallet.createRandom().address, 
        deviceId: ethers.encodeBytes32String("123"),
        mrEnclave: ethers.encodeBytes32String("1234"), 
        mrImage: ethers.encodeBytes32String("5678") 
      };
    });

    describe('checkBoot', () => {
      it('should return true when all checks pass', async () => {
        const result = await backend.checkBoot(mockBootInfo, false);
        expect(result.reason).toBe('');
        expect(result.isAllowed).toBe(true);
      });

      it('should return false when enclave is not allowed', async () => {
        const badBootInfo = { 
          ...mockBootInfo, 
          mrEnclave: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).toBe('KMS check failed: Enclave not allowed');
        expect(result.isAllowed).toBe(false);
      });

      it('should return false when image is not allowed', async () => {
        const badBootInfo = { 
          ...mockBootInfo, 
          mrImage: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).toBe('KMS check failed: Image hash not allowed');
        expect(result.isAllowed).toBe(false);
      });

      it('should return false when app is not registered', async () => {
        const badBootInfo = { 
          ...mockBootInfo, 
          appId: ethers.Wallet.createRandom().address
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).toBe('KMS check failed: App not registered');
        expect(result.isAllowed).toBe(false);
      });

      it('should validate KMS app ID when isKms is true', async () => {
        const badBootInfo = { 
          ...mockBootInfo, 
          appId: ethers.Wallet.createRandom().address
        };
        const result = await backend.checkBoot(badBootInfo, true);
        expect(result.reason).toBe('App ID does not match KMS app ID');
        expect(result.isAllowed).toBe(false);
      });
    });
  });
});
