import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/KmsAuth";
import { IAppAuth } from "../typechain-types/IAppAuth";

// Declare global test contracts
declare global {
  var testContracts: {
    kmsAuth: KmsAuth;
    owner: SignerWithAddress;
  };
}

describe('EthereumBackend', () => {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let backend: EthereumBackend;
  let mockBootInfo: BootInfo;
  let appId: string;

  beforeEach(async () => {
    // Get test contracts from global setup
    ({ kmsAuth, owner } = global.testContracts);
    
    // Initialize backend with KmsAuth contract address
    backend = new EthereumBackend(
      owner.provider,
      await kmsAuth.getAddress()
    );

    // Generate a valid app ID
    appId = ethers.Wallet.createRandom().address;

    // Create mock boot info with valid addresses
    mockBootInfo = {
      appId,
      composeHash: ethers.encodeBytes32String('0x1234567890abcdef'),
      instanceId: ethers.Wallet.createRandom().address,
      deviceId: ethers.encodeBytes32String('0x123'),
      mrEnclave: ethers.encodeBytes32String('0x1234'),
      mrImage: ethers.encodeBytes32String('0x5678')
    };

    // Set up KMS info
    await kmsAuth.setKmsInfo(
      mockBootInfo.appId,
      ethers.encodeBytes32String("0x1234"),
      "test-root-ca",
      "test-ra-report"
    );

    // Register enclave and image
    await kmsAuth.registerEnclave(mockBootInfo.mrEnclave);
    await kmsAuth.registerImage(mockBootInfo.mrImage);
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
        mrEnclave: ethers.encodeBytes32String('0x9999')
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('KMS check failed: Enclave not allowed');
      expect(result.isAllowed).toBe(false);
    });

    it('should return false when image is not allowed', async () => {
      const badBootInfo = { 
        ...mockBootInfo, 
        mrImage: ethers.encodeBytes32String('0x9999')
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
