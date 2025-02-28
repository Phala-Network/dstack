import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/contracts/KmsAuth";
import { IAppAuth } from "../typechain-types/contracts/IAppAuth";
import { expect } from "chai";

describe('Integration Tests', () => {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let backend: EthereumBackend;
  let appId: string;

  beforeAll(async () => {
    owner = global.testContracts.owner;
    kmsAuth = global.testContracts.kmsAuth;
    appId = global.testContracts.appId;

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
      mockBootInfo = {
        appId,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.encodeBytes32String('123'),
        mrAggregated: ethers.encodeBytes32String('11'),
        mrImage: ethers.encodeBytes32String('22'),
        composeHash: ethers.encodeBytes32String('33'),
      };
    });

    it('should return true when all checks pass', async () => {
      const [isAllowed, reason] = await kmsAuth.isAppAllowed(mockBootInfo);
      expect(reason).to.equal('');
      expect(isAllowed).to.equal(true);
    });

    it('should return true when enclave is not registered but image is registered', async () => {
      const badMrAggregated = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        mrAggregated: badMrAggregated
      });

      expect(isAllowed).to.equal(true);
      expect(reason).to.equal('');
    });

    it('should return true when image is not registered but enclave is registered', async () => {
      const badMrImage = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        mrImage: badMrImage
      });

      expect(reason).to.equal('');
      expect(isAllowed).to.equal(true);
    });

    it('should return false when enclave and image are not registered', async () => {
      const badMrAggregated = ethers.encodeBytes32String('9999');
      const badMrImage = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        mrAggregated: badMrAggregated,
        mrImage: badMrImage
      });
      expect(reason).to.equal('Neither aggregated MR nor image is allowed');
      expect(isAllowed).to.equal(false);
    });
  });

  describe('EthereumBackend', () => {
    let appId: string;
    let mockBootInfo: BootInfo;

    beforeEach(async () => {
      appId = global.testContracts.appId;
      mockBootInfo = {
        appId,
        composeHash: ethers.encodeBytes32String("33"),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.encodeBytes32String("123"),
        mrAggregated: ethers.encodeBytes32String("11"),
        mrImage: ethers.encodeBytes32String("22")
      };
    });

    describe('checkBoot', () => {
      it('should return true when all checks pass', async () => {
        const result = await backend.checkBoot(mockBootInfo, false);
        expect(result.reason).to.equal('');
        expect(result.isAllowed).to.equal(true);
      });

      it('should return true when enclave is not allowed but image is allowed', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          mrAggregated: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('');
        expect(result.isAllowed).to.equal(true);
      });

      it('should return true when image is not allowed but enclave is allowed', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          mrImage: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('');
        expect(result.isAllowed).to.equal(true);
      });

      it('should return false when enclave and image are not registered', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          mrAggregated: ethers.encodeBytes32String('9999'),
          mrImage: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('Neither aggregated MR nor image is allowed');
        expect(result.isAllowed).to.equal(false);
      });

      it('should return false when app is not registered', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          appId: ethers.Wallet.createRandom().address
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('App not registered');
        expect(result.isAllowed).to.equal(false);
      });
    });
  });
});
