import { ethers } from 'ethers';
import { EthereumBackend } from './ethereum';
import { BootInfo } from './types';

// Mock contract instance
const mockContract = {
  isAppAllowed: jest.fn(),
  kmsAppId: jest.fn(),
  appController: jest.fn()
};

// Mock ethers
jest.mock('ethers', () => ({
  ethers: {
    JsonRpcProvider: jest.fn().mockImplementation(() => ({
      // Add any provider methods you need to mock
    })),
    Contract: jest.fn().mockImplementation(() => mockContract),
    getAddress: jest.fn().mockImplementation(addr => addr),
    ZeroAddress: '0x0000000000000000000000000000000000000000'
  }
}));

describe('EthereumBackend', () => {
  let backend: EthereumBackend;
  const mockRpcUrl = 'http://localhost:8545';
  const mockKmsContractAddr = '0x1234567890123456789012345678901234567890';
  
  const mockBootInfo: BootInfo = {
    mrEnclave: '0x1234',
    mrImage: '0x5678',
    appId: '0x9012345678901234567890123456789012345678',
    composeHash: '0xabcd',
    instanceId: '0x3456789012345678901234567890123456789012',
    deviceId: '0xef12'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    backend = new EthereumBackend(mockRpcUrl, mockKmsContractAddr);
  });

  describe('checkBoot', () => {
    it('should return true when all checks pass', async () => {
      // Mock successful responses
      mockContract.isAppAllowed.mockResolvedValue([true, '']);
      mockContract.appController.mockResolvedValue('0x1234567890123456789012345678901234567890');

      const result = await backend.checkBoot(mockBootInfo, false);
      expect(result.isAllowed).toBe(true);
      expect(result.reason).toBe('');
    });

    it('should return false when KMS check fails', async () => {
      mockContract.isAppAllowed.mockResolvedValue([false, 'KMS check failed']);

      const result = await backend.checkBoot(mockBootInfo, false);
      expect(result.isAllowed).toBe(false);
      expect(result.reason).toBe('KMS check failed: KMS check failed');
    });

    it('should return false when app controller is not set', async () => {
      mockContract.isAppAllowed.mockResolvedValue([true, '']);
      mockContract.appController.mockResolvedValue(ethers.ZeroAddress);

      const result = await backend.checkBoot(mockBootInfo, false);
      expect(result.isAllowed).toBe(false);
      expect(result.reason).toBe('No controller set for app');
    });

    it('should validate KMS app ID when isKms is true', async () => {
      mockContract.isAppAllowed.mockResolvedValue([true, '']);
      mockContract.kmsAppId.mockResolvedValue('0x1111111111111111111111111111111111111111');

      const result = await backend.checkBoot(mockBootInfo, true);
      expect(result.isAllowed).toBe(false);
      expect(result.reason).toBe('App ID does not match KMS app ID');
    });
  });
});
