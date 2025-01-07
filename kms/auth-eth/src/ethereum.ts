import { ethers } from 'ethers';
import { BootInfo, BootResponse } from './types';
import { KmsAuth__factory } from '../typechain-types/factories/KmsAuth__factory';
import { KmsAuth } from '../typechain-types/KmsAuth';
import { AppAuth__factory } from '../typechain-types/factories/AppAuth__factory';
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider';

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider | HardhatEthersProvider;
  private kmsAuth: KmsAuth;

  constructor(provider: ethers.JsonRpcProvider | HardhatEthersProvider, kmsAuthAddr: string) {
    this.provider = provider;
    this.kmsAuth = KmsAuth__factory.connect(
      ethers.getAddress(kmsAuthAddr),
      this.provider
    );
  }

  private decodeHex(hex: string, sz: number = 32): string {
    // Remove '0x' prefix if present
    hex = hex.startsWith('0x') ? hex.slice(2) : hex;

    // Pad hex string to 64 characters (32 bytes)
    hex = hex.padStart(sz * 2, '0');

    // Add '0x' prefix back
    return '0x' + hex;
  }

  private async getAppController(appId: string): Promise<[string | null, string | null]> {
    try {
      const controller = await this.kmsAuth.appController(ethers.getAddress(appId));
      if (controller === ethers.ZeroAddress) {
        return [null, 'No controller set for app'];
      }
      return [controller, null];
    } catch (e) {
      return [null, `Error checking app registration: ${e instanceof Error ? e.message : String(e)}`];
    }
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    try {
      // Create boot info struct for contract call
      const bootInfoStruct = {
        appId: bootInfo.appId,
        composeHash: this.decodeHex(bootInfo.composeHash),
        instanceId: bootInfo.instanceId,
        deviceId: this.decodeHex(bootInfo.deviceId),
        mrEnclave: this.decodeHex(bootInfo.mrEnclave),
        mrImage: this.decodeHex(bootInfo.mrImage)
      };

      if (isKms) {
        const kmsAppId = await this.kmsAuth.kmsAppId();
        if (bootInfo.appId.toLowerCase() !== kmsAppId.toLowerCase()) {
          return { isAllowed: false, reason: 'App ID does not match KMS app ID' };
        }
      }

      {
        // First check with KmsAuth if the app and measurements are allowed
        const [isAllowed, reason] = await this.kmsAuth.isAppAllowed(bootInfoStruct);
        if (!isAllowed) {
          return { isAllowed: false, reason: `KMS check failed: ${reason}` };
        }
      }

      // Then check if app is registered and get AppAuth contract
      const [controllerAddr, error] = await this.getAppController(bootInfo.appId);
      if (!controllerAddr) {
        return { isAllowed: false, reason: error || 'Unknown error getting app controller' };
      }

      // Initialize AppAuth contract
      const appAuth = AppAuth__factory.connect(
        controllerAddr,
        this.provider
      );

      {
        // Finally check with AppAuth contract
        const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfoStruct);
        return { isAllowed, reason };
      }

    } catch (e) {
      if (e instanceof Error && e.message.includes('invalid address')) {
        return { isAllowed: false, reason: 'Invalid address format' };
      }
      throw new Error(`Error checking boot: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
