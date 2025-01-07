import { ethers } from 'ethers';
import { BootInfo, BootResponse, KMS_CONTRACT_ABI, APP_CONTRACT_ABI } from './types';

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider;
  private kmsContract: ethers.Contract;

  constructor(rpcUrl: string, kmsContractAddr: string) {
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
    this.kmsContract = new ethers.Contract(
      ethers.getAddress(kmsContractAddr),
      KMS_CONTRACT_ABI,
      this.provider
    );
  }

  private decodeHex32(hexStr: string): string {
    // Remove 0x prefix if present and pad to 64 characters
    hexStr = hexStr.replace('0x', '').padStart(64, '0');
    return '0x' + hexStr;
  }

  private async getAppController(appId: string): Promise<[string | null, string | null]> {
    try {
      const controller = await this.kmsContract.appController(ethers.getAddress(appId));
      if (controller === ethers.ZeroAddress) {
        return [null, "No controller set for app"];
      }
      return [controller, null];
    } catch (e) {
      return [null, `Error checking app registration: ${e instanceof Error ? e.message : String(e)}`];
    }
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    try {
      // If isKms, ensure the App ID matches the KMS App ID in the contract
      if (isKms) {
        const kmsAppId = await this.kmsContract.kmsAppId();
        if (bootInfo.appId !== kmsAppId) {
          return { isAllowed: false, reason: "App ID does not match KMS app ID" };
        }
      }

      // Create boot info tuple for contract call
      const bootInfoTuple = [
        ethers.getAddress(bootInfo.appId),
        this.decodeHex32(bootInfo.composeHash),
        ethers.getAddress(bootInfo.instanceId),
        this.decodeHex32(bootInfo.deviceId),
        this.decodeHex32(bootInfo.mrEnclave),
        this.decodeHex32(bootInfo.mrImage)
      ] as const;

      // First check with KmsAuth if the app and measurements are allowed
      const [kmsAllowed, kmsReason] = await this.kmsContract.isAppAllowed(bootInfoTuple);
      if (!kmsAllowed) {
        return { isAllowed: false, reason: `KMS check failed: ${kmsReason}` };
      }

      // Then check if app is registered and get AppAuth contract
      const [controllerAddr, error] = await this.getAppController(bootInfo.appId);
      if (!controllerAddr) {
        return { isAllowed: false, reason: error || "Unknown error" };
      }

      // Initialize AppAuth contract
      const appAuth = new ethers.Contract(
        controllerAddr,
        APP_CONTRACT_ABI,
        this.provider
      );

      // Finally check with AppAuth contract
      const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfoTuple);
      return { isAllowed, reason };

    } catch (e) {
      throw new Error(`Error checking boot: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
