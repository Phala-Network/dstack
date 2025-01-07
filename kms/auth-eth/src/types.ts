export interface BootInfo {
  mrEnclave: string;
  mrImage: string;
  appId: string;
  composeHash: string;
  instanceId: string;
  deviceId: string;
}

export interface BootResponse {
  isAllowed: boolean;
  reason: string;
}

// Removed KMS_CONTRACT_ABI and APP_CONTRACT_ABI since we're using typechain types now
