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

export const KMS_CONTRACT_ABI = [
  {
    inputs: [{
      components: [
        {name: "appId", type: "address"},
        {name: "composeHash", type: "bytes32"},
        {name: "instanceId", type: "address"},
        {name: "deviceId", type: "bytes32"},
        {name: "mrEnclave", type: "bytes32"},
        {name: "mrImage", type: "bytes32"}
      ],
      name: "bootInfo",
      type: "tuple"
    }],
    name: "isAppAllowed",
    outputs: [
      {name: "allowed", type: "bool"},
      {name: "reason", type: "string"}
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "kmsAppId",
    outputs: [{name: "appId", type: "address"}],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{name: "appId", type: "address"}],
    name: "appController",
    outputs: [{name: "", type: "address"}],
    stateMutability: "view",
    type: "function"
  }
] as const;

export const APP_CONTRACT_ABI = [
  {
    inputs: [{
      components: [
        {name: "appId", type: "address"},
        {name: "composeHash", type: "bytes32"},
        {name: "instanceId", type: "address"},
        {name: "deviceId", type: "bytes32"},
        {name: "mrEnclave", type: "bytes32"},
        {name: "mrImage", type: "bytes32"}
      ],
      name: "bootInfo",
      type: "tuple"
    }],
    name: "isAppAllowed",
    outputs: [
      {name: "allowed", type: "bool"},
      {name: "reason", type: "string"}
    ],
    stateMutability: "view",
    type: "function"
  }
] as const;
