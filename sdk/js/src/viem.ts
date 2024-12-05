import { type DeriveKeyResponse } from './index'
import { privateKeyToAccount } from 'viem/accounts'

export function toViemAccount(deriveKeyResponse: DeriveKeyResponse) {
  const hex = Array.from(deriveKeyResponse.asUint8Array(32)).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}
