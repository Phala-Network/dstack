import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'
import { toViemAccount } from '../viem'

// const endpoint = '../../tappd.sock'
const endpoint = 'http://127.0.0.1:8090'

describe('viem support', () => {
  it('should able to get account from deriveKey', async () => {
    const client = new TappdClient(endpoint)
    const result = await client.deriveKey('/', 'test')
    const account =  toViemAccount(result)

    expect(account.source).toBe('privateKey')
    expect(typeof account.sign).toBe('function')
    expect(typeof account.signMessage).toBe('function')
  })
})
