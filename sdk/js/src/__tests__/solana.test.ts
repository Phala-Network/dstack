import { expect, describe, it } from 'vitest'
import { Keypair } from '@solana/web3.js'

import { TappdClient } from '../index'
import { toKeypair } from '../solana'

describe('solana support', () => {
  it('should able to get keypair from deriveKey', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const keypair = toKeypair(result)
    expect(keypair).toBeInstanceOf(Keypair)
    console.log(keypair.publicKey.toBase58())
  })
})