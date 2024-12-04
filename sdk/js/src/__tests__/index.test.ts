import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'

// const endpoint = '../../tappd.sock'
const endpoint = 'http://127.0.0.1:8090'

describe('TappdClient', () => {
  it('should able to derive key', async () => {
    const client = new TappdClient(endpoint)
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient(endpoint)
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient(endpoint)
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new TappdClient(endpoint)
    const result = await client.deriveKey('/', 'test')
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })
})
