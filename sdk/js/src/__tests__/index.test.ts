import { expect, describe, it } from 'vitest'
import { TappdClient } from '../index'

describe('TappdClient', () => {
  it('should able to derive key', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    expect(result).toHaveProperty('key')
    expect(result).toHaveProperty('certificate_chain')
  })

  it('should able to request tdx quote', async () => {
    const client = new TappdClient()
    // You can put computation result as report data to tdxQuote. NOTE: it should serializable by JSON.stringify
    const result = await client.tdxQuote('some data or anything can be call by toJSON')
    expect(result).toHaveProperty('quote')
    expect(result).toHaveProperty('event_log')
    expect(result.quote.substring(0, 2)).toBe('0x')
    expect(result.event_log.substring(0, 1) === '{')
    expect(() => JSON.parse(result.event_log)).not.toThrowError()
    expect(result.replayRtmrs().length).toBe(4)
  })

  it('should able to get derive key result as uint8array', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const key = result.asUint8Array()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('should able to get derive key result as uint8array with specified length', async () => {
    const client = new TappdClient()
    const result = await client.deriveKey('/', 'test')
    const full = result.asUint8Array()
    const key = result.asUint8Array(32)
    expect(full).toBeInstanceOf(Uint8Array)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
    expect(key.length).not.eq(full.length)
  })

  it('should able set quote hash_algorithm', async () => {
    const client = new TappdClient()
    const result = await client.tdxQuote('pure string', 'raw')
  })

  it('should throw error on report_data large then 64 characters and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote('0'.padEnd(65, 'x'), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    expect(() => client.tdxQuote(Buffer.alloc(65), 'raw')).rejects.toThrow()
  })

  it('should throw error on report_data large then 128 bytes and using raw hash_algorithm', async () => {
    const client = new TappdClient()
    const input = new Uint8Array(65).fill(0)
    expect(() => client.tdxQuote(input, 'raw')).rejects.toThrow()
  })
})
