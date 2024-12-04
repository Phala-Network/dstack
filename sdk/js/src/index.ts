import net from 'net'
import crypto from 'crypto'
import http from 'http'
import https from 'https'
import { URL } from 'url'

export interface DeriveKeyResponse {
  key: string
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
}

export type Hex = `0x${string}`

export interface TdxQuoteResponse {
  quote: Hex
  event_log: string
}

function x509key_to_uint8array(pem: string, max_length?: number) {
  const content = pem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\n/g, '')
  const binaryDer = atob(content)
  if (!max_length) {
    max_length = binaryDer.length
  }
  const result = new Uint8Array(max_length)
  for (let i = 0; i < max_length; i++) {
    result[i] = binaryDer.charCodeAt(i)
  }
  return result
}

export function send_rpc_request<T = any>(endpoint: string, path: string, payload: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const abortController = new AbortController()
    const timeout = setTimeout(() => {
      abortController.abort()
      reject(new Error('Request timed out'))
    }, 30_000) // 30 seconds timeout

    const isHttp = endpoint.startsWith('http://') || endpoint.startsWith('https://')

    if (isHttp) {
      const url = new URL(path, endpoint)
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      }

      const req = (url.protocol === 'https:' ? https : http).request(url, options, (res) => {
        let data = ''
        res.on('data', (chunk) => {
          data += chunk
        })
        res.on('end', () => {
          clearTimeout(timeout)
          try {
            const result = JSON.parse(data)
            resolve(result as T)
          } catch (error) {
            reject(new Error('Failed to parse response'))
          }
        })
      })

      req.on('error', (error) => {
        clearTimeout(timeout)
        reject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        req.destroy()
        reject(new Error('Request aborted'))
      })

      req.write(payload)
      req.end()
    } else {
      const client = net.createConnection({ path: endpoint }, () => {
        client.write(`POST ${path} HTTP/1.1\r\n`)
        client.write(`Host: localhost\r\n`)
        client.write(`Content-Type: application/json\r\n`)
        client.write(`Content-Length: ${payload.length}\r\n`)
        client.write('\r\n')
        client.write(payload)
      })

      let data = ''
      let headers: Record<string, string> = {}
      let headersParsed = false
      let contentLength = 0
      let bodyData = ''

      client.on('data', (chunk) => {
        data += chunk
        if (!headersParsed) {
          const headerEndIndex = data.indexOf('\r\n\r\n')
          if (headerEndIndex !== -1) {
            const headerLines = data.slice(0, headerEndIndex).split('\r\n')
            headerLines.forEach(line => {
              const [key, value] = line.split(': ')
              if (key && value) {
                headers[key.toLowerCase()] = value
              }
            })
            headersParsed = true
            contentLength = parseInt(headers['content-length'] || '0', 10)
            bodyData = data.slice(headerEndIndex + 4)
          }
        } else {
          bodyData += chunk
        }

        if (headersParsed && bodyData.length >= contentLength) {
          client.end()
        }
      })

      client.on('end', () => {
        clearTimeout(timeout)
        try {
          const result = JSON.parse(bodyData.slice(0, contentLength))
          resolve(result as T)
        } catch (error) {
          reject(new Error('Failed to parse response'))
        }
      })

      client.on('error', (error) => {
        clearTimeout(timeout)
        reject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        client.destroy()
        reject(new Error('Request aborted'))
      })
    }
  })
}

export class TappdClient {
  private endpoint: string

  constructor(endpoint: string = '/var/run/tappd.sock') {
    if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
      console.log(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
      endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
    }
    this.endpoint = endpoint
  }

  async deriveKey(path: string, subject: string): Promise<DeriveKeyResponse> {
    const payload = JSON.stringify({ path, subject })
    const result = await send_rpc_request<DeriveKeyResponse>(this.endpoint, '/prpc/Tappd.DeriveKey', payload)
    Object.defineProperty(result, 'asUint8Array', {
      get: () => (length?: number) => x509key_to_uint8array(result.key, length),
      enumerable: true,
      configurable: false,
    })
    return Object.freeze(result)
  }

  async tdxQuote(report_data: string | Buffer | Uint8Array): Promise<TdxQuoteResponse> {
    let hashInput: Buffer
    if (typeof report_data === 'string') {
      hashInput = Buffer.from(report_data)
    } else if (report_data instanceof Uint8Array) {
      hashInput = Buffer.from(report_data)
    } else {
      hashInput = report_data
    }
    const hash = crypto.createHash('sha384').update(hashInput).digest('hex')
    const payload = JSON.stringify({ report_data: `0x${hash}` })
    const result = await send_rpc_request<TdxQuoteResponse>(this.endpoint, '/prpc/Tappd.TdxQuote', payload)
    return Object.freeze(result)
  }
}
