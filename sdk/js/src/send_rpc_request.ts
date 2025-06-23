import http from 'http'
import https from 'https'
import net from 'net'

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