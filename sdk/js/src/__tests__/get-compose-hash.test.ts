import { expect, describe, it } from 'vitest'
import { getComposeHash, AppCompose } from '../get-compose-hash'

describe('Deterministic JSON Serialization', () => {
  describe('Key Sorting', () => {
    it('should sort object keys lexicographically', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        bash_script: "start.sh"
      }
      
      const compose2: AppCompose = {
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml",
        runner: "docker-compose"
      }
      
      // Both should produce the same hash despite different key order
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle nested object key sorting', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        nested_config: {
          gamma: 3.14,
          alpha: "first",
          beta: 42
        }
      } as AppCompose
      
      const compose2: AppCompose = {
        nested_config: {
          alpha: "first",
          beta: 42,
          gamma: 3.14
        },
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle deeply nested objects', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        config: {
          database: {
            port: 5432,
            host: "localhost",
            credentials: {
              username: "admin",
              password: "secret"
            }
          },
          cache: {
            redis: {
              url: "redis://localhost:6379",
              timeout: 1000
            }
          }
        }
      } as AppCompose
      
      const compose2: AppCompose = {
        config: {
          cache: {
            redis: {
              timeout: 1000,
              url: "redis://localhost:6379"
            }
          },
          database: {
            credentials: {
              password: "secret",
              username: "admin"
            },
            host: "localhost",
            port: 5432
          }
        },
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Array Handling', () => {
    it('should preserve array order', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        items: [3, 1, 2]
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        items: [1, 2, 3]
      } as AppCompose
      
      // Different array orders should produce different hashes
      expect(getComposeHash(compose1)).not.toBe(getComposeHash(compose2))
    })

    it('should handle arrays with objects', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        services: [
          { name: "web", port: 80 },
          { name: "db", port: 5432 }
        ]
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        services: [
          { port: 80, name: "web" },
          { port: 5432, name: "db" }
        ]
      } as AppCompose
      
      // Object keys should be sorted within arrays
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Special Value Handling', () => {
    it('should convert NaN to null', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        special_value: NaN
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
      expect(hash).toHaveLength(64) // SHA256 hex length
    })

    it('should convert Infinity to null', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        special_value: Infinity
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        special_value: -Infinity
      } as AppCompose
      
      const compose3: AppCompose = {
        runner: "docker-compose",
        special_value: null
      }
      
      // All should produce the same hash since NaN and Infinity become null
      const hash1 = getComposeHash(compose1)
      const hash2 = getComposeHash(compose2)
      const hash3 = getComposeHash(compose3)
      
      expect(hash1).toBe(hash2)
      expect(hash2).toBe(hash3)
    })

    it('should handle undefined values', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        optional_field: undefined
      } as AppCompose
      
      const compose2: AppCompose = {
        runner: "docker-compose"
      }
      
      // undefined values should be treated consistently
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Preprocessing Logic', () => {
    it('should remove docker_compose_file when runner is bash', () => {
      const compose: AppCompose = {
        runner: "bash",
        bash_script: "start.sh",
        docker_compose_file: "docker-compose.yml"
      }
      
      const hash = getComposeHash(compose)
      
      // Should be the same as compose without docker_compose_file
      const compose2: AppCompose = {
        runner: "bash",
        bash_script: "start.sh"
      }
      
      expect(hash).toBe(getComposeHash(compose2))
    })

    it('should remove bash_script when runner is docker-compose', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        bash_script: "start.sh"
      }
      
      const hash = getComposeHash(compose)
      
      // Should be the same as compose without bash_script
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(hash).toBe(getComposeHash(compose2))
    })

    it('should remove empty pre_launch_script', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        pre_launch_script: ""
      }
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should keep non-empty pre_launch_script', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        pre_launch_script: "echo 'Starting...'"
      }
      
      const compose2: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      expect(getComposeHash(compose1)).not.toBe(getComposeHash(compose2))
    })
  })

  describe('UTF-8 Support', () => {
    it('should handle non-ASCII characters consistently', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        text: "你好世界",
        description: "🚀 Deploy"
      } as AppCompose
      
      const compose2: AppCompose = {
        description: "🚀 Deploy",
        runner: "docker-compose",
        text: "你好世界"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })
  })

  describe('Cross-Language Compatibility Example', () => {
    it('should produce consistent hash for reference data', () => {
      // This is a reference test case that should produce the same hash
      // as equivalent implementations in Go and Python
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        text: "你好世界",
        id: "c73a3a4e-ce71-4c12-a1b7-78be1a2e48e0",
        b_number: 123,
        a_status: true,
        z_items: [3, 1, 2],
        nested: {
          gamma: 3.14,
          alpha: "first"
        }
      } as AppCompose
      
      const hash = getComposeHash(compose)
      
      // This should be a deterministic hash
      expect(hash).toHaveLength(64)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
      
      // The exact hash value depends on the specific data structure
      // but it should be consistent across runs
      const hash2 = getComposeHash(compose)
      expect(hash).toBe(hash2)
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty objects', () => {
      const compose: AppCompose = {}
      const hash = getComposeHash(compose)
      
      expect(hash).toHaveLength(64)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
    })

    it('should handle null values', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        optional_field: null
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
    })

    it('should handle boolean values', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        enabled: true,
        debug: false
      } as AppCompose
      
      const compose2: AppCompose = {
        debug: false,
        enabled: true,
        runner: "docker-compose"
      } as AppCompose
      
      expect(getComposeHash(compose1)).toBe(getComposeHash(compose2))
    })

    it('should handle numeric edge cases', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        zero: 0,
        negative: -42,
        float: 3.14159,
        large: 1e10
      } as AppCompose
      
      const hash = getComposeHash(compose)
      expect(hash).toBeDefined()
    })
  })

  describe('Determinism Verification', () => {
    it('should produce identical hashes for multiple calls', () => {
      const compose: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml",
        environment: {
          NODE_ENV: "production",
          PORT: 3000,
          DATABASE_URL: "postgres://localhost:5432/mydb"
        }
      } as AppCompose
      
      const hashes = Array.from({ length: 10 }, () => getComposeHash(compose))
      
      // All hashes should be identical
      const firstHash = hashes[0]
      expect(hashes.every(hash => hash === firstHash)).toBe(true)
    })

    it('should produce different hashes for different data', () => {
      const compose1: AppCompose = {
        runner: "docker-compose",
        docker_compose_file: "docker-compose.yml"
      }
      
      const compose2: AppCompose = {
        runner: "bash",
        bash_script: "start.sh"
      }
      
      expect(getComposeHash(compose1)).not.toBe(getComposeHash(compose2))
    })
  })
}) 