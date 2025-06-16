import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DNSValidator } from '../src/services/dns-validator';

describe('DNSValidator', () => {
  let validator: DNSValidator;

  beforeEach(() => {
    validator = new DNSValidator();
    vi.resetAllMocks();
    // Setup fetch mock
    vi.stubGlobal('fetch', vi.fn());
  });

  it('should validate a valid domain that exists', async () => {
    // Mock successful DNS response with NS records
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        Status: 0,
        Answer: [
          {
            name: 'example.com',
            type: 2, // NS record type
            TTL: 172800,
            data: 'ns1.example.com'
          },
          {
            name: 'example.com',
            type: 2,
            TTL: 172800,
            data: 'ns2.example.com'
          }
        ]
      })
    } as Response);

    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(true);
    expect(result.error).toBeUndefined();
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('cloudflare-dns.com/dns-query'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Accept': 'application/dns-json'
        })
      })
    );
  });

  it('should reject an invalid domain format', async () => {
    const result = await validator.validateDNS('invalid..domain');
    expect(result.exists).toBe(false);
    expect(result.error).toBe('Invalid domain format');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('should handle DNS query errors gracefully', async () => {
    // Mock DNS query error response
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue({
      ok: false,
      statusText: 'Bad Request'
    } as Response);

    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(false);
    expect(result.error).toBe('DNS query failed: Bad Request');
  });

  it('should correctly extract root domain from subdomains', async () => {
    // Mock successful DNS response
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        Status: 0,
        Answer: [
          {
            name: 'example.com',
            type: 2,
            TTL: 172800,
            data: 'ns1.example.com'
          }
        ]
      })
    } as Response);

    const result = await validator.validateDNS('sub.example.com');
    expect(result.exists).toBe(true);
    expect(result.error).toBeUndefined();
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('example.com'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Accept': 'application/dns-json'
        })
      })
    );
  });

  it('should handle domains with no NS records', async () => {
    // Mock DNS response with no NS records
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        Status: 0,
        Answer: [
          {
            name: 'example.com',
            type: 1, // A record type
            TTL: 300,
            data: '93.184.216.34'
          }
        ]
      })
    } as Response);

    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it('should handle malformed DNS responses', async () => {
    // Mock malformed DNS response
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        Status: 2, // DNS error status
        Answer: null
      })
    } as Response);

    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(false);
    expect(result.error).toBeUndefined();
  });
}); 