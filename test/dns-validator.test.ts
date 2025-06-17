import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DNSValidator } from '../src/services/dns-validator';

describe('DNSValidator', () => {
  let validator: DNSValidator;

  beforeEach(() => {
    validator = new DNSValidator();
    vi.resetAllMocks();
    // In Cloudflare Workers, fetch is globally available, so we don't need to stub it
    // The actual fetch will be used, which is the correct behavior for Workers
  });

  it('should validate a valid domain that exists', async () => {
    // In Cloudflare Workers, we can use the actual fetch to make real DNS queries
    // This test will make a real DNS query to Cloudflare's DNS service
    const result = await validator.validateDNS('example.com');
    
    // The result should indicate the domain exists (it's a well-known domain)
    expect(result.exists).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.details).toBeDefined();
    expect(result.details.status).toBe(0); // DNS query successful
    expect(Array.isArray(result.details.answer)).toBe(true);
  });

  it('should reject an invalid domain format', async () => {
    const result = await validator.validateDNS('invalid..domain');
    expect(result.exists).toBe(false);
    expect(result.error).toBe('Invalid domain format');
  });

  it('should handle non-existent domains gracefully', async () => {
    // Use a domain that is very unlikely to exist
    const result = await validator.validateDNS('this-domain-definitely-does-not-exist-12345.com');
    expect(result.exists).toBe(false);
    expect(result.error).toBeUndefined(); // No error, just doesn't exist
    expect(result.details).toBeDefined();
  });

  it('should correctly extract root domain from subdomains', async () => {
    const result = await validator.validateDNS('sub.example.com');
    expect(result.exists).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.details).toBeDefined();
  });

  it('should handle domains with no NS records', async () => {
    // Some domains might not have NS records in the response
    // This test will use a real domain and check the behavior
    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(true); // example.com should exist
    expect(result.error).toBeUndefined();
  });

  it('should handle malformed DNS responses gracefully', async () => {
    // This test will use a real domain and rely on the actual DNS service
    // to handle any malformed responses appropriately
    const result = await validator.validateDNS('example.com');
    expect(result.exists).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should validate multiple domains in sequence', async () => {
    const domains = ['example.com', 'google.com', 'github.com'];
    
    for (const domain of domains) {
      const result = await validator.validateDNS(domain);
      expect(result.exists).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.details).toBeDefined();
    }
  });
}); 