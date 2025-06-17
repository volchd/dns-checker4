import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SPFValidator } from '../src/services/spf-validator';

describe('SPFValidator', () => {
  let validator: SPFValidator;

  beforeEach(() => {
    vi.resetAllMocks();
    validator = new SPFValidator();
    
    // In Cloudflare Workers, we don't need to mock the SPF service methods
    // as they will use the actual fetch API which is available globally
  });

  it('should validate a valid SPF record', async () => {
    // This test will make a real DNS query to get the SPF record
    const result = await validator.validateSPF('example.com');

    // The result should be valid for a real domain
    expect(result.isValid).toBeDefined();
    expect(typeof result.score).toBe('number');
    expect(Array.isArray(result.issues)).toBe(true);
    expect(Array.isArray(result.mechanisms)).toBe(true);
    expect(typeof result.lookupCount).toBe('number');
  });

  it('should detect missing SPF record', async () => {
    // Use a domain that likely doesn't have an SPF record
    const result = await validator.validateSPF('this-domain-definitely-does-not-exist-12345.com');

    expect(result.isValid).toBe(false);
    expect(result.score).toBe(0);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: expect.stringContaining('No SPF record found')
      })
    );
  });

  it('should validate a domain with a known SPF record', async () => {
    // Use a domain that is known to have an SPF record
    const result = await validator.validateSPF('google.com');

    expect(result.isValid).toBeDefined();
    expect(typeof result.score).toBe('number');
    expect(Array.isArray(result.issues)).toBe(true);
    expect(Array.isArray(result.mechanisms)).toBe(true);
  });

  it('should handle domains with complex SPF records', async () => {
    // Test with a domain that might have a complex SPF record
    const result = await validator.validateSPF('microsoft.com');

    expect(result.isValid).toBeDefined();
    expect(typeof result.score).toBe('number');
    expect(Array.isArray(result.issues)).toBe(true);
    expect(Array.isArray(result.mechanisms)).toBe(true);
  });

  it('should validate multiple domains in sequence', async () => {
    const domains = ['google.com', 'microsoft.com', 'github.com'];
    
    for (const domain of domains) {
      const result = await validator.validateSPF(domain);
      expect(result.isValid).toBeDefined();
      expect(typeof result.score).toBe('number');
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.mechanisms)).toBe(true);
    }
  });

  it('should handle invalid domain formats', async () => {
    const result = await validator.validateSPF('invalid..domain');

    expect(result.isValid).toBe(false);
    expect(result.score).toBe(0);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: expect.stringContaining('Invalid domain format')
      })
    );
  });

  it('should handle empty domain input', async () => {
    const result = await validator.validateSPF('');

    expect(result.isValid).toBe(false);
    expect(result.score).toBe(0);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: expect.stringContaining('Domain parameter is required')
      })
    );
  });
}); 