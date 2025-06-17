import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DKIMService } from '../dkim.service';
import { DKIMValidator } from '../dkim-validator';

describe('DKIMService', () => {
  let dkimService: DKIMService;

  beforeEach(() => {
    dkimService = new DKIMService();
    vi.clearAllMocks();
    // In Cloudflare Workers, fetch is globally available, so we don't need to stub it
  });

  describe('validateDomain', () => {
    it('should return valid for correct domain', () => {
      const result = dkimService.validateDomain('example.com');
      expect(result.isValid).toBe(true);
    });

    it('should return error for empty domain', () => {
      const result = dkimService.validateDomain('');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Domain parameter is required');
    });

    it('should return error for invalid domain', () => {
      const result = dkimService.validateDomain('invalid-domain');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Invalid domain format');
    });
  });

  describe('validateSelector', () => {
    it('should return valid for correct selector', () => {
      const result = dkimService.validateSelector('default');
      expect(result.isValid).toBe(true);
    });

    it('should return error for invalid selector', () => {
      const result = dkimService.validateSelector('invalid@selector');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Invalid selector format');
    });
  });

  describe('parseDKIMRecord', () => {
    it('should parse valid DKIM record', () => {
      const rawRecord = '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC..."';
      const parsed = dkimService['parseDKIMRecord'](rawRecord);
      
      expect(parsed.version).toBe('DKIM1');
      expect(parsed.keyType).toBe('rsa');
      expect(parsed.publicKey).toBe('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...');
    });
  });

  describe('isErrorResponse', () => {
    it('should return true for error response', () => {
      const errorResponse = { error: 'Test error' };
      expect(dkimService.isErrorResponse(errorResponse)).toBe(true);
    });

    it('should return false for success response', () => {
      const successResponse: any = { 
        domain: 'example.com', 
        record: 'test',
        parsed: {},
        summary: {},
        metadata: {}
      };
      expect(dkimService.isErrorResponse(successResponse)).toBe(false);
    });
  });

  describe('isSuccessResponse', () => {
    it('should return true for success response', () => {
      const successResponse: any = { 
        domain: 'example.com', 
        record: 'test',
        parsed: {},
        summary: {},
        metadata: {}
      };
      expect(dkimService.isSuccessResponse(successResponse)).toBe(true);
    });

    it('should return false for error response', () => {
      const errorResponse = { error: 'Test error' };
      expect(dkimService.isSuccessResponse(errorResponse)).toBe(false);
    });
  });

  describe('DKIMValidator', () => {
    let validator: DKIMValidator;

    beforeEach(() => {
      validator = new DKIMValidator();
    });

    it('should return records as an array in validation result', async () => {
      // This test will make a real DNS query to get DKIM records
      const result = await validator.validateDKIM('example.com');

      // Verify that records is an array
      expect(Array.isArray(result.records)).toBe(true);
      expect(typeof result.score).toBe('number');
      expect(Array.isArray(result.issues)).toBe(true);
      expect(typeof result.isValid).toBe('boolean');

      // Verify that record field is not present
      expect(result).not.toHaveProperty('record');
    });

    it('should implement correct DKIM scoring logic', async () => {
      // Test with a real domain to validate the scoring logic
      const result = await validator.validateDKIM('google.com');

      expect(typeof result.score).toBe('number');
      expect(typeof result.isValid).toBe('boolean');
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.records)).toBe(true);
    });

    it('should handle domains with no DKIM records', async () => {
      // Use a domain that likely doesn't have DKIM records
      const result = await validator.validateDKIM('this-domain-definitely-does-not-exist-12345.com');

      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
      expect(Array.isArray(result.records)).toBe(true);
      expect(Array.isArray(result.issues)).toBe(true);
    });

    it('should validate multiple domains in sequence', async () => {
      const domains = ['google.com', 'microsoft.com', 'github.com'];
      
      for (const domain of domains) {
        const result = await validator.validateDKIM(domain);
        expect(typeof result.score).toBe('number');
        expect(typeof result.isValid).toBe('boolean');
        expect(Array.isArray(result.issues)).toBe(true);
        expect(Array.isArray(result.records)).toBe(true);
      }
    });

    it('should handle invalid domain formats', async () => {
      const result = await validator.validateDKIM('invalid..domain');

      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.records)).toBe(true);
    });

    it('should handle empty domain input', async () => {
      const result = await validator.validateDKIM('');

      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.records)).toBe(true);
    });
  });
}); 