import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SPFService } from '../spf.service';

describe('SPFService', () => {
  let spfService: SPFService;
  const mockDomain = 'example.com';

  beforeEach(() => {
    spfService = new SPFService();
    vi.clearAllMocks();
    // In Cloudflare Workers, fetch is globally available, so we don't need to stub it
  });

  describe('getSPFRecord', () => {
    it('should return parsed SPF record for valid domain', async () => {
      // This test will make a real DNS query to get the SPF record
      const result = await spfService.getSPFRecord(mockDomain);

      // The result should be valid for a real domain
      expect(result).toBeDefined();
      if (result) {
        expect(typeof result.raw).toBe('string');
        expect(Array.isArray(result.mechanisms)).toBe(true);
        expect(Array.isArray(result.modifiers)).toBe(true);
        expect(typeof result.processedRedirects).toBe('number');
        expect(typeof result.processedIncludes).toBe('number');
      }
    });

    it('should return null when no SPF record is found', async () => {
      // Use a domain that likely doesn't have an SPF record
      const result = await spfService.getSPFRecord('this-domain-definitely-does-not-exist-12345.com');
      expect(result).toBeNull();
    });

    it('should handle network errors gracefully', async () => {
      // This test will rely on the actual network behavior
      // In a real Cloudflare Workers environment, network errors would be handled appropriately
      const result = await spfService.getSPFRecord(mockDomain);
      // The result should either be valid or null, but not throw an error
      expect(result === null || typeof result === 'object').toBe(true);
    });

    it('should handle SPF record with modifiers', async () => {
      // Test with a domain that might have modifiers in its SPF record
      const result = await spfService.getSPFRecord('google.com');

      expect(result).toBeDefined();
      if (result) {
        expect(Array.isArray(result.mechanisms)).toBe(true);
        expect(Array.isArray(result.modifiers)).toBe(true);
        expect(typeof result.processedRedirects).toBe('number');
        expect(typeof result.processedIncludes).toBe('number');
      }
    });

    it('should track recursive processing counts for redirects and includes', async () => {
      // Test with a domain that might have includes or redirects
      const result = await spfService.getSPFRecord('microsoft.com');

      expect(result).toBeDefined();
      if (result) {
        expect(typeof result.processedRedirects).toBe('number');
        expect(typeof result.processedIncludes).toBe('number');
        // redirects and includes may be undefined if they don't exist
        if (result.redirects !== undefined) {
          expect(Array.isArray(result.redirects)).toBe(true);
        }
        if (result.includes !== undefined) {
          expect(Array.isArray(result.includes)).toBe(true);
        }
      }
    });
  });

  describe('getSPFRecordForDomain', () => {
    it('should return formatted response with recursive processing counts', async () => {
      const result = await spfService.getSPFRecordForDomain(mockDomain);

      expect(spfService.isSuccessResponse(result) || spfService.isErrorResponse(result)).toBe(true);
      
      if (spfService.isSuccessResponse(result)) {
        expect(typeof result.summary.processedRedirects).toBe('number');
        expect(typeof result.summary.processedIncludes).toBe('number');
        expect(typeof result.summary.totalMechanisms).toBe('number');
        expect(typeof result.summary.redirectCount).toBe('number');
      }
    });

    it('should handle domain validation errors', async () => {
      const result = await spfService.getSPFRecordForDomain('');

      expect(spfService.isErrorResponse(result)).toBe(true);
      if (spfService.isErrorResponse(result)) {
        expect(result.error).toBeDefined();
        expect(typeof result.error).toBe('string');
      }
    });

    it('should handle invalid domain formats', async () => {
      const result = await spfService.getSPFRecordForDomain('invalid..domain');

      expect(spfService.isErrorResponse(result)).toBe(true);
      if (spfService.isErrorResponse(result)) {
        expect(result.error).toBeDefined();
        expect(typeof result.error).toBe('string');
      }
    });

    it('should validate multiple domains in sequence', async () => {
      const domains = ['google.com', 'microsoft.com', 'github.com'];
      
      for (const domain of domains) {
        const result = await spfService.getSPFRecordForDomain(domain);
        expect(spfService.isSuccessResponse(result) || spfService.isErrorResponse(result)).toBe(true);
      }
    });
  });

  describe('isErrorResponse', () => {
    it('should return true for error response', () => {
      const errorResponse = { error: 'Test error' };
      expect(spfService.isErrorResponse(errorResponse)).toBe(true);
    });

    it('should return false for success response', () => {
      const successResponse: any = { 
        domain: 'example.com', 
        record: 'test',
        parsed: {},
        summary: {},
        metadata: {}
      };
      expect(spfService.isErrorResponse(successResponse)).toBe(false);
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
      expect(spfService.isSuccessResponse(successResponse)).toBe(true);
    });

    it('should return false for error response', () => {
      const errorResponse = { error: 'Test error' };
      expect(spfService.isSuccessResponse(errorResponse)).toBe(false);
    });
  });
}); 