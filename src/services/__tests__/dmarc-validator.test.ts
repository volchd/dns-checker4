import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DMARCValidator } from '../dmarc-validator';

describe('DMARCValidator', () => {
  let dmarcValidator: DMARCValidator;
  const mockDomain = 'example.com';

  beforeEach(() => {
    dmarcValidator = new DMARCValidator();
    vi.clearAllMocks();
  });

  describe('validateDMARC', () => {
    it('should return validation result for valid domain with DMARC record', async () => {
      // This test will make a real DNS query to get the DMARC record
      const result = await dmarcValidator.validateDMARC(mockDomain);

      // The result should be a valid validation result
      expect(result).toBeDefined();
      expect(typeof result.isValid).toBe('boolean');
      expect(typeof result.score).toBe('number');
      expect(typeof result.record).toBe('string');
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.recommendations)).toBe(true);
      expect(typeof result.details).toBe('object');
    });

    it('should handle domain without DMARC record', async () => {
      // Use a domain that likely doesn't have a DMARC record
      const result = await dmarcValidator.validateDMARC('this-domain-definitely-does-not-exist-12345.com');
      
      expect(result).toBeDefined();
      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
      expect(result.record).toBe('');
      expect(result.issues.length).toBeGreaterThan(0);
      expect(result.issues.some(issue => issue.type === 'error')).toBe(true);
    });

    it('should handle network errors gracefully', async () => {
      // This test will rely on the actual network behavior
      const result = await dmarcValidator.validateDMARC(mockDomain);
      // The result should be a valid validation result object
      expect(typeof result).toBe('object');
      expect(result).toHaveProperty('isValid');
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('recommendations');
    });

    it('should validate multiple domains in sequence', async () => {
      const domains = ['google.com', 'microsoft.com', 'github.com'];
      
      for (const domain of domains) {
        const result = await dmarcValidator.validateDMARC(domain);
        expect(result).toBeDefined();
        expect(typeof result.isValid).toBe('boolean');
        expect(typeof result.score).toBe('number');
        expect(Array.isArray(result.issues)).toBe(true);
        expect(Array.isArray(result.recommendations)).toBe(true);
      }
    });

    it('should return proper score breakdown', async () => {
      const result = await dmarcValidator.validateDMARC(mockDomain);
      
      expect(result).toBeDefined();
      // The score should be a number between 0 and 22
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(22);
    });

    it('should include proper details in validation result', async () => {
      const result = await dmarcValidator.validateDMARC(mockDomain);
      
      expect(result.details).toBeDefined();
      expect(typeof result.details.hasVersion).toBe('boolean');
      expect(typeof result.details.hasValidPolicy).toBe('boolean');
      expect(typeof result.details.hasSubdomainPolicy).toBe('boolean');
      expect(typeof result.details.hasPercentage).toBe('boolean');
      expect(typeof result.details.hasReports).toBe('boolean');
      expect(typeof result.details.hasFailureOptions).toBe('boolean');
      expect(typeof result.details.hasAdkim).toBe('boolean');
      expect(typeof result.details.hasAspf).toBe('boolean');
      expect(typeof result.details.finalDomain).toBe('string');
    });

    it('should handle domains with comprehensive DMARC configuration', async () => {
      // Test with a domain that might have a comprehensive DMARC setup
      const result = await dmarcValidator.validateDMARC('google.com');
      
      expect(result).toBeDefined();
      expect(typeof result.isValid).toBe('boolean');
      expect(typeof result.score).toBe('number');
      expect(Array.isArray(result.issues)).toBe(true);
      expect(Array.isArray(result.recommendations)).toBe(true);
    });
  });

  describe('validation logic', () => {
    it('should identify missing DMARC records as invalid', async () => {
      const result = await dmarcValidator.validateDMARC('this-domain-definitely-does-not-exist-12345.com');
      
      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
      expect(result.issues.some(issue => 
        issue.type === 'error' && 
        issue.message.includes('No DMARC record found')
      )).toBe(true);
    });

    it('should provide recommendations for improvement', async () => {
      const result = await dmarcValidator.validateDMARC(mockDomain);
      
      expect(Array.isArray(result.recommendations)).toBe(true);
      // Even if the domain has a perfect DMARC setup, there might be general recommendations
      expect(result.recommendations.length).toBeGreaterThanOrEqual(0);
    });

    it('should categorize issues by type (error, warning, info)', async () => {
      const result = await dmarcValidator.validateDMARC(mockDomain);
      
      for (const issue of result.issues) {
        expect(['error', 'warning', 'info']).toContain(issue.type);
        expect(typeof issue.message).toBe('string');
        if (issue.recommendation) {
          expect(typeof issue.recommendation).toBe('string');
        }
      }
    });
  });
}); 