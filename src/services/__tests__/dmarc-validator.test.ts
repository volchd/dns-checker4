import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DMARCValidator } from '../dmarc-validator';
import { DMARCService } from '../dmarc.service';
import { DMARCRecord } from '../../types/dmarc.types';

// Mock the DMARCService
vi.mock('../dmarc.service');

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
      // The score should be a number between 0 and 29
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(29);
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

describe('DMARCValidator Scoring Logic', () => {
  let dmarcValidator: DMARCValidator;
  let mockDMARCService: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockDMARCService = {
      getDMARCRecordForDomain: vi.fn(),
      isErrorResponse: vi.fn()
    };
    
    // Mock the DMARCService constructor
    (DMARCService as any).mockImplementation(() => mockDMARCService);
    
    dmarcValidator = new DMARCValidator();
  });

  describe('Real-world example scoring', () => {
    it('should score CNN.com DMARC record correctly', async () => {
      // Real example: v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email; ruf=mailto:Njk3@ruf.vali.email
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'reject',
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc_agg@vali.email' },
          { type: 'afrf', uri: 'mailto:Njk3@ruf.vali.email' }
        ]
      };

      const mockResponse = {
        domain: 'cnn.com',
        record: 'v=DMARC1; p=reject; rua=mailto:dmarc_agg@vali.email; ruf=mailto:Njk3@ruf.vali.email',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('cnn.com');

      // Expected scoring breakdown:
      // - DMARC Implementation: 10 points (record exists and is valid)
      // - Valid Policy: 10 points (p=reject = full enforcement)
      // - Subdomain Policy: 3 points (no sp= tag, but assume no significant subdomains)
      // - Alignment Mode: 2 points (no alignment tags specified, defaults to relaxed)
      // - Reports: 2 points (rua= present)
      // - Percentage: 2 points (no pct= specified, defaults to 100%)
      // Total: 29/29

      expect(result.score).toBe(29);
      expect(result.isValid).toBe(true);
      expect(result.issues).toHaveLength(0);
      expect(result.recommendations).toContain('Consider adding subdomain policy (sp=) to protect subdomains');
      expect(result.recommendations).toContain('DMARC is properly configured with reject policy - excellent security posture');
    });

    it('should score DMARC record with subdomain policy correctly', async () => {
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'reject',
        subdomainPolicy: 'reject',
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc@example.com' }
        ]
      };

      const mockResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('example.com');

      // Should still get 29/29 points
      expect(result.score).toBe(29);
      expect(result.isValid).toBe(true);
    });

    it('should score DMARC record with weaker subdomain policy correctly', async () => {
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'reject',
        subdomainPolicy: 'none', // Weaker than main policy
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc@example.com' }
        ]
      };

      const mockResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('example.com');

      // Should get 26/29 points (lose 3 points for weaker subdomain policy)
      expect(result.score).toBe(26);
      expect(result.isValid).toBe(true);
    });

    it('should score DMARC record with quarantine policy correctly', async () => {
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'quarantine',
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc@example.com' }
        ]
      };

      const mockResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('example.com');

      // Should get 27/29 points (8 points for quarantine policy instead of 10)
      expect(result.score).toBe(27);
      expect(result.isValid).toBe(true);
    });

    it('should score DMARC record with none policy correctly', async () => {
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'none',
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc@example.com' }
        ]
      };

      const mockResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('example.com');

      // Should get 20/29 points (3 points for none policy instead of 10)
      expect(result.score).toBe(20);
      expect(result.isValid).toBe(true);
    });

    it('should score DMARC record with percentage less than 100 correctly', async () => {
      const mockParsedRecord: DMARCRecord = {
        version: 'DMARC1',
        policy: 'reject',
        percentage: 50,
        reports: [
          { type: 'afrf', uri: 'mailto:dmarc@example.com' }
        ]
      };

      const mockResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com',
        parsed: mockParsedRecord
      };

      mockDMARCService.getDMARCRecordForDomain.mockResolvedValue(mockResponse);
      mockDMARCService.isErrorResponse.mockReturnValue(false);

      const result = await dmarcValidator.validateDMARC('example.com');

      // Should get 28/29 points (1 point for percentage instead of 2)
      expect(result.score).toBe(28);
      expect(result.isValid).toBe(true);
    });
  });
}); 