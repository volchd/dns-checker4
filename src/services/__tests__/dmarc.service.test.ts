import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DMARCService } from '../dmarc.service';
import { DMARCRecord } from '../../types/dmarc.types';

// Mock fetch globally
global.fetch = vi.fn();

describe('DMARCService', () => {
  let dmarcService: DMARCService;

  beforeEach(() => {
    dmarcService = new DMARCService();
    vi.clearAllMocks();
  });

  describe('validateDomain', () => {
    it('should return error for empty domain', () => {
      const result = dmarcService.validateDomain('');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Domain parameter is required');
    });

    it('should return error for invalid domain format', () => {
      const result = dmarcService.validateDomain('invalid-domain');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Invalid domain format');
    });

    it('should return valid for correct domain', () => {
      const result = dmarcService.validateDomain('example.com');
      expect(result.isValid).toBe(true);
    });
  });

  describe('parseDMARCRecord', () => {
    it('should parse a valid DMARC record', () => {
      const rawRecord = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com';
      const parsed = dmarcService['parseDMARCRecord'](rawRecord);
      
      expect(parsed.version).toBe('DMARC1');
      expect(parsed.policy).toBe('reject');
      expect(parsed.reports).toHaveLength(1);
      expect(parsed.reports![0].type).toBe('afrf');
      expect(parsed.reports![0].uri).toBe('mailto:dmarc@example.com');
    });

    it('should parse DMARC record with all fields', () => {
      const rawRecord = 'v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; fo=1; adkim=r; aspf=s';
      const parsed = dmarcService['parseDMARCRecord'](rawRecord);
      
      expect(parsed.version).toBe('DMARC1');
      expect(parsed.policy).toBe('quarantine');
      expect(parsed.subdomainPolicy).toBe('reject');
      expect(parsed.percentage).toBe(25);
      expect(parsed.reports).toHaveLength(2);
      expect(parsed.failureOptions).toEqual(['1']);
      expect(parsed.adkim).toBe('r');
      expect(parsed.aspf).toBe('s');
    });
  });

  describe('formatDMARCResponse', () => {
    it('should format DMARC response correctly', () => {
      const domain = 'example.com';
      const dmarcRecord = {
        raw: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
        parsed: {
          version: 'DMARC1',
          policy: 'reject' as const,
          reports: [{
            type: 'afrf' as const,
            uri: 'mailto:dmarc@example.com'
          }]
        } as DMARCRecord
      };

      const response = dmarcService.formatDMARCResponse(domain, dmarcRecord);
      
      expect(response.domain).toBe(domain);
      expect(response.record).toBe(dmarcRecord.raw);
      expect(response.parsed).toEqual(dmarcRecord.parsed);
      expect(response.summary.hasVersion).toBe(true);
      expect(response.summary.hasValidPolicy).toBe(true);
      expect(response.summary.policy).toBe('reject');
      expect(response.summary.reportCount).toBe(1);
      expect(response.metadata).toBeDefined();
    });
  });

  describe('error responses', () => {
    it('should create not found error', () => {
      const error = dmarcService.createNotFoundError('example.com');
      expect(error.error).toBe('No DMARC record found for the domain');
      expect(error.domain).toBe('example.com');
    });

    it('should create multiple records error', () => {
      const error = dmarcService.createMultipleRecordsError('example.com');
      expect(error.error).toBe('Multiple DMARC records found for the domain');
      expect(error.domain).toBe('example.com');
    });
  });

  describe('type guards', () => {
    it('should identify error responses', () => {
      const errorResponse = {
        error: 'Test error',
        domain: 'example.com'
      };
      expect(dmarcService.isErrorResponse(errorResponse)).toBe(true);
      expect(dmarcService.isSuccessResponse(errorResponse)).toBe(false);
    });

    it('should identify success responses', () => {
      const successResponse = {
        domain: 'example.com',
        record: 'v=DMARC1; p=reject',
        parsed: { version: 'DMARC1', policy: 'reject' as const },
        summary: {
          hasVersion: true,
          hasValidPolicy: true,
          hasSubdomainPolicy: false,
          hasPercentage: false,
          hasReports: false,
          hasFailureOptions: false,
          hasAdkim: false,
          hasAspf: false,
          policy: 'reject',
          reportCount: 0
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: 'test',
          processingTime: 0
        }
      };
      expect(dmarcService.isSuccessResponse(successResponse)).toBe(true);
      expect(dmarcService.isErrorResponse(successResponse)).toBe(false);
    });
  });
}); 