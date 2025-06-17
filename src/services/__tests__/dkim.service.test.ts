import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DKIMService } from '../dkim.service';

describe('DKIMService', () => {
  let dkimService: DKIMService;

  beforeEach(() => {
    dkimService = new DKIMService();
    vi.clearAllMocks();
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
}); 