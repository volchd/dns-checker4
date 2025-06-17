import { describe, it, expect, beforeEach } from 'vitest';
import { ValidateDomainService } from '../validate-domain.service';

describe('ValidateDomainService', () => {
  let service: ValidateDomainService;

  beforeEach(() => {
    service = new ValidateDomainService();
  });

  describe('validateDomainFormat', () => {
    it('should return error for empty domain', () => {
      const result = service['validateDomainFormat']('');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Domain parameter is required');
    });

    it('should return error for invalid domain format', () => {
      const result = service['validateDomainFormat']('invalid-domain-format');
      expect(result.isValid).toBe(false);
      expect(result.error?.error).toBe('Invalid domain format');
    });

    it('should return valid for correct domain format', () => {
      const result = service['validateDomainFormat']('example.com');
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });
  });

  describe('isErrorResponse', () => {
    it('should return true for error response', () => {
      const errorResponse = {
        error: 'Test error',
        timestamp: new Date().toISOString()
      };
      expect(service.isErrorResponse(errorResponse)).toBe(true);
    });

    it('should return false for success response', () => {
      const successResponse = {
        total_score: 100,
        total_max_score: 100,
        spf_result: {} as any,
        kdim_result: {} as any,
        dmarc_result: {} as any
      };
      expect(service.isErrorResponse(successResponse)).toBe(false);
    });
  });

  describe('isSuccessResponse', () => {
    it('should return true for success response', () => {
      const successResponse = {
        total_score: 100,
        total_max_score: 100,
        spf_result: {} as any,
        kdim_result: {} as any,
        dmarc_result: {} as any
      };
      expect(service.isSuccessResponse(successResponse)).toBe(true);
    });

    it('should return false for error response', () => {
      const errorResponse = {
        error: 'Test error',
        timestamp: new Date().toISOString()
      };
      expect(service.isSuccessResponse(errorResponse)).toBe(false);
    });
  });
}); 