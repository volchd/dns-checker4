import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DKIMService } from '../dkim.service';
import { DKIMValidator } from '../dkim-validator';

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

  describe('DKIMValidator', () => {
    let validator: DKIMValidator;

    beforeEach(() => {
      validator = new DKIMValidator();
    });

    it('should return records as an array in validation result', async () => {
      // Mock the DKIM service to return some test records
      const mockRecords = [
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            hashAlgorithms: ['sha256'],
            flags: []
          },
          selector: 'default'
        }
      ];

      // Mock the getAllDKIMRecords method
      const originalGetAllDKIMRecords = validator['dkimService'].getAllDKIMRecords;
      validator['dkimService'].getAllDKIMRecords = async () => mockRecords;

      const result = await validator.validateDKIM('example.com');

      // Verify that records is an array
      expect(Array.isArray(result.records)).toBe(true);
      expect(result.records).toHaveLength(1);
      expect(result.records[0]).toEqual({
        raw: mockRecords[0].raw,
        parsed: mockRecords[0].parsed,
        selector: mockRecords[0].selector
      });

      // Verify that record field is not present
      expect(result).not.toHaveProperty('record');

      // Restore original method
      validator['dkimService'].getAllDKIMRecords = originalGetAllDKIMRecords;
    });

    it('should implement correct DKIM scoring logic', async () => {
      // Use a real 2048-bit base64-encoded public key
      // Test 1: No DKIM records (0 points)
      const noRecords: any[] = [];
      let score = validator['calculateScore'](noRecords, []);
      expect(score.dkimImplemented).toBe(0);
      expect(score.keyLength).toBe(0);
      expect(score.multipleSelectors).toBe(0);
      expect(score.noTestMode).toBe(0);
      expect(score.total).toBe(0);

      // Test 2: Single 2048-bit key, no test mode (10 + 5 + 0 + 2 = 17 points)
      const single2048Record = [{
        raw: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9RpjsxaBXR9r7OAU6U8/zn92ivImI75naUujWbItRI/QmL1jy5PWGqLwoUA0b90ObWaLDc+i9MtTNmGeWO009hr20fIxhGg6XBT2kjZ1DTThopSe1nAndsupmcBwlQ5Q6LJ+ZAxLcujnPIxM0ZBLmgpkv8u6RfY4eFP8OLvdAW3oSuB0DyLDigQX4Sj8wBO4YIdQH6AAmBeOsidsKAFNFUCpc3vCxtBDR12U+cBg724l3sBkMQ8evnz6idnqxq9QAVYh8k4kJ+RP+6cqTdy7LjIm8xY/bQNpQIpGUAuDo2DjLcCDun9DAI4Q/3z+Q0o9QuQIDAQAB',
        parsed: {
          version: 'DKIM1',
          keyType: 'rsa',
          publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9RpjsxaBXR9r7OAU6U8/zn92ivImI75naUujWbItRI/QmL1jy5PWGqLwoUA0b90ObWaLDc+i9MtTNmGeWO009hr20fIxhGg6XBT2kjZ1DTThopSe1nAndsupmcBwlQ5Q6LJ+ZAxLcujnPIxM0ZBLmgpkv8u6RfY4eFP8OLvdAW3oSuB0DyLDigQX4Sj8wBO4YIdQH6AAmBeOsidsKAFNFUCpc3vCxtBDR12U+cBg724l3sBkMQ8evnz6idnqxq9QAVYh8k4kJ+RP+6cqTdy7LjIm8xY/bQNpQIpGUAuDo2DjLcCDun9DAI4Q/3z+Q0o9QuQIDAQAB',
          flags: []
        },
        selector: 'default'
      }];
      score = validator['calculateScore'](single2048Record, []);
      expect(score.dkimImplemented).toBe(10);
      expect(score.keyLength).toBe(5);
      expect(score.multipleSelectors).toBe(0);
      expect(score.noTestMode).toBe(2);
      expect(score.total).toBe(17);

      // Test 3: Single 1024-bit key, no test mode (10 + 3 + 0 + 2 = 15 points)
      const single1024Record = [{
        raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
        parsed: {
          version: 'DKIM1',
          keyType: 'rsa',
          publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          flags: []
        },
        selector: 'default'
      }];
      score = validator['calculateScore'](single1024Record, []);
      expect(score.dkimImplemented).toBe(10);
      expect(score.keyLength).toBe(3);
      expect(score.multipleSelectors).toBe(0);
      expect(score.noTestMode).toBe(2);
      expect(score.total).toBe(15);

      // Test 4: Multiple selectors, 2048-bit keys, no test mode (10 + 3 + 3 + 2 = 18 points)
      const multipleRecords = [
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            flags: []
          },
          selector: 'default'
        },
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            flags: []
          },
          selector: 'selector2'
        }
      ];
      score = validator['calculateScore'](multipleRecords, []);
      expect(score.dkimImplemented).toBe(10);
      expect(score.keyLength).toBe(3);
      expect(score.multipleSelectors).toBe(3);
      expect(score.noTestMode).toBe(2);
      expect(score.total).toBe(18);

      // Test 5: Test mode flag present (10 + 3 + 3 + 0 = 16 points)
      const testModeRecords = [
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            flags: ['y']
          },
          selector: 'default'
        },
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            flags: []
          },
          selector: 'selector2'
        }
      ];
      score = validator['calculateScore'](testModeRecords, []);
      expect(score.dkimImplemented).toBe(10);
      expect(score.keyLength).toBe(3);
      expect(score.multipleSelectors).toBe(3);
      expect(score.noTestMode).toBe(0); // Test mode flag present
      expect(score.total).toBe(16);

      // Test 6: Insecure key (<1024 bits) caps score at 0 for key length
      const insecureRecords = [
        {
          raw: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VJTUt9Us8cKxMzAyOiHtuiAs0ohRHpk6F1Mk1pxR5xuWjEjLfRqoP6AdXmuR+sU+POk3A1WqOBeuefe1C2WPEa6lQMSxJpkS7ontCvyqpkdL641pLU93tZA0VZxJ0W6jZk1C1KnRbKcnmyqdp5JJdR1qSP5a2SI6hdRk0gQIDAQAB',
            flags: []
          },
          selector: 'default'
        },
        {
          raw: 'v=DKIM1; k=rsa; p=short',
          parsed: {
            version: 'DKIM1',
            keyType: 'rsa',
            publicKey: 'short', // This will be <1024 bits
            flags: []
          },
          selector: 'selector2'
        }
      ];
      score = validator['calculateScore'](insecureRecords, []);
      expect(score.dkimImplemented).toBe(10);
      expect(score.keyLength).toBe(0); // Capped at 0 due to insecure key
      expect(score.multipleSelectors).toBe(3);
      expect(score.noTestMode).toBe(2);
      expect(score.total).toBe(15);
    });
  });
}); 