import { describe, it, expect } from 'vitest';
import { Base64Validator } from '../base64-validator';

describe('Base64Validator', () => {
  describe('isValid', () => {
    it('should return true for valid base64 strings', () => {
      const validBase64 = 'SGVsbG8gV29ybGQ='; // "Hello World" in base64
      expect(Base64Validator.isValid(validBase64)).toBe(true);
    });

    it('should return true for gene.com valid base64 public key', () => {
      const validBase64Key = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoSfVEgXUbacNuQL8nyexi6E1iCFdbHIMHsgglRcoUK15qNxa7Spwz46G8GjVaMc8dXYo4fb3Bdcnsnn0akaLq8hT/Hfqj0qLh8F7/qe+8/wLSqgGGnb6qu6Uao9g2lgMiNOBirwY8Bw/hqVF0TaX9F+ZDV80vJN5CJ3bQsV9n6nbPv8RO42bX5PEk2aCzkO82UrvPoP58F45A1OcPxridPOp3ONRZW7B4GnWAkvbj9ML9ku/HiPql5+vFJNxEa74Pb6yMliTqMWc9kfCe/M3/uMElWvub4wyBiqnVKeWc32gCTjK+eb5gedJDqEqwN7fgDY7kB+ZgXw/gM3fsGbfWwIDAQAB';
      expect(Base64Validator.isValid(validBase64Key)).toBe(true);
    });
    it('should return true for gene.com 2 valid base64 public key', () => {
      const validBase64Key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCu3jOWkldvK37Pz4Pg295GQfvKYNFVExS9wpKfl9Dxondc4nXI65MibbOVqk2p5k9eJfHqnbANgs16KhSfqWRK7dEOuH0QdsLjB/2b73Zm+ZKlbHUJujtKBM5Y8dPtVnKi0CVQTQFrmoX2zzWxh5HpsJ1SvpYEtY74tVBgbYKrzwIDAQAB';
      expect(Base64Validator.isValid(validBase64Key)).toBe(true);
    });
    it('should return false for invalid base64 strings', () => {
      const invalidBase64 = 'SGVsbG8gV29ybGQ!@#'; // Invalid characters
      expect(Base64Validator.isValid(invalidBase64)).toBe(false);
    });

    it('should return false for null input', () => {
      expect(Base64Validator.isValid(null as any)).toBe(false);
    });

    it('should return false for undefined input', () => {
      expect(Base64Validator.isValid(undefined as any)).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(Base64Validator.isValid('')).toBe(false);
    });

    it('should return false for whitespace-only string', () => {
      expect(Base64Validator.isValid('   ')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(Base64Validator.isValid(123 as any)).toBe(false);
      expect(Base64Validator.isValid({} as any)).toBe(false);
      expect(Base64Validator.isValid([] as any)).toBe(false);
    });
  });

  describe('isValidSilent', () => {
    it('should return true for valid base64 strings without logging', () => {
      const validBase64 = 'SGVsbG8gV29ybGQ='; // "Hello World" in base64
      expect(Base64Validator.isValidSilent(validBase64)).toBe(true);
    });

    it('should return false for invalid base64 strings without logging', () => {
      const invalidBase64 = 'SGVsbG8gV29ybGQ!@#'; // Invalid characters
      expect(Base64Validator.isValidSilent(invalidBase64)).toBe(false);
    });

    it('should return false for null input without logging', () => {
      expect(Base64Validator.isValidSilent(null as any)).toBe(false);
    });

    it('should return false for undefined input without logging', () => {
      expect(Base64Validator.isValidSilent(undefined as any)).toBe(false);
    });

    it('should return false for empty string without logging', () => {
      expect(Base64Validator.isValidSilent('')).toBe(false);
    });

    it('should return false for whitespace-only string without logging', () => {
      expect(Base64Validator.isValidSilent('   ')).toBe(false);
    });

    it('should return false for non-string input without logging', () => {
      expect(Base64Validator.isValidSilent(123 as any)).toBe(false);
      expect(Base64Validator.isValidSilent({} as any)).toBe(false);
      expect(Base64Validator.isValidSilent([] as any)).toBe(false);
    });
  });

  describe('isValidStrict', () => {
    it('should return true for valid base64 strings', () => {
      const validBase64 = 'SGVsbG8gV29ybGQ='; // "Hello World" in base64
      expect(Base64Validator.isValidStrict(validBase64)).toBe(true);
    });

    it('should return false for invalid base64 strings', () => {
      const invalidBase64 = 'SGVsbG8gV29ybGQ!@#'; // Invalid characters
      expect(Base64Validator.isValidStrict(invalidBase64)).toBe(false);
    });

    it('should return false for strings with invalid padding', () => {
      const invalidPadding = 'SGVsbG8gV29ybGQ==='; // Too many padding characters
      expect(Base64Validator.isValidStrict(invalidPadding)).toBe(false);
    });

    it('should return false for strings with invalid characters', () => {
      const invalidChars = 'SGVsbG8gV29ybGQ$'; // Invalid character
      expect(Base64Validator.isValidStrict(invalidChars)).toBe(false);
    });

    it('should return false for null input', () => {
      expect(Base64Validator.isValidStrict(null as any)).toBe(false);
    });

    it('should return false for undefined input', () => {
      expect(Base64Validator.isValidStrict(undefined as any)).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(Base64Validator.isValidStrict('')).toBe(false);
    });

    it('should return false for whitespace-only string', () => {
      expect(Base64Validator.isValidStrict('   ')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(Base64Validator.isValidStrict(123 as any)).toBe(false);
      expect(Base64Validator.isValidStrict({} as any)).toBe(false);
      expect(Base64Validator.isValidStrict([] as any)).toBe(false);
    });
  });
}); 