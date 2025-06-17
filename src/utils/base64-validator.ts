/**
 * Base64 Validator Utility
 * 
 * This utility class provides base64 encoding validation functionality.
 * It can be used across different parts of the application that need
 * to validate base64-encoded strings.
 */
export class Base64Validator {
  /**
   * Validates if a string is properly base64 encoded
   * 
   * This method attempts to decode the string as base64 and returns true
   * if successful, false otherwise. It handles various edge cases including
   * null/undefined values, non-string inputs, and empty strings.
   * 
   * @param str - The string to validate as base64
   * @returns boolean - True if valid base64, false otherwise
   */
  static isValid(str: string): boolean {
    // Handle edge cases first
    if (str == null || str === undefined) {
      console.log('[Base64 Validator] isValid: Input is null/undefined');
      return false;
    }
    
    if (typeof str !== 'string') {
      console.log(`[Base64 Validator] isValid: Input is not a string, type: ${typeof str}`);
      return false;
    }
    
    if (str.trim() === '') {
      console.log('[Base64 Validator] isValid: Input is empty or whitespace only');
      return false;
    }

    console.log(`[Base64 Validator] isValid called with:`, {
      input: str.substring(0, 50) + '...',
      length: str.length,
      type: typeof str
    });
    
    // Use strict validation to catch invalid characters
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      console.log(`[Base64 Validator] isValid: Invalid base64 characters detected`);
      return false;
    }

    // Check padding
    const paddingCount = (str.match(/=/g) || []).length;
    if (paddingCount > 2 || (paddingCount > 0 && str.length % 4 !== 0)) {
      console.log(`[Base64 Validator] isValid: Invalid padding detected`);
      return false;
    }
    
    try {
      // Check if the string can be decoded as base64 using atob (available in Workers)
      const decoded = atob(str);
      console.log(`[Base64 Validator] isValid: Successfully decoded ${decoded.length} bytes`);
      return true;
    } catch (error) {
      console.log(`[Base64 Validator] isValid: Decode failed - ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  /**
   * Validates if a string is properly base64 encoded (without logging)
   * 
   * This is a silent version of the isValid method that doesn't produce
   * console output, useful for performance-critical scenarios or when
   * logging is not desired.
   * 
   * @param str - The string to validate as base64
   * @returns boolean - True if valid base64, false otherwise
   */
  static isValidSilent(str: string): boolean {
    // Handle edge cases
    if (str == null || str === undefined) {
      return false;
    }
    
    if (typeof str !== 'string') {
      return false;
    }
    
    if (str.trim() === '') {
      return false;
    }
    
    // Use strict validation to catch invalid characters
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }

    // Check padding
    const paddingCount = (str.match(/=/g) || []).length;
    if (paddingCount > 2 || (paddingCount > 0 && str.length % 4 !== 0)) {
      return false;
    }
    
    try {
      // Check if the string can be decoded as base64 using atob (available in Workers)
      atob(str);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validates if a string is properly base64 encoded using strict validation
   * 
   * This method uses a more strict approach to validate base64 strings,
   * checking for proper padding and valid characters.
   * 
   * @param str - The string to validate as base64
   * @returns boolean - True if valid base64, false otherwise
   */
  static isValidStrict(str: string): boolean {
    // Handle edge cases
    if (str == null || str === undefined) {
      return false;
    }
    
    if (typeof str !== 'string') {
      return false;
    }
    
    if (str.trim() === '') {
      return false;
    }

    // Check for valid base64 characters and padding
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }

    // Check padding
    const paddingCount = (str.match(/=/g) || []).length;
    if (paddingCount > 2 || (paddingCount > 0 && str.length % 4 !== 0)) {
      return false;
    }

    try {
      // Check if the string can be decoded as base64 using atob (available in Workers)
      atob(str);
      return true;
    } catch (error) {
      return false;
    }
  }
} 