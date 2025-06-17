import { DKIMService, DKIMResponse, DKIMErrorResponse, DKIMRecordData } from './dkim.service';
import { 
  DKIMValidationResult, 
  DKIMIssue, 
  DKIMScoreBreakdown,
  DKIMRecord,
  DKIMRecordData as DKIMRecordDataType
} from '../types/dkim.types';
import { Base64Validator } from '../utils';

/**
 * DKIM Validator Service
 * 
 * This service provides comprehensive validation of DKIM (DomainKeys Identified Mail) records
 * for email domains. DKIM is an email authentication method that allows the receiver to verify
 * that an email was indeed sent and authorized by the owner of the domain.
 * 
 * Key Features:
 * - Validates DKIM record syntax and structure
 * - Checks cryptographic key strength and encoding
 * - Evaluates security best practices
 * - Provides scoring and recommendations
 * - Supports multiple selector validation
 * 
 * Security Considerations:
 * - Minimum key length: 1024 bits (acceptable but not optimal)
 * - Recommended key length: 2048 bits (modern standard)
 * - Insecure threshold: <512 bits (should be avoided)
 */
export class DKIMValidator {
  private dkimService: DKIMService;
  
  // Security thresholds for key length validation
  private readonly MIN_KEY_LENGTH = 1024; // Minimum acceptable key length in bits
  private readonly RECOMMENDED_KEY_LENGTH = 2048; // Recommended key length in bits
  private readonly INSECURE_KEY_LENGTH = 512; // Keys below this are considered insecure

  constructor() {
    this.dkimService = new DKIMService();
    console.log('[DKIM Validator] Initialized with security thresholds:', {
      minKeyLength: this.MIN_KEY_LENGTH,
      recommendedKeyLength: this.RECOMMENDED_KEY_LENGTH,
      insecureKeyLength: this.INSECURE_KEY_LENGTH
    });
  }

  /**
   * Validates if a DKIM public key is properly formatted and encoded
   * 
   * This helper method provides consistent base64 validation for DKIM public keys
   * across the validator class. It uses Base64Validator for efficient validation.
   * 
   * @param publicKey - The public key string to validate
   * @param silent - Whether to use silent validation (default: false for detailed logging)
   * @returns boolean - True if the public key is valid base64, false otherwise
   */
  private isValidDKIMPublicKey(publicKey: string, silent: boolean = false): boolean {
    if (!publicKey || publicKey.trim() === '') {
      return false;
    }
    
    return Base64Validator.isValid(publicKey);
  }

  /**
   * Main validation method for DKIM records
   * 
   * This method performs a comprehensive validation of all DKIM records for a given domain.
   * It checks for the presence of DKIM records, validates their structure, analyzes key strength,
   * and provides security recommendations.
   * 
   * @param domain - The domain to validate DKIM records for
   * @returns Promise<DKIMValidationResult> - Complete validation results with scoring
   */
  async validateDKIM(domain: string): Promise<DKIMValidationResult> {
    console.log(`[DKIM Validator] Starting validation for domain: ${domain}`);
    
    const issues: DKIMIssue[] = [];
    const recommendations: string[] = [];
    let records: DKIMRecordData[] = [];
    let finalDomain = domain;

    // Step 1: Retrieve all DKIM records for the domain
    console.log(`[DKIM Validator] Retrieving DKIM records for domain: ${domain}`);
    const dkimResult = await this.dkimService.getAllDKIMRecords(domain);
    
    if (dkimResult.length === 0) {
      console.warn(`[DKIM Validator] No DKIM records found for domain: ${domain}`);
      issues.push({
        type: 'error',
        message: 'No DKIM records found',
        recommendation: 'Implement DKIM for your domain to improve email deliverability and security'
      });
      return this.createValidationResult(
        domain,
        [],
        issues,
        recommendations,
        this.calculateScore([], issues),
        finalDomain
      );
    }

    console.log(`[DKIM Validator] Found ${dkimResult.length} DKIM record(s) for domain: ${domain}`);
    records = dkimResult;
    
    // Step 2: Perform comprehensive validation
    console.log('[DKIM Validator] Starting record validation...');
    const recordIssues = this.validateRecords(records);
    console.log(`[DKIM Validator] Record validation found ${recordIssues.length} issue(s)`);
    issues.push(...recordIssues);
    
    const selectorIssues = this.validateMultipleSelectors(records);
    console.log(`[DKIM Validator] Selector validation found ${selectorIssues.length} issue(s)`);
    issues.push(...selectorIssues);
    
    const testModeIssues = this.validateTestMode(records);
    console.log(`[DKIM Validator] Test mode validation found ${testModeIssues.length} issue(s)`);
    issues.push(...testModeIssues);
    
    // Step 3: Generate recommendations based on findings
    console.log('[DKIM Validator] Generating recommendations...');
    recommendations.push(...this.generateRecommendations(records, issues));
    
    // Step 4: Calculate security score
    const score = this.calculateScore(records, issues);
    console.log(`[DKIM Validator] Calculated security score: ${score.total}/20`, score);
    
    return this.createValidationResult(
      domain,
      records,
      issues,
      recommendations,
      score,
      finalDomain
    );
  }

  /**
   * Validates individual DKIM records for syntax and structure
   * 
   * This method checks each DKIM record for:
   * - Proper DKIM version declaration
   * - Presence and validity of public key
   * - Key encoding and cryptographic strength
   * 
   * @param records - Array of DKIM record data to validate
   * @returns Array of validation issues found
   */
  private validateRecords(records: DKIMRecordData[]): DKIMIssue[] {
    const issues: DKIMIssue[] = [];
    console.log(`[DKIM Validator] Validating ${records.length} DKIM record(s)`);
    
    for (const recordData of records) {
      const record = recordData.parsed;
      const selector = recordData.selector || '';
      
      console.log(`[DKIM Validator] Validating record for selector: ${selector}`);
      console.log(`[DKIM Validator] Raw record: ${recordData.raw.substring(0, 100)}...`);
      console.log(`[DKIM Validator] Parsed record keys:`, Object.keys(record));
      console.log(`[DKIM Validator] Parsed publicKey field:`, {
        exists: !!record.publicKey,
        type: typeof record.publicKey,
        length: record.publicKey?.length || 0,
        value: record.publicKey ? record.publicKey.substring(0, 50) + '...' : 'undefined'
      });
      
      // Check DKIM version
      if (!record.version || record.version !== 'DKIM1') {
        console.warn(`[DKIM Validator] Missing or invalid DKIM version in selector ${selector}: ${record.version}`);
        issues.push({
          type: 'warning',
          message: `Missing DKIM version in selector ${selector}`,
          recommendation: 'Consider adding v=DKIM1 to your DKIM records for explicit version declaration'
        });
      } else {
        console.log(`[DKIM Validator] ✓ Valid DKIM version found in selector ${selector}`);
      }
      
      // Check public key presence
      if (!record.publicKey || record.publicKey.trim() === '') {
        console.error(`[DKIM Validator] Missing public key in selector ${selector}`);
        console.error(`[DKIM Validator] Public key field:`, {
          exists: !!record.publicKey,
          type: typeof record.publicKey,
          length: record.publicKey?.length || 0,
          isEmpty: record.publicKey === '',
          isWhitespaceOnly: record.publicKey?.trim() === ''
        });
        issues.push({
          type: 'error',
          message: `Missing public key in selector ${selector}`,
          recommendation: 'DKIM records must include a valid public key (p=)'
        });
        continue; // Skip further validation for this record
      }
      
      // Validate public key encoding and strength
      console.log(`[DKIM Validator] Validating public key for selector ${selector}`);
      const keyValidation = this.validatePublicKey(record.publicKey, selector);
      if (keyValidation.issues) {
        issues.push(...keyValidation.issues);
      }
    }
    
    return issues;
  }

  /**
   * Validates DKIM public key encoding and cryptographic strength
   * 
   * This method performs several critical security checks:
   * - Base64 encoding validation
   * - Key length analysis
   * - Security threshold evaluation
   * 
   * @param publicKey - The base64-encoded public key to validate
   * @param selector - The DKIM selector for context in error messages
   * @returns Object containing validation issues if any
   */
  private validatePublicKey(publicKey: string, selector: string): { issues?: DKIMIssue[] } {
    const issues: DKIMIssue[] = [];
    
    console.log(`[DKIM Validator] Analyzing public key for selector ${selector}`);
    console.log(`[DKIM Validator] Public key length: ${publicKey?.length || 0}`);
    console.log(`[DKIM Validator] Public key (first 50 chars): ${publicKey?.substring(0, 50)}...`);
    
    // Check for invisible characters
    if (publicKey) {
      const invisibleChars = publicKey.split('').map((char, index) => {
        const code = char.charCodeAt(0);
        if (code < 32 || code > 126) {
          return { index, char, code };
        }
        return null;
      }).filter(Boolean);
      
      if (invisibleChars.length > 0) {
        console.warn(`[DKIM Validator] Found ${invisibleChars.length} invisible characters in public key for selector ${selector}:`, invisibleChars);
      }
    }
    
    // Step 1: Validate base64 encoding using Base64Validator
    console.log(`[DKIM Validator] Validating base64 encoding for selector ${selector}`);
    
    if (!this.isValidDKIMPublicKey(publicKey)) {
      console.error(`[DKIM Validator] Invalid base64 encoding in public key for selector ${selector}`);
      console.error(`key: ${publicKey}`);
      console.error(`[DKIM Validator] Key type: ${typeof publicKey}`);
      console.error(`[DKIM Validator] Key is null/undefined: ${publicKey == null}`);
      console.error(`[DKIM Validator] Key is empty string: ${publicKey === ''}`);
      console.error(`[DKIM Validator] Key is whitespace only: ${publicKey?.trim() === ''}`);
      issues.push({
        type: 'error',
        message: `Invalid base64 encoding in public key for selector ${selector}`,
        recommendation: 'Public key must be properly base64 encoded'
      });
      return { issues };
    }
    
    console.log(`[DKIM Validator] ✓ Valid base64 encoding for selector ${selector}`);
    
    // Step 2: Decode and analyze key length
    // Since Base64Validator.isValid() already confirmed the key is valid base64,
    // we can safely decode it without additional try-catch
    const decodedKey = new Uint8Array(atob(publicKey).split('').map(char => char.charCodeAt(0)));
    const keyLengthBits = decodedKey.length * 8;
    
    console.log(`[DKIM Validator] Key length for selector ${selector}: ${keyLengthBits} bits`);
    
    // Step 3: Evaluate key strength against security thresholds
    if (keyLengthBits < this.INSECURE_KEY_LENGTH) {
      console.error(`[DKIM Validator] Insecure key length (${keyLengthBits} bits) in selector ${selector}`);
      issues.push({
        type: 'error',
        message: `Insecure key length (${keyLengthBits} bits) in selector ${selector}`,
        recommendation: `Upgrade to at least ${this.MIN_KEY_LENGTH}-bit keys, preferably ${this.RECOMMENDED_KEY_LENGTH}-bit`
      });
    } else if (keyLengthBits < this.MIN_KEY_LENGTH) {
      console.warn(`[DKIM Validator] Key length (${keyLengthBits} bits) in selector ${selector} is below recommended minimum`);
      issues.push({
        type: 'warning',
        message: `Key length (${keyLengthBits} bits) in selector ${selector} is below recommended minimum`,
        recommendation: `Consider upgrading to ${this.RECOMMENDED_KEY_LENGTH}-bit keys for better security`
      });
    } else if (keyLengthBits >= this.RECOMMENDED_KEY_LENGTH) {
      console.log(`[DKIM Validator] ✓ Good key length (${keyLengthBits} bits) in selector ${selector}`);
      issues.push({
        type: 'info',
        message: `Good key length (${keyLengthBits} bits) in selector ${selector}`,
        recommendation: 'Key length meets modern security standards'
      });
    }
    
    return { issues };
  }

  /**
   * Validates DKIM selector configuration for redundancy and key rotation
   * 
   * This method checks if the domain has multiple DKIM selectors configured,
   * which is a best practice for enabling key rotation without downtime.
   * 
   * @param records - Array of DKIM records to analyze
   * @returns Array of validation issues related to selector configuration
   */
  private validateMultipleSelectors(records: DKIMRecordData[]): DKIMIssue[] {
    const issues: DKIMIssue[] = [];
    
    console.log(`[DKIM Validator] Analyzing selector configuration: ${records.length} selector(s) found`);
    
    if (records.length === 1) {
      console.warn('[DKIM Validator] Only one DKIM selector found - consider implementing multiple selectors');
      issues.push({
        type: 'warning',
        message: 'Only one DKIM selector found',
        recommendation: 'Consider implementing multiple selectors to enable key rotation without downtime'
      });
    } else if (records.length >= 2) {
      console.log(`[DKIM Validator] ✓ Multiple DKIM selectors found (${records.length}) - good for key rotation`);
      issues.push({
        type: 'info',
        message: `Multiple DKIM selectors found (${records.length})`,
        recommendation: 'Good practice for key rotation and redundancy'
      });
    }
    
    return issues;
  }

  /**
   * Validates DKIM records for test mode configuration
   * 
   * This method checks if any DKIM records have the test mode flag (t=y) set,
   * which indicates that DKIM failures should be treated lightly. This is
   * typically not desired in production environments.
   * 
   * @param records - Array of DKIM records to check for test mode
   * @returns Array of validation issues related to test mode
   */
  private validateTestMode(records: DKIMRecordData[]): DKIMIssue[] {
    const issues: DKIMIssue[] = [];
    
    console.log('[DKIM Validator] Checking for test mode flags in DKIM records');
    
    for (const recordData of records) {
      const record = recordData.parsed;
      const selector = recordData.selector || '';
      
      if (record.flags && record.flags.includes('y')) {
        console.warn(`[DKIM Validator] Test mode flag (t=y) found in selector ${selector}`);
        issues.push({
          type: 'warning',
          message: `Test mode flag (t=y) found in selector ${selector}`,
          recommendation: 'Remove test mode flag for production use. Test mode indicates DKIM failures should be treated lightly'
        });
      } else {
        console.log(`[DKIM Validator] ✓ No test mode flag in selector ${selector}`);
      }
    }
    
    return issues;
  }

  /**
   * Generates actionable recommendations based on validation findings
   * 
   * This method analyzes the validation results and generates specific,
   * actionable recommendations to improve DKIM configuration and security.
   * 
   * @param records - Array of DKIM records analyzed
   * @param issues - Array of validation issues found
   * @returns Array of recommendation strings
   */
  private generateRecommendations(records: DKIMRecordData[], issues: DKIMIssue[]): string[] {
    const recommendations: string[] = [];
    
    console.log('[DKIM Validator] Generating recommendations based on validation results');
    
    // Handle case where no DKIM records exist
    if (records.length === 0) {
      recommendations.push('Implement DKIM for your domain to improve email deliverability and security');
      return recommendations;
    }
    
    // Check for weak cryptographic keys
    const hasWeakKeys = issues.some(issue => 
      issue.type === 'error' && issue.message.includes('Insecure key length')
    );
    const hasShortKeys = issues.some(issue => 
      issue.type === 'warning' && issue.message.includes('Key length') && issue.message.includes('below recommended')
    );
    
    if (hasWeakKeys) {
      console.log('[DKIM Validator] Recommending key upgrade due to weak keys');
      recommendations.push(`Upgrade all DKIM keys to at least ${this.MIN_KEY_LENGTH}-bit length`);
    } else if (hasShortKeys) {
      console.log('[DKIM Validator] Recommending key upgrade due to short keys');
      recommendations.push(`Consider upgrading DKIM keys to ${this.RECOMMENDED_KEY_LENGTH}-bit for better security`);
    }
    
    // Check for single selector configuration
    if (records.length === 1) {
      console.log('[DKIM Validator] Recommending multiple selectors for key rotation');
      recommendations.push('Implement multiple DKIM selectors to enable key rotation without downtime');
    }
    
    // Check for test mode flags
    const hasTestMode = issues.some(issue => 
      issue.type === 'warning' && issue.message.includes('Test mode flag')
    );
    if (hasTestMode) {
      console.log('[DKIM Validator] Recommending removal of test mode flags');
      recommendations.push('Remove test mode flags (t=y) from production DKIM records');
    }
    
    // General best practices
    recommendations.push('Monitor DKIM authentication rates in your email analytics');
    recommendations.push('Set up DMARC to complement DKIM and SPF for comprehensive email authentication');
    
    console.log(`[DKIM Validator] Generated ${recommendations.length} recommendations`);
    return recommendations;
  }

  /**
   * Calculates a comprehensive security score for DKIM configuration
   * 
   * This method evaluates the DKIM configuration across multiple security dimensions
   * and returns a detailed score breakdown. The scoring system is designed to:
   * - Reward proper DKIM implementation (10 points)
   * - Encourage strong cryptographic keys (5 points)
   * - Promote multiple selector configuration (3 points)
   * - Ensure production-ready configuration (2 points)
   * 
   * Scoring Breakdown:
   * - DKIM Implemented: 10 points (all or nothing)
   * - Key Length: 0-5 points (based on cryptographic strength)
   * - Multiple Selectors: 0-3 points (redundancy and key rotation)
   * - No Test Mode: 0-2 points (production readiness)
   * 
   * @param records - Array of DKIM records to score
   * @param issues - Array of validation issues to consider
   * @returns Detailed score breakdown with component scores
   */
  private calculateScore(records: DKIMRecordData[], issues: DKIMIssue[]): DKIMScoreBreakdown {
    console.log('[DKIM Validator] Calculating security score...');
    
    let dkimImplemented = 0;
    let keyLength = 0;
    let multipleSelectors = 0;
    let noTestMode = 0;

    // DKIM Implemented: 10 points (all or nothing)
    if (records.length > 0) {
      dkimImplemented = 10;
      console.log('[DKIM Validator] ✓ DKIM implemented: 10 points');
    } else {
      console.log('[DKIM Validator] ✗ DKIM not implemented: 0 points');
    }

    // DKIM Key Length: Up to 5 points
    // Scoring logic:
    // - 2048-bit (or higher) keys present: 5 points
    // - 1024-bit keys: 3 points (still acceptable but not optimal)
    // - <1024-bit: 0 points (insecure configuration)
    // If multiple selectors/keys, score based on the strongest key in use,
    // but if any production key is <1024, cap the score at 0 as it's a vulnerability
    if (records.length > 0) {
      let bestKeyLength = 0;
      let hasInsecureKey = false;
      
      console.log('[DKIM Validator] Analyzing key lengths across all selectors...');
      
      for (const recordData of records) {
        // Use Base64Validator for efficient validation without logging
        if (this.isValidDKIMPublicKey(recordData.parsed.publicKey, true)) {
          const decodedKey = new Uint8Array(atob(recordData.parsed.publicKey).split('').map(char => char.charCodeAt(0)));
          const keyLengthBits = decodedKey.length * 8;
          
          console.log(`[DKIM Validator] Selector ${recordData.selector}: ${keyLengthBits} bits`);
          
          if (keyLengthBits >= this.RECOMMENDED_KEY_LENGTH) {
            bestKeyLength = Math.max(bestKeyLength, 5);
            console.log(`[DKIM Validator] ✓ Strong key (${keyLengthBits} bits): 5 points`);
          } else if (keyLengthBits >= this.MIN_KEY_LENGTH) {
            bestKeyLength = Math.max(bestKeyLength, 3);
            console.log(`[DKIM Validator] ~ Acceptable key (${keyLengthBits} bits): 3 points`);
          } else {
            hasInsecureKey = true;
            console.log(`[DKIM Validator] ✗ Insecure key (${keyLengthBits} bits): 0 points`);
          }
        } else {
          hasInsecureKey = true;
          console.log(`[DKIM Validator] ✗ Invalid key format: 0 points`);
        }
      }
      
      if (hasInsecureKey) {
        keyLength = 0; // Cap at 0 if any key is insecure
        console.log('[DKIM Validator] ✗ Insecure keys present: 0 points (capped due to security risk)');
      } else {
        keyLength = bestKeyLength;
        console.log(`[DKIM Validator] ✓ Key length score: ${keyLength} points`);
      }
    }

    // DKIM Multiple Selectors: 3 points (if ≥2 selectors; 0 if only one)
    if (records.length >= 2) {
      multipleSelectors = 3;
      console.log(`[DKIM Validator] ✓ Multiple selectors (${records.length}): 3 points`);
    } else {
      console.log('[DKIM Validator] ~ Single selector: 0 points');
    }

    // No DKIM Test Mode: 2 points (if no test flags; 0 if any present)
    let hasTestMode = false;
    if (records.length > 0) { // Only check for test mode if there are records
      for (const recordData of records) {
        if (recordData.parsed.flags && recordData.parsed.flags.includes('y')) {
          hasTestMode = true;
          console.log(`[DKIM Validator] ✗ Test mode flag found in selector ${recordData.selector}: 0 points`);
          break;
        }
      }
      if (!hasTestMode) {
        noTestMode = 2;
        console.log('[DKIM Validator] ✓ No test mode flags: 2 points');
      }
    }

    const total = dkimImplemented + keyLength + multipleSelectors + noTestMode;
    
    console.log('[DKIM Validator] Final score breakdown:', {
      dkimImplemented,
      keyLength,
      multipleSelectors,
      noTestMode,
      total
    });
    
    return {
      dkimImplemented,
      keyLength,
      multipleSelectors,
      noTestMode,
      total
    };
  }

  /**
   * Creates a comprehensive validation result object
   * 
   * This method assembles all validation findings into a structured result object
   * that includes the overall validation status, detailed scoring, and metadata
   * about the DKIM configuration.
   * 
   * @param domain - The domain being validated
   * @param records - Array of DKIM records found
   * @param issues - Array of validation issues
   * @param recommendations - Array of recommendations
   * @param score - Detailed score breakdown
   * @param finalDomain - The final domain used for validation (may differ from input)
   * @returns Complete validation result object
   */
  private createValidationResult(
    domain: string,
    records: DKIMRecordData[],
    issues: DKIMIssue[],
    recommendations: string[],
    score: DKIMScoreBreakdown,
    finalDomain: string = domain
  ): DKIMValidationResult {
    const isValid = score.total >= 15; // Consider valid if score is 15+ out of 20 (75% threshold)
    
    console.log(`[DKIM Validator] Creating validation result for domain: ${domain}`);
    console.log(`[DKIM Validator] Overall validation status: ${isValid ? 'VALID' : 'INVALID'} (score: ${score.total}/20)`);
    
    // Extract key length information for the first record (for backward compatibility)
    let keyLength = 0;
    if (records.length > 0) {
      // Use Base64Validator for efficient validation without logging
      if (this.isValidDKIMPublicKey(records[0].parsed.publicKey, true)) {
        const decodedKey = new Uint8Array(atob(records[0].parsed.publicKey).split('').map(char => char.charCodeAt(0)));
        keyLength = decodedKey.length * 8;
        console.log(`[DKIM Validator] Primary key length: ${keyLength} bits`);
      } else {
        console.warn('[DKIM Validator] Could not determine primary key length - invalid base64 encoding');
        keyLength = 0;
      }
    }
    
    const result = {
      isValid,
      score: score.total,
      records: records.map(r => ({
        raw: r.raw,
        parsed: r.parsed,
        selector: r.selector
      })),
      issues,
      recommendations,
      details: {
        hasVersion: records.length > 0 && records.every(r => r.parsed.version === 'DKIM1'),
        hasValidKeyType: records.length > 0 && records.every(r => r.parsed.keyType === 'rsa' || !r.parsed.keyType),
        hasValidPublicKey: records.length > 0 && records.every(r => r.parsed.publicKey && r.parsed.publicKey.trim() !== '' && this.isValidDKIMPublicKey(r.parsed.publicKey, true)),
        hasValidHashAlgorithms: records.length > 0 && records.every(r => Array.isArray(r.parsed.hashAlgorithms) && r.parsed.hashAlgorithms.length > 0),
        keyLength,
        finalDomain
      }
    };
    
    console.log('[DKIM Validator] Validation result details:', {
      recordCount: records.length,
      issueCount: issues.length,
      recommendationCount: recommendations.length,
      hasVersion: result.details.hasVersion,
      hasValidKeyType: result.details.hasValidKeyType,
      hasValidPublicKey: result.details.hasValidPublicKey,
      hasValidHashAlgorithms: result.details.hasValidHashAlgorithms
    });
    
    return result;
  }

  /**
   * Validates a single DKIM record for a specific selector
   * 
   * This method provides targeted validation for a specific DKIM selector,
   * useful for debugging or validating individual record configurations.
   * 
   * @param domain - The domain to validate
   * @param selector - The specific DKIM selector to validate
   * @returns Promise<DKIMValidationResult> - Validation results for the specific selector
   */
  async validateSingleDKIMRecord(domain: string, selector: string): Promise<DKIMValidationResult> {
    console.log(`[DKIM Validator] Validating single DKIM record for domain: ${domain}, selector: ${selector}`);
    
    const dkimResult = await this.dkimService.getDKIMRecordForDomain(domain, selector);
    
    if (this.dkimService.isErrorResponse(dkimResult)) {
      const errorResponse = dkimResult as DKIMErrorResponse;
      console.error(`[DKIM Validator] Error retrieving DKIM record for selector ${selector}:`, errorResponse.error);
      
      return this.createValidationResult(
        domain,
        [],
        [{
          type: 'error',
          message: errorResponse.error,
          recommendation: errorResponse.suggestion || 'Check if the DKIM record exists for this selector'
        }],
        ['Implement DKIM for your domain'],
        this.calculateScore([], []),
        domain
      );
    }
    
    const dkimResponse = dkimResult as DKIMResponse;
    console.log(`[DKIM Validator] Successfully retrieved DKIM record for selector ${selector}`);
    
    const recordData: DKIMRecordData = {
      raw: dkimResponse.record,
      parsed: dkimResponse.parsed,
      selector: dkimResponse.selector || ''
    };
    
    // Perform validation on the single record
    const issues = this.validateRecords([recordData]);
    const multipleSelectorIssues = this.validateMultipleSelectors([recordData]);
    const testModeIssues = this.validateTestMode([recordData]);
    const allIssues = [...issues, ...multipleSelectorIssues, ...testModeIssues];
    
    const recommendations = this.generateRecommendations([recordData], allIssues);
    const score = this.calculateScore([recordData], allIssues);
    
    console.log(`[DKIM Validator] Single record validation complete for selector ${selector}`);
    
    return this.createValidationResult(
      domain,
      [recordData],
      allIssues,
      recommendations,
      score,
      domain
    );
  }
} 