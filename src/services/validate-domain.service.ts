import { DNSValidator } from './dns-validator';
import { SPFValidator } from './spf-validator';
import { DKIMValidator } from './dkim-validator';
import { DMARCValidator } from './dmarc-validator';
import { 
  DomainValidationResult, 
  DomainValidationError, 
  DomainValidationResponse 
} from '../types/domain.types';

/**
 * Domain Validation Service
 * 
 * This service provides comprehensive validation of email domains by:
 * 1. Validating DNS existence using DNS-over-HTTPS
 * 2. Validating SPF (Sender Policy Framework) records
 * 3. Validating DKIM (DomainKeys Identified Mail) records
 * 4. Validating DMARC (Domain-based Message Authentication, Reporting & Conformance) records
 * 
 * The service returns a comprehensive score and detailed analysis of each component.
 * 
 * Key Features:
 * - DNS existence validation
 * - SPF record validation and scoring
 * - DKIM record validation and scoring
 * - DMARC record validation and scoring
 * - Comprehensive security scoring
 * - Detailed recommendations for improvement
 * 
 * Security Considerations:
 * - Uses DNS-over-HTTPS for secure DNS queries
 * - Validates domain format before processing
 * - Provides detailed error reporting
 * - Handles validation failures gracefully
 */
export class ValidateDomainService {
  private dnsValidator: DNSValidator;
  private spfValidator: SPFValidator;
  private dkimValidator: DKIMValidator;
  private dmarcValidator: DMARCValidator;

  // Scoring constants
  private readonly MAX_TOTAL_SCORE = 100;
  private readonly SPF_MAX_SCORE = 20;
  private readonly DKIM_MAX_SCORE = 17;
  private readonly DMARC_MAX_SCORE = 29;

  constructor() {
    this.dnsValidator = new DNSValidator();
    this.spfValidator = new SPFValidator();
    this.dkimValidator = new DKIMValidator();
    this.dmarcValidator = new DMARCValidator();
    console.log('[Validate Domain Service] Initialized with all validators');
  }

  /**
   * Validates domain format
   * Basic validation to ensure domain parameter is reasonable
   * @param domain - Domain string to validate
   * @returns True if domain format is valid
   */
  private isValidDomain(domain: string): boolean {
    // Basic domain validation - should contain at least one dot and valid characters
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/;
    return domainRegex.test(domain) && domain.length > 0 && domain.length <= 253;
  }

  /**
   * Validates domain parameter and returns appropriate error response if invalid
   * @param domain - Domain string to validate
   * @returns Validation result with error response if invalid
   */
  validateDomainFormat(domain: string): { isValid: boolean; error?: DomainValidationError } {
    if (!domain) {
      return {
        isValid: false,
        error: {
          error: 'Domain parameter is required',
          timestamp: new Date().toISOString()
        }
      };
    }

    if (!this.isValidDomain(domain)) {
      return {
        isValid: false,
        error: {
          error: 'Invalid domain format',
          domain,
          timestamp: new Date().toISOString()
        }
      };
    }

    return { isValid: true };
  }

  /**
   * Main validation method for domains
   * 
   * This method performs a comprehensive validation of a domain by:
   * 1. Validating DNS existence
   * 2. Validating SPF records
   * 3. Validating DKIM records
   * 4. Validating DMARC records
   * 5. Calculating total security score
   * 
   * @param domain - The domain to validate
   * @returns Promise<DomainValidationResponse> - Complete validation results with scoring
   */
  async validateDomain(domain: string): Promise<DomainValidationResponse> {
    console.log(`[Validate Domain Service] Starting comprehensive validation for domain: ${domain}`);

    // Step 1: Validate domain format
    const domainValidation = this.validateDomainFormat(domain);
    if (!domainValidation.isValid) {
      console.error(`[Validate Domain Service] Domain validation failed: ${domainValidation.error?.error}`);
      return domainValidation.error!;
    }

    // Step 2: Validate DNS existence
    console.log(`[Validate Domain Service] Validating DNS existence for domain: ${domain}`);
    const dnsResult = await this.dnsValidator.validateDNS(domain);
    
    if (!dnsResult.exists) {
      console.error(`[Validate Domain Service] DNS validation failed for domain: ${domain}`);
      return {
        error: dnsResult.error || 'Domain does not exist or has no DNS records',
        domain,
        details: dnsResult.details,
        timestamp: new Date().toISOString()
      };
    }
    console.log(`[Validate Domain Service] ✓ DNS validation successful for domain: ${domain}`);

    // Step 3: Run all validations in parallel for better performance
    console.log(`[Validate Domain Service] Running SPF, DKIM, and DMARC validations in parallel`);
    const [spfResult, dkimResult, dmarcResult] = await Promise.all([
      this.spfValidator.validateSPF(domain),
      this.dkimValidator.validateDKIM(domain),
      this.dmarcValidator.validateDMARC(domain)
    ]);

    console.log(`[Validate Domain Service] All validations completed for domain: ${domain}`);

    // Step 4: Calculate total score
    const totalScore = spfResult.score + dkimResult.score + dmarcResult.score;
    console.log(`[Validate Domain Service] Calculated total score: ${totalScore}/${this.MAX_TOTAL_SCORE}`);

    // Step 5: Create comprehensive result
    const result: DomainValidationResult = {
      total_score: totalScore,
      total_max_score: this.MAX_TOTAL_SCORE,
      spf_result: spfResult,
      kdim_result: dkimResult,
      dmarc_result: dmarcResult
    };

    console.log(`[Validate Domain Service] Validation complete for domain: ${domain}`);
    return result;
  }

  /**
   * Checks if a response is an error response
   * @param result - The validation result to check
   * @returns True if the result is an error response
   */
  isErrorResponse(result: DomainValidationResponse): result is DomainValidationError {
    return 'error' in result;
  }

  /**
   * Checks if a response is a success response
   * @param result - The validation result to check
   * @returns True if the result is a success response
   */
  isSuccessResponse(result: DomainValidationResponse): result is DomainValidationResult {
    return !this.isErrorResponse(result);
  }
} 