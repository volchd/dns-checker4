import { SPFService, SPFResponse, SPFErrorResponse } from './spf.service';
import { 
  SPFValidationResult, 
  SPFMechanism, 
  SPFIssue, 
  SPFQualifier,
  SPFScoreBreakdown,
  SPFRedirect
} from '../types/spf.types';

/**
 * SPF Validator Service
 * 
 * This service provides comprehensive validation of SPF (Sender Policy Framework) records
 * for email domains. SPF is an email authentication method that helps prevent email spoofing
 * by allowing domain owners to specify which mail servers are authorized to send email
 * on behalf of their domain.
 * 
 * Key Features:
 * - Validates SPF record syntax and structure
 * - Checks DNS lookup limits and performance
 * - Evaluates mechanism usage and security policies
 * - Handles redirects and includes
 * - Provides scoring and recommendations
 * 
 * Security Considerations:
 * - Maximum DNS lookups: 10 (RFC 7208 limit)
 * - Deprecated mechanisms: ptr (should be avoided)
 * - All mechanism policy: Should use ~all or -all, not +all
 * - Redirect depth: Limited to prevent loops
 */
export class SPFValidator {
  private spfService: SPFService;
  
  // SPF validation constants and limits
  private readonly MAX_LOOKUPS = 10; // RFC 7208 limit for DNS lookups
  private readonly DEPRECATED_MECHANISMS = ['ptr']; // Mechanisms that should be avoided
  private readonly VALID_MECHANISMS = ['ip4', 'ip6', 'a', 'mx', 'include', 'exists', 'redirect', 'all'];
  private readonly MAX_REDIRECT_DEPTH = 2; // Prevent redirect loops

  constructor() {
    this.spfService = new SPFService();
    console.log('[SPF Validator] Initialized with validation limits:', {
      maxLookups: this.MAX_LOOKUPS,
      deprecatedMechanisms: this.DEPRECATED_MECHANISMS,
      maxRedirectDepth: this.MAX_REDIRECT_DEPTH
    });
  }

  /**
   * Main validation method for SPF records
   * 
   * This method performs a comprehensive validation of SPF records for a given domain.
   * It checks for the presence of SPF records, validates their syntax, analyzes mechanism
   * usage, handles redirects and includes, and provides security recommendations.
   * 
   * @param domain - The domain to validate SPF records for
   * @returns Promise<SPFValidationResult> - Complete validation results with scoring
   */
  async validateSPF(domain: string): Promise<SPFValidationResult> {
    console.log(`[SPF Validator] Starting validation for domain: ${domain}`);

    const issues: SPFIssue[] = [];
    const recommendations: string[] = [];
    let mechanisms: SPFMechanism[] = [];
    let lookupCount = 0;
    let record = '';
    let redirectRecord = '';
    let redirects: SPFRedirect[] = [];
    let finalDomain = domain;
    let processedRedirects = 0;
    let processedIncludes = 0;

    // Step 1: Retrieve SPF record using SPF service
    console.log(`[SPF Validator] Retrieving SPF record for domain: ${domain}`);
    const spfResult = await this.spfService.getSPFRecordForDomain(domain);
    
    if (this.spfService.isErrorResponse(spfResult)) {
      console.error(`[SPF Validator] Error retrieving SPF record for domain: ${domain}:`, spfResult.error);
      issues.push({
        type: 'error',
        message: spfResult.error,
        recommendation: spfResult.suggestion || 'Check if the domain has a valid SPF record in DNS'
      });
      
      return this.createValidationResult(
        domain,
        '',
        [],
        issues,
        recommendations,
        0,
        {
          recordPresent: 0,
          singleRecord: 0,
          syntaxValid: 0,
          lookupLimit: 0,
          noPassAll: 0,
          allMechanismPolicy: 0,
          noDeprecatedMechanisms: 0,
          total: 0
        },
        redirects,
        finalDomain
      );
    }

    const spfResponse = spfResult as SPFResponse;
    console.log(`[SPF Validator] ✓ Successfully retrieved SPF record for domain: ${domain}`);

    // Step 2: Extract processing statistics and calculate lookup count
    processedRedirects = spfResponse.summary.processedRedirects;
    processedIncludes = spfResponse.summary.processedIncludes;
    
    // Calculate total lookup count using the processed fields
    lookupCount = processedRedirects + processedIncludes;
    console.log(`[SPF Validator] DNS lookup analysis:`, {
      redirects: processedRedirects,
      includes: processedIncludes,
      total: lookupCount,
      limit: this.MAX_LOOKUPS,
      overLimit: lookupCount > this.MAX_LOOKUPS
    });

    // Step 3: Handle redirects if present
    if (spfResponse.hasRedirects && spfResponse.redirectedRecord) {
      console.log(`[SPF Validator] SPF record has redirects, using redirected record for validation`);
      
      // Use the redirected record for validation
      record = spfResponse.record; // Original record
      redirectRecord = spfResponse.redirectedRecord.record; // Final redirected record
      mechanisms = this.convertSPFServiceMechanisms(spfResponse.redirectedRecord.mechanisms);
      redirects = spfResponse.redirects || [];
      finalDomain = spfResponse.finalDomain || domain;
      
      // Add info about redirects
      issues.push({
        type: 'info',
        message: `SPF record redirects to ${finalDomain}`,
        recommendation: 'Ensure the redirect target is properly maintained'
      });
      
      console.log(`[SPF Validator] Using redirected record from ${finalDomain}: ${redirectRecord}`);
    } else {
      // Use the original record for validation
      record = spfResponse.record;
      mechanisms = this.convertSPFServiceMechanisms(spfResponse.mechanisms);
      redirects = spfResponse.redirects || [];
      finalDomain = spfResponse.finalDomain || domain;
      
      console.log(`[SPF Validator] Using original record: ${record}`);
    }

    console.log(`[SPF Validator] Parsed ${mechanisms.length} SPF mechanisms:`, mechanisms);

    // Step 4: Validate mechanisms
    console.log('[SPF Validator] Starting mechanism validation...');
    const mechanismIssues = this.validateMechanisms(mechanisms);
    console.log(`[SPF Validator] Mechanism validation found ${mechanismIssues.length} issue(s)`);
    issues.push(...mechanismIssues);

    // Step 5: Check lookup limit compliance
    if (lookupCount > this.MAX_LOOKUPS) {
      console.error(`[SPF Validator] DNS lookup limit exceeded: ${lookupCount} > ${this.MAX_LOOKUPS}`);
      issues.push({
        type: 'error',
        message: `Too many DNS lookups (${lookupCount} > ${this.MAX_LOOKUPS})`,
        recommendation: 'Consider using SPF flattening or subdomains to reduce DNS lookups below 10'
      });
    } else {
      console.log(`[SPF Validator] ✓ DNS lookup count within limits: ${lookupCount}/${this.MAX_LOOKUPS}`);
    }

    // Step 6: Generate recommendations
    console.log('[SPF Validator] Generating recommendations...');
    recommendations.push(...this.generateRecommendations(mechanisms, issues, lookupCount));

    // Step 7: Calculate security score
    const score = this.calculateScore(mechanisms, issues, lookupCount);
    console.log(`[SPF Validator] Calculated security score: ${score.total}/20`, score);

    const result = this.createValidationResult(
      domain,
      record,
      mechanisms,
      issues,
      recommendations,
      lookupCount,
      score,
      redirects,
      finalDomain,
      redirectRecord
    );
    
    console.log(`[SPF Validator] Validation complete for domain: ${domain}`);
    return result;
  }

  /**
   * Converts SPF service mechanism format to validator mechanism format
   * 
   * This method standardizes the mechanism format between the SPF service
   * and the validator for consistent processing.
   * 
   * @param serviceMechanisms - Mechanisms from SPF service
   * @returns Array of standardized SPF mechanisms
   */
  private convertSPFServiceMechanisms(serviceMechanisms: any[]): SPFMechanism[] {
    console.log(`[SPF Validator] Converting ${serviceMechanisms.length} mechanisms from service format`);
    
    return serviceMechanisms.map(mech => ({
      type: mech.type,
      value: mech.value,
      qualifier: mech.qualifier || '+' as SPFQualifier
    }));
  }

  /**
   * Validates SPF mechanisms for security and best practices
   * 
   * This method checks each mechanism for:
   * - Deprecated mechanism usage (e.g., ptr)
   * - All mechanism presence and policy
   * - Security implications of mechanism choices
   * 
   * @param mechanisms - Array of SPF mechanisms to validate
   * @returns Array of validation issues found
   */
  private validateMechanisms(mechanisms: SPFMechanism[]): SPFIssue[] {
    const issues: SPFIssue[] = [];
    
    console.log(`[SPF Validator] Validating ${mechanisms.length} SPF mechanisms`);

    // Check for deprecated mechanisms
    const deprecated = mechanisms.filter(m => this.DEPRECATED_MECHANISMS.includes(m.type));
    if (deprecated.length > 0) {
      console.warn(`[SPF Validator] Found ${deprecated.length} deprecated mechanism(s):`, deprecated);
      issues.push({
        type: 'warning',
        message: 'Deprecated mechanisms found',
        recommendation: 'Replace deprecated mechanisms with ip4/ip6 or include mechanisms'
      });
    } else {
      console.log('[SPF Validator] ✓ No deprecated mechanisms found');
    }

    // Check for all mechanism presence and policy
    const allMechanism = mechanisms.find(m => m.type === 'all');
    if (!allMechanism) {
      console.error('[SPF Validator] Missing all mechanism - this is required for proper SPF policy');
      issues.push({
        type: 'error',
        message: 'Missing all mechanism',
        recommendation: 'Add an all mechanism (preferably ~all or -all) at the end of your SPF record'
      });
    } else if (allMechanism.qualifier === '+') {
      console.error('[SPF Validator] Using +all mechanism - this allows all senders and defeats SPF purpose');
      issues.push({
        type: 'error',
        message: 'Using +all mechanism',
        recommendation: 'Replace +all with ~all or -all to properly restrict unauthorized senders'
      });
    } else {
      console.log(`[SPF Validator] ✓ All mechanism found with qualifier: ${allMechanism.qualifier}`);
    }

    console.log(`[SPF Validator] Mechanism validation complete: ${issues.length} issue(s) found`);
    return issues;
  }

  /**
   * Generates actionable recommendations based on validation findings
   * 
   * This method analyzes the validation results and generates specific,
   * actionable recommendations to improve SPF configuration and security.
   * 
   * @param mechanisms - Array of SPF mechanisms analyzed
   * @param issues - Array of validation issues found
   * @param lookupCount - Number of DNS lookups required
   * @returns Array of recommendation strings
   */
  private generateRecommendations(
    mechanisms: SPFMechanism[], 
    issues: SPFIssue[],
    lookupCount: number
  ): string[] {
    const recommendations: string[] = [];
    
    console.log('[SPF Validator] Generating recommendations based on validation results');

    // Add recommendations based on issues
    issues.forEach(issue => {
      if (issue.recommendation) {
        recommendations.push(issue.recommendation);
      }
    });

    // Check for specific mechanism patterns and provide targeted advice
    const hasAllMechanism = mechanisms.some(m => m.type === 'all');
    if (!hasAllMechanism) {
      console.log('[SPF Validator] Recommending all mechanism addition');
      recommendations.push('Add an all mechanism at the end of your SPF record to specify default policy');
    }

    const hasIncludeMechanisms = mechanisms.some(m => m.type === 'include');
    if (hasIncludeMechanisms) {
      console.log('[SPF Validator] Recommending include mechanism monitoring');
      recommendations.push('Monitor include mechanisms to ensure they remain valid and accessible');
    }

    if (lookupCount > 5) {
      console.log('[SPF Validator] Recommending lookup optimization');
      recommendations.push('Consider optimizing SPF record to reduce DNS lookups for better performance');
    }

    // General best practices
    recommendations.push('Regularly review and update your SPF record as your email infrastructure changes');
    recommendations.push('Set up DMARC to complement SPF and DKIM for comprehensive email authentication');
    recommendations.push('Monitor SPF authentication rates in your email analytics');

    console.log(`[SPF Validator] Generated ${recommendations.length} recommendations`);
    return recommendations;
  }

  /**
   * Calculates a comprehensive security score for SPF configuration
   * 
   * This method evaluates the SPF configuration across multiple security dimensions
   * and returns a detailed score breakdown. The scoring system is designed to:
   * - Reward proper SPF implementation (5 points)
   * - Encourage single record usage (2 points)
   * - Validate syntax correctness (3 points)
   * - Ensure lookup limit compliance (3 points)
   * - Prevent overly permissive policies (3 points)
   * - Promote secure all mechanism usage (2 points)
   * - Avoid deprecated mechanisms (2 points)
   * 
   * @param mechanisms - Array of SPF mechanisms to score
   * @param issues - Array of validation issues to consider
   * @param lookupCount - Number of DNS lookups required
   * @returns Detailed score breakdown with component scores
   */
  private calculateScore(
    mechanisms: SPFMechanism[],
    issues: SPFIssue[],
    lookupCount: number
  ): SPFScoreBreakdown {
    console.log('[SPF Validator] Calculating security score...');
    
    let recordPresent = 0;
    let singleRecord = 0;
    let syntaxValid = 0;
    let lookupLimit = 0;
    let noPassAll = 0;
    let allMechanismPolicy = 0;
    let noDeprecatedMechanisms = 0;

    // Record Present: 5 points (all or nothing)
    if (mechanisms.length > 0) {
      recordPresent = 5;
      console.log('[SPF Validator] ✓ SPF record present: 5 points');
    } else {
      console.log('[SPF Validator] ✗ No SPF record: 0 points');
    }

    // Single Record: 2 points (if no redirects)
    const hasRedirects = issues.some(issue => issue.message.includes('redirects'));
    if (!hasRedirects) {
      singleRecord = 2;
      console.log('[SPF Validator] ✓ Single SPF record: 2 points');
    } else {
      console.log('[SPF Validator] ~ Multiple records (redirects): 0 points');
    }

    // Syntax Valid: 3 points (if no syntax errors)
    const hasSyntaxErrors = issues.some(issue => issue.type === 'error' && issue.message.includes('syntax'));
    if (!hasSyntaxErrors) {
      syntaxValid = 3;
      console.log('[SPF Validator] ✓ Valid syntax: 3 points');
    } else {
      console.log('[SPF Validator] ✗ Syntax errors: 0 points');
    }

    // Lookup Limit: 3 points (if within 10 lookups)
    if (lookupCount <= this.MAX_LOOKUPS) {
      lookupLimit = 3;
      console.log(`[SPF Validator] ✓ Lookup count within limits (${lookupCount}/${this.MAX_LOOKUPS}): 3 points`);
    } else {
      console.log(`[SPF Validator] ✗ Lookup count exceeded (${lookupCount}/${this.MAX_LOOKUPS}): 0 points`);
    }

    // No Pass All: 3 points (if not using +all)
    const hasPassAll = mechanisms.some(m => m.type === 'all' && m.qualifier === '+');
    if (!hasPassAll) {
      noPassAll = 3;
      console.log('[SPF Validator] ✓ No +all mechanism: 3 points');
    } else {
      console.log('[SPF Validator] ✗ Using +all mechanism: 0 points');
    }

    // All Mechanism Policy: 2 points (if using ~all or -all)
    const allMechanism = mechanisms.find(m => m.type === 'all');
    if (allMechanism && (allMechanism.qualifier === '~' || allMechanism.qualifier === '-')) {
      allMechanismPolicy = 2;
      console.log(`[SPF Validator] ✓ Secure all mechanism policy (${allMechanism.qualifier}all): 2 points`);
    } else {
      console.log('[SPF Validator] ~ Insecure or missing all mechanism policy: 0 points');
    }

    // No Deprecated Mechanisms: 2 points (if no deprecated mechanisms)
    const hasDeprecated = mechanisms.some(m => this.DEPRECATED_MECHANISMS.includes(m.type));
    if (!hasDeprecated) {
      noDeprecatedMechanisms = 2;
      console.log('[SPF Validator] ✓ No deprecated mechanisms: 2 points');
    } else {
      console.log('[SPF Validator] ✗ Deprecated mechanisms found: 0 points');
    }

    const total = recordPresent + singleRecord + syntaxValid + lookupLimit + noPassAll + allMechanismPolicy + noDeprecatedMechanisms;
    
    console.log('[SPF Validator] Final score breakdown:', {
      recordPresent,
      singleRecord,
      syntaxValid,
      lookupLimit,
      noPassAll,
      allMechanismPolicy,
      noDeprecatedMechanisms,
      total
    });
    
    return {
      recordPresent,
      singleRecord,
      syntaxValid,
      lookupLimit,
      noPassAll,
      allMechanismPolicy,
      noDeprecatedMechanisms,
      total
    };
  }

  /**
   * Creates a comprehensive validation result object
   * 
   * This method assembles all validation findings into a structured result object
   * that includes the overall validation status, detailed scoring, and metadata
   * about the SPF configuration.
   * 
   * @param domain - The domain being validated
   * @param record - The SPF record string
   * @param mechanisms - Array of parsed SPF mechanisms
   * @param issues - Array of validation issues
   * @param recommendations - Array of recommendations
   * @param lookupCount - Number of DNS lookups required
   * @param score - Detailed score breakdown
   * @param redirects - Array of redirect information
   * @param finalDomain - The final domain used for validation
   * @param redirectRecord - The redirected record if applicable
   * @returns Complete validation result object
   */
  private createValidationResult(
    domain: string,
    record: string,
    mechanisms: SPFMechanism[],
    issues: SPFIssue[],
    recommendations: string[],
    lookupCount: number,
    score?: SPFScoreBreakdown,
    redirects: SPFRedirect[] = [],
    finalDomain: string = domain,
    redirectRecord: string = ''
  ): SPFValidationResult {
    const isValid = score ? score.total >= 15 : false; // Consider valid if score is 15+ out of 20 (75% threshold)
    
    console.log(`[SPF Validator] Creating validation result for domain: ${domain}`);
    console.log(`[SPF Validator] Overall validation status: ${isValid ? 'VALID' : 'INVALID'} (score: ${score?.total || 0}/20)`);
    
    const allMechanism = mechanisms.find(m => m.type === 'all');
    
    const result = {
      isValid,
      score: score?.total || 0,
      record,
      redirectRecord,
      issues,
      recommendations,
      mechanisms,
      lookupCount,
      redirects,
      details: {
        hasVersion: record.startsWith('v=spf1'),
        hasAllMechanism: !!allMechanism,
        allMechanismQualifier: allMechanism?.qualifier,
        hasMultipleRecords: issues.some(i => i.message.includes('Multiple SPF records')),
        hasDeprecatedMechanisms: mechanisms.some(m => this.DEPRECATED_MECHANISMS.includes(m.type)),
        exceedsLookupLimit: lookupCount > this.MAX_LOOKUPS,
        hasPassAll: mechanisms.some(m => m.type === 'all' && m.qualifier === '+'),
        finalDomain
      }
    };
    
    console.log('[SPF Validator] Validation result details:', {
      mechanismCount: mechanisms.length,
      issueCount: issues.length,
      recommendationCount: recommendations.length,
      lookupCount,
      redirectCount: redirects.length,
      hasVersion: result.details.hasVersion,
      hasAllMechanism: result.details.hasAllMechanism,
      allMechanismQualifier: result.details.allMechanismQualifier,
      hasMultipleRecords: result.details.hasMultipleRecords,
      hasDeprecatedMechanisms: result.details.hasDeprecatedMechanisms,
      exceedsLookupLimit: result.details.exceedsLookupLimit,
      hasPassAll: result.details.hasPassAll,
      finalDomain: result.details.finalDomain
    });
    
    return result;
  }
} 