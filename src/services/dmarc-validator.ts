import { DMARCService, DMARCResponse, DMARCErrorResponse } from './dmarc.service';
import { 
  DMARCValidationResult, 
  DMARCIssue, 
  DMARCScoreBreakdown,
  DMARCRecord,
  DMARCPolicy
} from '../types/dmarc.types';

/**
 * DMARC Validator Service
 * 
 * This service provides comprehensive validation of DMARC (Domain-based Message Authentication, 
 * Reporting & Conformance) records for email domains. DMARC is an email authentication protocol 
 * that helps prevent email spoofing by allowing domain owners to specify how their emails should 
 * be handled when authentication fails.
 * 
 * Key Features:
 * - Validates DMARC record syntax and structure
 * - Checks required and optional tags
 * - Evaluates policy enforcement levels
 * - Analyzes reporting configuration
 * - Provides scoring and recommendations
 * 
 * Security Considerations:
 * - Version tag must be v=DMARC1; and must be first
 * - Policy tag (p=) is required and must be none, quarantine, or reject
 * - Subdomain policy should be considered for comprehensive protection
 * - Reporting addresses should be properly formatted
 * - Percentage should be 100 for full enforcement
 */
export class DMARCValidator {
  private dmarcService: DMARCService;
  
  // DMARC validation constants
  private readonly VALID_POLICIES: DMARCPolicy[] = ['none', 'quarantine', 'reject'];
  private readonly VALID_ALIGNMENT_MODES = ['r', 's'];
  private readonly VALID_FAILURE_OPTIONS = ['0', '1', 'd', 's'];
  private readonly MIN_PERCENTAGE = 1;
  private readonly MAX_PERCENTAGE = 100;
  private readonly DEFAULT_PERCENTAGE = 100;
  private readonly DEFAULT_REPORT_INTERVAL = 86400; // 24 hours in seconds

  constructor() {
    this.dmarcService = new DMARCService();
    console.log('[DMARC Validator] Initialized with validation rules');
  }

  /**
   * Main validation method for DMARC records
   * 
   * This method performs a comprehensive validation of DMARC records for a given domain.
   * It checks for the presence of DMARC records, validates their syntax, analyzes policy
   * configuration, and provides security recommendations.
   * 
   * @param domain - The domain to validate DMARC records for
   * @returns Promise<DMARCValidationResult> - Complete validation results with scoring
   */
  async validateDMARC(domain: string): Promise<DMARCValidationResult> {
    console.log(`[DMARC Validator] Starting validation for domain: ${domain}`);

    const issues: DMARCIssue[] = [];
    const recommendations: string[] = [];
    let record = '';
    let parsedRecord: DMARCRecord | null = null;
    let finalDomain = domain;

    // Step 1: Retrieve DMARC record using DMARC service
    console.log(`[DMARC Validator] Retrieving DMARC record for domain: ${domain}`);
    const dmarcResult = await this.dmarcService.getDMARCRecordForDomain(domain);
    
    if (this.dmarcService.isErrorResponse(dmarcResult)) {
      console.error(`[DMARC Validator] Error retrieving DMARC record for domain: ${domain}:`, dmarcResult.error);
      issues.push({
        type: 'error',
        message: dmarcResult.error,
        recommendation: dmarcResult.suggestion || 'Check if the domain has a valid DMARC record in DNS'
      });
      
      return this.createValidationResult(
        domain,
        '',
        null,
        issues,
        recommendations,
        0,
        {
          dmarcImplemented: 0,
          validPolicy: 0,
          subdomainPolicy: 0,
          alignmentMode: 0,
          reports: 0,
          percentage: 0,
          total: 0
        },
        finalDomain
      );
    }

    const dmarcResponse = dmarcResult as DMARCResponse;
    console.log(`[DMARC Validator] ✓ Successfully retrieved DMARC record for domain: ${domain}`);

    // Step 2: Extract record data
    record = dmarcResponse.record;
    parsedRecord = dmarcResponse.parsed;
    finalDomain = dmarcResponse.domain;
    
    console.log(`[DMARC Validator] Using DMARC record: ${record}`);

    // Step 3: Validate DMARC record structure
    console.log('[DMARC Validator] Starting DMARC record validation...');
    const structureIssues = this.validateDMARCStructure(parsedRecord, record);
    console.log(`[DMARC Validator] Structure validation found ${structureIssues.length} issue(s)`);
    issues.push(...structureIssues);

    // Step 4: Validate policy configuration
    console.log('[DMARC Validator] Validating policy configuration...');
    const policyIssues = this.validatePolicyConfiguration(parsedRecord);
    console.log(`[DMARC Validator] Policy validation found ${policyIssues.length} issue(s)`);
    issues.push(...policyIssues);

    // Step 5: Validate optional tags
    console.log('[DMARC Validator] Validating optional tags...');
    const optionalIssues = this.validateOptionalTags(parsedRecord);
    console.log(`[DMARC Validator] Optional tag validation found ${optionalIssues.length} issue(s)`);
    issues.push(...optionalIssues);

    // Step 6: Generate recommendations
    console.log('[DMARC Validator] Generating recommendations...');
    recommendations.push(...this.generateRecommendations(parsedRecord, issues));

    // Step 7: Calculate security score
    const score = this.calculateScore(parsedRecord, issues);
    console.log(`[DMARC Validator] Calculated security score: ${score.total}/29`, score);

    const result = this.createValidationResult(
      domain,
      record,
      parsedRecord,
      issues,
      recommendations,
      score.total,
      score,
      finalDomain
    );
    
    console.log(`[DMARC Validator] Validation complete for domain: ${domain}`);
    return result;
  }

  /**
   * Validates the basic structure and required elements of a DMARC record
   */
  private validateDMARCStructure(parsedRecord: DMARCRecord, rawRecord: string): DMARCIssue[] {
    const issues: DMARCIssue[] = [];

    // Check if record starts with v=DMARC1;
    if (!rawRecord.trim().startsWith('v=DMARC1;')) {
      issues.push({
        type: 'error',
        message: 'DMARC record must start with v=DMARC1;',
        recommendation: 'Ensure the version tag is present and is the first tag in the record'
      });
    }

    // Check if version is present and valid
    if (!parsedRecord.version || parsedRecord.version !== 'DMARC1') {
      issues.push({
        type: 'error',
        message: 'Invalid or missing version tag',
        recommendation: 'DMARC record must include v=DMARC1; as the first tag'
      });
    }

    // Check if policy is present
    if (!parsedRecord.policy) {
      issues.push({
        type: 'error',
        message: 'Missing required policy tag (p=)',
        recommendation: 'Add a policy tag with one of: none, quarantine, or reject'
      });
    }

    return issues;
  }

  /**
   * Validates the policy configuration and enforcement settings
   */
  private validatePolicyConfiguration(parsedRecord: DMARCRecord): DMARCIssue[] {
    const issues: DMARCIssue[] = [];

    // Validate main policy
    if (parsedRecord.policy && !this.VALID_POLICIES.includes(parsedRecord.policy)) {
      issues.push({
        type: 'error',
        message: `Invalid policy value: ${parsedRecord.policy}`,
        recommendation: `Policy must be one of: ${this.VALID_POLICIES.join(', ')}`
      });
    }

    // Validate subdomain policy if present
    if (parsedRecord.subdomainPolicy && !this.VALID_POLICIES.includes(parsedRecord.subdomainPolicy)) {
      issues.push({
        type: 'error',
        message: `Invalid subdomain policy value: ${parsedRecord.subdomainPolicy}`,
        recommendation: `Subdomain policy must be one of: ${this.VALID_POLICIES.join(', ')}`
      });
    }

    // Check if policy is set to none (monitoring only)
    if (parsedRecord.policy === 'none') {
      issues.push({
        type: 'warning',
        message: 'DMARC policy is set to none (monitoring only)',
        recommendation: 'Consider moving to quarantine or reject policy for better protection against email spoofing'
      });
    }

    return issues;
  }

  /**
   * Validates optional DMARC tags
   */
  private validateOptionalTags(parsedRecord: DMARCRecord): DMARCIssue[] {
    const issues: DMARCIssue[] = [];

    // Validate percentage
    if (parsedRecord.percentage !== undefined) {
      if (parsedRecord.percentage < this.MIN_PERCENTAGE || parsedRecord.percentage > this.MAX_PERCENTAGE) {
        issues.push({
          type: 'error',
          message: `Invalid percentage value: ${parsedRecord.percentage}`,
          recommendation: `Percentage must be between ${this.MIN_PERCENTAGE} and ${this.MAX_PERCENTAGE}`
        });
      } else if (parsedRecord.percentage < 100 && parsedRecord.policy !== 'none') {
        issues.push({
          type: 'warning',
          message: `Policy is applied to only ${parsedRecord.percentage}% of emails`,
          recommendation: 'Consider setting percentage to 100 for full protection'
        });
      }
    }

    // Validate alignment modes
    if (parsedRecord.adkim && !this.VALID_ALIGNMENT_MODES.includes(parsedRecord.adkim)) {
      issues.push({
        type: 'error',
        message: `Invalid adkim value: ${parsedRecord.adkim}`,
        recommendation: `adkim must be one of: ${this.VALID_ALIGNMENT_MODES.join(', ')}`
      });
    }

    if (parsedRecord.aspf && !this.VALID_ALIGNMENT_MODES.includes(parsedRecord.aspf)) {
      issues.push({
        type: 'error',
        message: `Invalid aspf value: ${parsedRecord.aspf}`,
        recommendation: `aspf must be one of: ${this.VALID_ALIGNMENT_MODES.join(', ')}`
      });
    }

    // Validate failure options
    if (parsedRecord.failureOptions) {
      for (const option of parsedRecord.failureOptions) {
        if (!this.VALID_FAILURE_OPTIONS.includes(option)) {
          issues.push({
            type: 'error',
            message: `Invalid failure option: ${option}`,
            recommendation: `Failure options must be one of: ${this.VALID_FAILURE_OPTIONS.join(', ')}`
          });
        }
      }
    }

    // Validate reports
    if (parsedRecord.reports) {
      for (const report of parsedRecord.reports) {
        if (!report.uri.startsWith('mailto:')) {
          issues.push({
            type: 'warning',
            message: `Report URI should use mailto: protocol: ${report.uri}`,
            recommendation: 'Use mailto: protocol for report URIs'
          });
        }
      }
    }

    return issues;
  }

  /**
   * Generates recommendations based on DMARC configuration and issues
   */
  private generateRecommendations(parsedRecord: DMARCRecord, issues: DMARCIssue[]): string[] {
    const recommendations: string[] = [];

    // Policy recommendations
    if (parsedRecord.policy === 'none') {
      recommendations.push('Consider moving from monitoring (none) to enforcement (quarantine or reject)');
    }

    if (parsedRecord.policy === 'quarantine') {
      recommendations.push('Consider moving to reject policy for maximum protection against email spoofing');
    }

    // Percentage recommendations
    if (parsedRecord.percentage !== undefined && parsedRecord.percentage < 100 && parsedRecord.policy !== 'none') {
      recommendations.push('Set percentage to 100 for full policy enforcement');
    }

    // Subdomain policy recommendations
    if (!parsedRecord.subdomainPolicy && parsedRecord.policy !== 'none') {
      recommendations.push('Consider adding subdomain policy (sp=) to protect subdomains');
    }

    // Reporting recommendations
    if (!parsedRecord.reports || parsedRecord.reports.length === 0) {
      recommendations.push('Add reporting addresses (rua=) to receive DMARC aggregate reports');
    }

    // Alignment recommendations
    if (parsedRecord.adkim === 's' || parsedRecord.aspf === 's') {
      recommendations.push('Strict alignment mode is configured - ensure all sending domains are properly aligned');
    }

    // General security recommendations
    if (parsedRecord.policy === 'reject') {
      recommendations.push('DMARC is properly configured with reject policy - excellent security posture');
    }

    return recommendations;
  }

  /**
   * Calculates a security score based on DMARC configuration
   */
  private calculateScore(parsedRecord: DMARCRecord, issues: DMARCIssue[]): DMARCScoreBreakdown {
    let dmarcImplemented = 0;
    let validPolicy = 0;
    let subdomainPolicy = 0;
    let alignmentMode = 0;
    let reports = 0;
    let percentage = 0;

    // DMARC Implementation (10 points - all or nothing)
    const hasCriticalErrors = issues.some(issue => issue.type === 'error' && 
      (issue.message.includes('must start with v=DMARC1') || 
       issue.message.includes('Missing required policy tag')));
    
    if (!hasCriticalErrors) {
      dmarcImplemented = 10;
    }

    // Valid Policy (10 points)
    if (parsedRecord.policy === 'reject') {
      validPolicy = 10; // Full enforcement
    } else if (parsedRecord.policy === 'quarantine') {
      validPolicy = 8;  // Partial enforcement
    } else if (parsedRecord.policy === 'none') {
      validPolicy = 3;  // Monitor only, no protection
    }

    // Subdomain Policy (3 points)
    // Give points if subdomain policy is set (and not weaker than main policy) 
    // OR if no significant subdomains exist (common case)
    if (parsedRecord.subdomainPolicy) {
      if (parsedRecord.subdomainPolicy === 'none') {
        // Explicitly set to none - no points (subdomains are unprotected)
        subdomainPolicy = 0;
      } else {
        // Check if subdomain policy is not weaker than main policy
        const policyStrength = { 'none': 0, 'quarantine': 1, 'reject': 2 };
        const mainPolicyStrength = policyStrength[parsedRecord.policy as keyof typeof policyStrength] || 0;
        const subPolicyStrength = policyStrength[parsedRecord.subdomainPolicy as keyof typeof policyStrength] || 0;
        
        if (subPolicyStrength >= mainPolicyStrength) {
          subdomainPolicy = 3;
        }
      }
    } else {
      // No subdomain policy specified - assume no significant subdomains exist
      // This is the common case for most domains and should get full points
      subdomainPolicy = 3;
    }

    // Alignment Mode (2 points)
    // Give points if alignment is left at default (relaxed) or set to strict consistently
    const hasAdkim = parsedRecord.adkim !== undefined;
    const hasAspf = parsedRecord.aspf !== undefined;
    const adkimValid = !hasAdkim || this.VALID_ALIGNMENT_MODES.includes(parsedRecord.adkim!);
    const aspfValid = !hasAspf || this.VALID_ALIGNMENT_MODES.includes(parsedRecord.aspf!);
    
    if (adkimValid && aspfValid) {
      alignmentMode = 2;
    }

    // Reports (2 points)
    if (parsedRecord.reports && parsedRecord.reports.length > 0) {
      reports = 2;
    }

    // Percentage (2 points)
    if (parsedRecord.policy === 'none') {
      // Not applicable for none policy - no points
      percentage = 0;
    } else if (parsedRecord.percentage === 100) {
      // Full coverage
      percentage = 2;
    } else if (parsedRecord.percentage && parsedRecord.percentage >= 50) {
      // Partial coverage (50-99%)
      percentage = 1;
    } else if (parsedRecord.percentage && parsedRecord.percentage < 50) {
      // Very low coverage
      percentage = 0;
    } else {
      // No percentage specified, default to 100%
      percentage = 2;
    }

    const total = dmarcImplemented + validPolicy + subdomainPolicy + alignmentMode + reports + percentage;

    return {
      dmarcImplemented,
      validPolicy,
      subdomainPolicy,
      alignmentMode,
      reports,
      percentage,
      total
    };
  }

  /**
   * Creates a validation result object
   */
  private createValidationResult(
    domain: string,
    record: string,
    parsedRecord: DMARCRecord | null,
    issues: DMARCIssue[],
    recommendations: string[],
    score: number,
    scoreBreakdown: DMARCScoreBreakdown,
    finalDomain: string = domain
  ): DMARCValidationResult {
    const hasErrors = issues.some(issue => issue.type === 'error');
    const hasWarnings = issues.some(issue => issue.type === 'warning');

    return {
      isValid: !hasErrors,
      score,
      record,
      issues,
      recommendations,
      details: {
        hasVersion: parsedRecord?.version === 'DMARC1',
        hasValidPolicy: parsedRecord?.policy ? this.VALID_POLICIES.includes(parsedRecord.policy) : false,
        hasSubdomainPolicy: !!parsedRecord?.subdomainPolicy,
        hasPercentage: parsedRecord?.percentage !== undefined,
        hasReports: !!(parsedRecord?.reports && parsedRecord.reports.length > 0),
        hasFailureOptions: !!(parsedRecord?.failureOptions && parsedRecord.failureOptions.length > 0),
        hasAdkim: !!parsedRecord?.adkim,
        hasAspf: !!parsedRecord?.aspf,
        finalDomain
      }
    };
  }
} 