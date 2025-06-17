import { SPFService, SPFResponse, SPFErrorResponse } from './spf.service';
import { 
  SPFValidationResult, 
  SPFMechanism, 
  SPFIssue, 
  SPFQualifier,
  SPFScoreBreakdown,
  SPFRedirect
} from '../types/spf.types';

export class SPFValidator {
  private spfService: SPFService;
  private readonly MAX_LOOKUPS = 10;
  private readonly DEPRECATED_MECHANISMS = ['ptr'];
  private readonly VALID_MECHANISMS = ['ip4', 'ip6', 'a', 'mx', 'include', 'exists', 'redirect', 'all'];
  private readonly MAX_REDIRECT_DEPTH = 2; // Prevent redirect loops

  constructor() {
    this.spfService = new SPFService();
  }

  async validateSPF(domain: string): Promise<SPFValidationResult> {
    console.log(`Validating SPF for domain: ${domain}`);

    const issues: SPFIssue[] = [];
    const recommendations: string[] = [];
    let mechanisms: SPFMechanism[] = [];
    let lookupCount = 0;
    let record = '';
    let redirectRecord = '';
    let redirects: SPFRedirect[] = [];
    let finalDomain = domain;

    // Get SPF record using SPF service
    const spfResult = await this.spfService.getSPFRecordForDomain(domain);
    
    if (this.spfService.isErrorResponse(spfResult)) {
      console.log(`Error getting SPF record for domain: ${domain}: ${spfResult.error}`);
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
    console.log(`Successfully retrieved SPF record for domain: ${domain}`);

    // Handle redirects if present
    if (spfResponse.hasRedirects && spfResponse.redirectedRecord) {
      console.log(`SPF record has redirects, using redirected record for validation`);
      
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
      
      console.log(`Using redirected record from ${finalDomain}: ${redirectRecord}`);
    } else {
      // Use the original record for validation
      record = spfResponse.record;
      mechanisms = this.convertSPFServiceMechanisms(spfResponse.mechanisms);
      redirects = spfResponse.redirects || [];
      finalDomain = spfResponse.finalDomain || domain;
      
      console.log(`Using original record: ${record}`);
    }

    console.log(`Parsed mechanisms:`, mechanisms);

    // Calculate lookup count
    lookupCount = this.calculateLookupCount(mechanisms);

    // Validate mechanisms
    const mechanismIssues = this.validateMechanisms(mechanisms);
    issues.push(...mechanismIssues);

    // Generate recommendations
    recommendations.push(...this.generateRecommendations(mechanisms, issues));

    // Calculate score
    const score = this.calculateScore(mechanisms, issues, lookupCount);
    console.log(`Calculated score for ${domain}:`, score);

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
    console.log(`Returning result for ${domain}:`, result);
    return result;
  }

  /**
   * Convert SPF service mechanism format to validator mechanism format
   */
  private convertSPFServiceMechanisms(serviceMechanisms: any[]): SPFMechanism[] {
    return serviceMechanisms.map(mech => ({
      type: mech.type,
      value: mech.value,
      qualifier: mech.qualifier || '+' as SPFQualifier
    }));
  }

  private validateMechanisms(mechanisms: SPFMechanism[]): SPFIssue[] {
    const issues: SPFIssue[] = [];

    // Check for deprecated mechanisms
    const deprecated = mechanisms.filter(m => this.DEPRECATED_MECHANISMS.includes(m.type));
    if (deprecated.length > 0) {
      issues.push({
        type: 'warning',
        message: 'Deprecated mechanisms found',
        recommendation: 'Replace deprecated mechanisms with ip4/ip6 or include mechanisms'
      });
    }

    // Check for all mechanism
    const allMechanism = mechanisms.find(m => m.type === 'all');
    if (!allMechanism) {
      issues.push({
        type: 'error',
        message: 'Missing all mechanism',
        recommendation: 'Add an all mechanism (preferably ~all or -all) at the end of your SPF record'
      });
    } else if (allMechanism.qualifier === '+') {
      issues.push({
        type: 'error',
        message: 'Using +all mechanism',
        recommendation: 'Replace +all with ~all or -all to properly restrict unauthorized senders'
      });
    }

    return issues;
  }

  private calculateLookupCount(mechanisms: SPFMechanism[]): number {
    return mechanisms.reduce((count, mechanism) => {
      switch (mechanism.type) {
        case 'include':
        case 'a':
        case 'mx':
        case 'exists':
        case 'redirect':
          return count + 1;
        default:
          return count;
      }
    }, 0);
  }

  private generateRecommendations(
    mechanisms: SPFMechanism[], 
    issues: SPFIssue[]
  ): string[] {
    const recommendations: string[] = [];

    // Add recommendations based on issues
    issues.forEach(issue => {
      if (issue.recommendation) {
        recommendations.push(issue.recommendation);
      }
    });

    // Add general recommendations
    const lookupCount = this.calculateLookupCount(mechanisms);
    if (lookupCount > this.MAX_LOOKUPS) {
      recommendations.push(
        'Consider using SPF flattening or subdomains to reduce DNS lookups below 10'
      );
    }

    return [...new Set(recommendations)]; // Remove duplicates
  }

  private calculateScore(
    mechanisms: SPFMechanism[],
    issues: SPFIssue[],
    lookupCount: number
  ): SPFScoreBreakdown {
    const breakdown: SPFScoreBreakdown = {
      recordPresent: 10,
      singleRecord: 5,
      syntaxValid: 5,
      lookupLimit: 5,
      noPassAll: 5,
      allMechanismPolicy: 0,
      noDeprecatedMechanisms: 2,
      total: 0
    };

    // Check for multiple records
    if (issues.some(i => i.message.includes('Multiple SPF records'))) {
      breakdown.singleRecord = 0;
    }

    // Check lookup limit
    if (lookupCount > this.MAX_LOOKUPS) {
      breakdown.lookupLimit = 0;
    }

    // Check for pass all
    if (mechanisms.some(m => m.type === 'all' && m.qualifier === '+')) {
      breakdown.noPassAll = 0;
    }

    // Check all mechanism policy
    const allMechanism = mechanisms.find(m => m.type === 'all');
    if (allMechanism) {
      switch (allMechanism.qualifier) {
        case '-':
          breakdown.allMechanismPolicy = 5;
          break;
        case '~':
          breakdown.allMechanismPolicy = 3;
          break;
        default:
          breakdown.allMechanismPolicy = 0;
      }
    }

    // Check for deprecated mechanisms
    if (mechanisms.some(m => this.DEPRECATED_MECHANISMS.includes(m.type))) {
      breakdown.noDeprecatedMechanisms = 0;
    }

    // Calculate total
    breakdown.total = Object.values(breakdown).reduce((sum, score) => 
      typeof score === 'number' ? sum + score : sum, 0);

    return breakdown;
  }

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
    const allMechanism = mechanisms.find(m => m.type === 'all');
    
    return {
      isValid: issues.filter(i => i.type === 'error').length === 0,
      score: score?.total ?? 0,
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
  }
} 