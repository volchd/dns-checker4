import { DNSValidator } from './dns-validator';
import { 
  SPFValidationResult, 
  SPFMechanism, 
  SPFIssue, 
  SPFQualifier,
  SPFScoreBreakdown,
  SPFRedirect
} from '../types/spf.types';

export class SPFValidator {
  private dnsValidator: DNSValidator;
  private readonly MAX_LOOKUPS = 10;
  private readonly DEPRECATED_MECHANISMS = ['ptr'];
  private readonly VALID_MECHANISMS = ['ip4', 'ip6', 'a', 'mx', 'include', 'exists', 'redirect', 'all'];
  private readonly MAX_REDIRECT_DEPTH = 2; // Prevent redirect loops

  constructor() {
    this.dnsValidator = new DNSValidator();
  }

  async validateSPF(
    domain: string, 
    redirectDepth: number = 0,
    redirects: SPFRedirect[] = []
  ): Promise<SPFValidationResult> {
    console.log(`Validating SPF for domain: ${domain} (redirect depth: ${redirectDepth})`);

    if (redirectDepth > this.MAX_REDIRECT_DEPTH) {
      console.log(`Maximum redirect depth (${this.MAX_REDIRECT_DEPTH}) exceeded for domain: ${domain}`);
      return this.createValidationResult(
        domain,
        '',
        [],
        [{
          type: 'error',
          message: 'Maximum redirect depth exceeded',
          recommendation: 'Check for redirect loops in SPF records'
        }],
        [],
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
        domain
      );
    }

    const issues: SPFIssue[] = [];
    const recommendations: string[] = [];
    let mechanisms: SPFMechanism[] = [];
    let lookupCount = 0;
    let record = '';

    // Get TXT records
    const txtRecords = await this.dnsValidator.getTXTRecords(domain);
    const spfRecords = txtRecords.filter(record => record.startsWith('v=spf1'));
    console.log(`Found ${spfRecords.length} SPF records for domain: ${domain}`);

    // Check for SPF record presence
    if (spfRecords.length === 0) {
      console.log(`No SPF record found for domain: ${domain}`);
      issues.push({
        type: 'error',
        message: 'No SPF record found',
        recommendation: 'Create an SPF record starting with v=spf1'
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
        domain
      );
    }

    // Check for multiple SPF records
    if (spfRecords.length > 1) {
      console.log(`Multiple SPF records found for domain: ${domain}`);
      issues.push({
        type: 'error',
        message: 'Multiple SPF records found',
        recommendation: 'Merge all SPF records into a single record'
      });
    }

    record = spfRecords[0];
    console.log(`Processing SPF record: ${record}`);
    mechanisms = this.parseMechanisms(record);
    console.log(`Parsed mechanisms:`, mechanisms);

    // Check for redirect mechanism
    const redirectMechanism = mechanisms.find(m => m.type === 'redirect');
    if (redirectMechanism && redirectMechanism.value) {
      const redirectDomain = redirectMechanism.value;
      console.log(`Found redirect to: ${redirectDomain}`);
      
      // Add this redirect to the chain
      const currentRedirect: SPFRedirect = {
        from: domain,
        to: redirectDomain,
        record: record
      };
      const updatedRedirects = [...redirects, currentRedirect];
      console.log(`Updated redirect chain:`, updatedRedirects);

      try {
        // Add a note about the redirect
        issues.push({
          type: 'info',
          message: `SPF record redirects to ${redirectDomain}`,
          recommendation: 'Ensure the redirect target is properly maintained'
        });

        console.log(`Following redirect to: ${redirectDomain}`);
        // Validate the redirect domain
        const redirectResult = await this.validateSPF(
          redirectDomain, 
          redirectDepth + 1,
          updatedRedirects
        );
        console.log(`Redirect validation result for ${redirectDomain}:`, redirectResult);
        
        // Merge issues and recommendations
        issues.push(...redirectResult.issues.map(issue => ({
          ...issue,
          message: `Redirect (${redirectDomain}): ${issue.message}`
        })));
        recommendations.push(...redirectResult.recommendations);
        
        // Use the redirected domain's mechanisms and lookup count
        mechanisms = redirectResult.mechanisms;
        lookupCount = redirectResult.lookupCount;
        
        // Calculate score for the final result
        const score = this.calculateScore(mechanisms, issues, lookupCount);
        console.log(`Calculated score for ${domain} after redirect:`, score);
        console.log(`Original record: ${record}`);
        console.log(`Redirect record: ${redirectResult.record}`);

        // Return the redirect result with the updated redirect chain
        const result = {
          isValid: redirectResult.isValid,
          score: score.total,
          record: record,
          redirectRecord: redirectResult.record,
          issues,
          recommendations,
          mechanisms,
          lookupCount,
          redirects: updatedRedirects,
          details: {
            ...redirectResult.details,
            finalDomain: redirectDomain
          }
        };
        console.log(`Returning final result for ${domain}:`, result);
        return result;
      } catch (error) {
        console.error(`Error validating redirect to ${redirectDomain}:`, error);
        // If redirect validation fails, add it as an issue
        issues.push({
          type: 'error',
          message: `Failed to validate redirect to ${redirectDomain}: ${error instanceof Error ? error.message : 'Unknown error'}`,
          recommendation: 'Check if the redirect target domain is accessible and has a valid SPF record'
        });
        // Continue with the current domain's validation
      }
    }

    // If no redirect or redirect failed, validate current mechanisms
    console.log(`No redirect found or redirect failed, validating current mechanisms for ${domain}`);
    lookupCount = this.calculateLookupCount(mechanisms);

    // Validate mechanisms (excluding redirect as it's already handled)
    const mechanismIssues = this.validateMechanisms(
      mechanisms.filter(m => m.type !== 'redirect')
    );
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
      domain
    );
    console.log(`Returning result for ${domain}:`, result);
    return result;
  }

  private parseMechanisms(record: string): SPFMechanism[] {
    const mechanisms: SPFMechanism[] = [];
    const parts = record.split(' ');

    // Skip the version part
    for (let i = 1; i < parts.length; i++) {
      const part = parts[i];
      const qualifier = this.getQualifier(part);
      const cleanPart = part.replace(/^[+\-~?]/, '');
      
      let type: string;
      let value: string | undefined;
      
      // Handle both colon and equals sign separators
      if (cleanPart.includes('=')) {
        [type, value] = cleanPart.split('=');
      } else if (cleanPart.includes(':')) {
        [type, value] = cleanPart.split(':');
      } else {
        type = cleanPart;
        value = undefined;
      }
      
      if (this.VALID_MECHANISMS.includes(type)) {
        mechanisms.push({
          type,
          value,
          qualifier
        });
      }
    }

    return mechanisms;
  }

  private getQualifier(mechanism: string): SPFQualifier {
    if (mechanism.startsWith('-')) return '-';
    if (mechanism.startsWith('~')) return '~';
    if (mechanism.startsWith('?')) return '?';
    return '+';
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
    finalDomain: string = domain
  ): SPFValidationResult {
    const allMechanism = mechanisms.find(m => m.type === 'all');
    
    return {
      isValid: issues.filter(i => i.type === 'error').length === 0,
      score: score?.total ?? 0,
      record,
      redirectRecord: '',
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