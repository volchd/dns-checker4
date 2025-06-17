import { SPFService } from './spf.service';

/**
 * Example usage of the unified SPF service from other services or controllers
 * This demonstrates how to use the SPF service as a single call service
 */

export class ExampleService {
  private spfService: SPFService;

  constructor() {
    this.spfService = new SPFService();
  }

  /**
   * Example: Using SPF service from another service
   */
  async analyzeDomainSecurity(domain: string) {
    console.log(`🔍 Analyzing security for domain: ${domain}`);

    // Single call to SPF service
    const spfResult = await this.spfService.getSPFRecordForDomain(domain);

    // Check if it's an error response
    if (this.spfService.isErrorResponse(spfResult)) {
      console.error(`❌ Failed to get SPF record: ${spfResult.error}`);
      return {
        domain,
        spfStatus: 'error',
        spfError: spfResult.error,
        securityScore: 0
      };
    }

    // Process successful SPF result
    console.log(`✅ SPF record found for ${domain}`);
    
    const securityAnalysis = {
      domain,
      spfStatus: 'valid',
      hasRedirects: spfResult.hasRedirects,
      mechanismCount: spfResult.summary.totalMechanisms,
      securityScore: this.calculateSecurityScore(spfResult),
      spfData: spfResult
    };

    return securityAnalysis;
  }

  /**
   * Example: Using SPF service for bulk domain checking
   */
  async checkMultipleDomains(domains: string[]) {
    const results = [];

    for (const domain of domains) {
      const result = await this.spfService.getSPFRecordForDomain(domain);
      
      if (this.spfService.isSuccessResponse(result)) {
        results.push({
          domain,
          status: 'success',
          hasSPF: true,
          mechanismCount: result.summary.totalMechanisms
        });
      } else {
        results.push({
          domain,
          status: 'error',
          hasSPF: false,
          error: result.error
        });
      }
    }

    return results;
  }

  /**
   * Example: Using SPF service for validation in another service
   */
  async validateEmailDomain(email: string) {
    const domain = email.split('@')[1];
    if (!domain) {
      return { isValid: false, error: 'Invalid email format' };
    }

    const spfResult = await this.spfService.getSPFRecordForDomain(domain);
    
    if (this.spfService.isErrorResponse(spfResult)) {
      return {
        isValid: false,
        error: `Domain ${domain} has no SPF record`,
        details: spfResult.error
      };
    }

    return {
      isValid: true,
      domain,
      hasSPF: true,
      spfRecord: spfResult.record
    };
  }

  private calculateSecurityScore(spfResult: any): number {
    // Example scoring logic
    let score = 100;
    
    if (spfResult.hasRedirects) {
      score -= 10; // Redirects can be a security concern
    }
    
    if (spfResult.summary.totalMechanisms === 0) {
      score -= 50; // No mechanisms means no protection
    }
    
    return Math.max(0, score);
  }
}

/**
 * Example: Using SPF service from a controller
 */
export class ExampleController {
  private spfService: SPFService;

  constructor() {
    this.spfService = new SPFService();
  }

  async handleSPFRequest(domain: string) {
    // Single call to service
    const result = await this.spfService.getSPFRecordForDomain(domain);

    // Handle response based on type
    if (this.spfService.isErrorResponse(result)) {
      // Return appropriate error response
      const statusCode = result.error === 'No SPF record found for the domain' ? 404 : 400;
      return { status: statusCode, data: result };
    }

    // Return successful response
    return { status: 200, data: result };
  }
} 