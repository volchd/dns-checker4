import { Context } from 'hono';
import { ValidateDomainService } from '../services/validate-domain.service';

/**
 * Controller for handling domain validation requests
 * Provides endpoints to validate domains comprehensively including DNS, SPF, DKIM, and DMARC
 */
export class ValidateDomainController {
  private validateDomainService: ValidateDomainService;

  constructor() {
    this.validateDomainService = new ValidateDomainService();
    console.log('🚀 ValidateDomainController initialized');
  }

  /**
   * Handles GET requests for domain validation
   * Performs comprehensive validation of a domain including:
   * - DNS existence validation
   * - SPF record validation and scoring
   * - DKIM record validation and scoring
   * - DMARC record validation and scoring
   * 
   * Query Parameters:
   * - domain: The domain to validate (required)
   * 
   * Response includes:
   * - Total security score out of 100
   * - Individual scores for SPF, DKIM, and DMARC
   * - Detailed validation results for each component
   * - Issues and recommendations for improvement
   * 
   * @param c - Hono context object
   * @returns JSON response with comprehensive domain validation results
   */
  async validateDomain(c: Context) {
    console.log('📥 Received domain validation request');
    
    // Extract domain from query parameters
    const domain = c.req.query('domain');
    console.log(`🔍 Requested domain: ${domain || 'NOT PROVIDED'}`);

    // Make single call to service for complete domain validation
    const result = await this.validateDomainService.validateDomain(domain || '');

    // Check if result is an error response
    if (this.validateDomainService.isErrorResponse(result)) {
      console.error(`❌ Domain validation service returned error: ${result.error}`);
      
      // Determine appropriate status code based on error type
      if (result.error === 'Domain does not exist or has no DNS records') {
        return c.json(result, 404);
      } else if (result.error === 'Domain parameter is required' || result.error === 'Invalid domain format') {
        return c.json(result, 400);
      } else {
        return c.json(result, 500);
      }
    }

    console.log(`📤 Sending successful validation response for domain: ${domain}`);
    return c.json(result);
  }
} 