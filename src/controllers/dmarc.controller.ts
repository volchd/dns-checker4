import { Context } from 'hono';
import { DMARCService } from '../services/dmarc.service';

/**
 * Controller for handling DMARC (Domain-based Message Authentication, Reporting & Conformance) record requests
 * Provides endpoints to fetch and analyze DMARC records
 */
export class DMARCController {
  private dmarcService: DMARCService;

  constructor() {
    this.dmarcService = new DMARCService();
    console.log('🚀 DMARCController initialized');
  }

  /**
   * Handles GET requests for DMARC records
   * Fetches DMARC record for a domain
   * 
   * Query Parameters:
   * - domain: The domain to fetch DMARC record for (required)
   * 
   * Response includes:
   * - Raw DMARC record
   * - Parsed DMARC record components
   * - Summary information
   * - Metadata
   * 
   * @param c - Hono context object
   * @returns JSON response with DMARC record information
   */
  async getDMARCRecord(c: Context) {
    console.log('📥 Received DMARC record request');
    
    // Extract domain from query parameters
    const domain = c.req.query('domain');
    console.log(`🔍 Requested domain: ${domain || 'NOT PROVIDED'}`);

    // Make single call to service for complete DMARC record processing
    const result = await this.dmarcService.getDMARCRecordForDomain(domain || '');

    // Check if result is an error response
    if (this.dmarcService.isErrorResponse(result)) {
      console.error(`❌ DMARC service returned error: ${result.error}`);
      
      // Determine appropriate status code based on error type
      if (result.error === 'No DMARC record found for the domain') {
        return c.json(result, 404);
      } else if (result.error === 'Multiple DMARC records found for the domain') {
        return c.json(result, 409); // Conflict - multiple records
      } else if (result.error === 'Failed to fetch DMARC record') {
        return c.json(result, 500);
      } else {
        return c.json(result, 400);
      }
    }

    console.log(`📤 Sending successful response for domain: ${result.domain}`);
    return c.json(result);
  }
} 