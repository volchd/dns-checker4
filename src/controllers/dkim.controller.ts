import { Context } from 'hono';
import { DKIMService } from '../services/dkim.service';

/**
 * Controller for handling DKIM (DomainKeys Identified Mail) record requests
 * Provides endpoints to fetch and analyze DKIM records
 */
export class DKIMController {
  private dkimService: DKIMService;

  constructor() {
    this.dkimService = new DKIMService();
    console.log('🚀 DKIMController initialized');
  }

  /**
   * Handles GET requests for DKIM records
   * Fetches DKIM record for a domain with optional selector
   * 
   * Query Parameters:
   * - domain: The domain to fetch DKIM record for (required)
   * - selector: The selector to use (optional, defaults to 'default')
   * 
   * Response includes:
   * - Raw DKIM record
   * - Parsed DKIM record components
   * - Summary information
   * - Metadata
   * 
   * @param c - Hono context object
   * @returns JSON response with DKIM record information
   */
  async getDKIMRecord(c: Context) {
    console.log('📥 Received DKIM record request');
    
    // Extract parameters from query
    const domain = c.req.query('domain');
    const selector = c.req.query('selector');
    
    console.log(`🔍 Requested domain: ${domain || 'NOT PROVIDED'}`);
    if (selector) {
      console.log(`🔍 Requested selector: ${selector}`);
    }

    // Make single call to service for complete DKIM record processing
    const result = await this.dkimService.getDKIMRecordForDomain(domain || '', selector);

    // Check if result is an error response
    if (this.dkimService.isErrorResponse(result)) {
      console.error(`❌ DKIM service returned error: ${result.error}`);
      
      // Determine appropriate status code based on error type
      if (result.error.includes('No DKIM record found')) {
        return c.json(result, 404);
      } else if (result.error === 'Failed to fetch DKIM record') {
        return c.json(result, 500);
      } else {
        return c.json(result, 400);
      }
    }

    console.log(`📤 Sending successful response for domain: ${result.domain}`);
    return c.json(result);
  }
} 