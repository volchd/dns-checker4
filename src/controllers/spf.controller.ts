import { Context } from 'hono';
import { SPFService } from '../services/spf.service';

/**
 * Controller for handling SPF (Sender Policy Framework) record requests
 * Provides endpoints to fetch and analyze SPF records with redirect support
 */
export class SPFController {
  private spfService: SPFService;

  constructor() {
    this.spfService = new SPFService();
    console.log('🚀 SPFController initialized');
  }

  /**
   * Handles GET requests for SPF records
   * Fetches SPF record for a domain and handles redirects if present
   * 
   * Query Parameters:
   * - domain: The domain to fetch SPF record for (required)
   * 
   * Response includes:
   * - Original SPF record (if redirects are present)
   * - Final SPF record (after following redirects)
   * - Redirect chain information
   * - Parsed mechanisms and modifiers
   * 
   * @param c - Hono context object
   * @returns JSON response with SPF record information
   */
  async getSPFRecord(c: Context) {
    console.log('📥 Received SPF record request');
    
    // Extract domain from query parameters
    const domain = c.req.query('domain');
    console.log(`🔍 Requested domain: ${domain || 'NOT PROVIDED'}`);

    // Make single call to service for complete SPF record processing
    const result = await this.spfService.getSPFRecordForDomain(domain || '');

    // Check if result is an error response
    if (this.spfService.isErrorResponse(result)) {
      console.error(`❌ SPF service returned error: ${result.error}`);
      
      // Determine appropriate status code based on error type
      if (result.error === 'No SPF record found for the domain') {
        return c.json(result, 404);
      } else if (result.error === 'Failed to fetch SPF record') {
        return c.json(result, 500);
      } else {
        return c.json(result, 400);
      }
    }

    console.log(`📤 Sending successful response for domain: ${result.domain}`);
    return c.json(result);
  }
} 