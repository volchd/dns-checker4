import { DNSResponse, DNSRecord } from '../types/dns.types';
import { DMARCRecord, DMARCPolicy, DMARCSubdomainPolicy } from '../types/dmarc.types';
import { EXTERNAL_URLS } from '../config';

/**
 * DMARC Service - Unified DNS DMARC Record Service
 * 
 * Main Public Interface:
 * - getDMARCRecordForDomain(domain: string): Promise<DMARCResponse | DMARCErrorResponse>
 * - isErrorResponse(result): boolean
 * - isSuccessResponse(result): boolean
 * 
 * This service provides comprehensive DMARC record analysis including:
 * - Single domain queries with validation
 * - DNS format validation (_dmarc.<domain>)
 * - Record parsing and analysis
 * - Recommendations for DMARC configuration
 * 
 * Can be used from any controller or service that needs DMARC record information.
 */

export interface DMARCResponse {
  domain: string;
  record: string;
  parsed: DMARCRecord;
  summary: {
    hasVersion: boolean;
    hasValidPolicy: boolean;
    hasSubdomainPolicy: boolean;
    hasPercentage: boolean;
    hasReports: boolean;
    hasFailureOptions: boolean;
    hasAdkim: boolean;
    hasAspf: boolean;
    policy: string;
    subdomainPolicy?: string;
    percentage?: number;
    reportCount: number;
  };
  metadata: {
    timestamp: string;
    requestId: string;
    processingTime: number;
  };
}

export interface DMARCErrorResponse {
  error: string;
  domain?: string;
  details?: string;
  example?: string;
  provided?: string;
  suggestion?: string;
  timestamp?: string;
}

export class DMARCService {
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
   * Generates a simple request ID for tracking
   * @returns Unique request identifier
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Validates domain parameter and returns appropriate error response if invalid
   * @param domain - Domain string to validate
   * @returns Validation result with error response if invalid
   */
  validateDomain(domain: string): { isValid: boolean; error?: DMARCErrorResponse } {
    if (!domain) {
      return {
        isValid: false,
        error: {
          error: 'Domain parameter is required',
          example: '/dmarc?domain=example.com'
        }
      };
    }

    if (!this.isValidDomain(domain)) {
      return {
        isValid: false,
        error: {
          error: 'Invalid domain format',
          provided: domain,
          example: 'example.com'
        }
      };
    }

    return { isValid: true };
  }

  /**
   * Formats DMARC record data into a comprehensive API response
   * @param domain - The domain that was queried
   * @param dmarcRecord - The DMARC record data
   * @returns Formatted response object
   */
  formatDMARCResponse(domain: string, dmarcRecord: { raw: string; parsed: DMARCRecord }): DMARCResponse {
    const startTime = Date.now();
    
    const response: DMARCResponse = {
      domain,
      record: dmarcRecord.raw,
      parsed: dmarcRecord.parsed,
      summary: {
        hasVersion: !!dmarcRecord.parsed.version,
        hasValidPolicy: !!dmarcRecord.parsed.policy,
        hasSubdomainPolicy: !!dmarcRecord.parsed.subdomainPolicy,
        hasPercentage: dmarcRecord.parsed.percentage !== undefined,
        hasReports: !!(dmarcRecord.parsed.reports && dmarcRecord.parsed.reports.length > 0),
        hasFailureOptions: !!(dmarcRecord.parsed.failureOptions && dmarcRecord.parsed.failureOptions.length > 0),
        hasAdkim: !!dmarcRecord.parsed.adkim,
        hasAspf: !!dmarcRecord.parsed.aspf,
        policy: dmarcRecord.parsed.policy,
        subdomainPolicy: dmarcRecord.parsed.subdomainPolicy,
        percentage: dmarcRecord.parsed.percentage,
        reportCount: dmarcRecord.parsed.reports ? dmarcRecord.parsed.reports.length : 0
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: this.generateRequestId(),
        processingTime: Date.now() - startTime
      }
    };

    return response;
  }

  /**
   * Creates a standardized "not found" error response
   * @param domain - The domain that was queried
   * @returns Error response object
   */
  createNotFoundError(domain: string): DMARCErrorResponse {
    return {
      error: 'No DMARC record found for the domain',
      domain,
      details: 'DMARC is not implemented for this domain',
      suggestion: 'Consider implementing DMARC to improve email security',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Creates a standardized error response for multiple records
   * @param domain - The domain that was queried
   * @returns Error response object
   */
  createMultipleRecordsError(domain: string): DMARCErrorResponse {
    return {
      error: 'Multiple DMARC records found for the domain',
      domain,
      details: 'Multiple DMARC records may cause receivers to ignore all DMARC records',
      suggestion: 'Remove duplicate DMARC records and keep only one',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Creates a standardized error response
   * @param domain - The domain that was queried
   * @param error - The error that occurred
   * @returns Error response object
   */
  createErrorResponse(domain: string, error: unknown): DMARCErrorResponse {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    return {
      error: 'Failed to fetch DMARC record',
      domain,
      details: errorMessage,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Fetches DMARC record from DNS
   * @param domain - The domain to query
   * @returns The DMARC record string or null if not found
   */
  private async fetchDMARCRecord(domain: string): Promise<string | null> {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      console.log(`🔍 Fetching DMARC record for: ${dmarcDomain}`);
      
      const response = await fetch(`${EXTERNAL_URLS.DNS.CLOUDFLARE}?name=${encodeURIComponent(dmarcDomain)}&type=TXT`, {
        headers: {
          'Accept': 'application/dns-json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`DNS API returned status ${response.status}`);
      }
      
      const data: DNSResponse = await response.json();
      
      if (data.Status !== 0) {
        // NXDOMAIN or other DNS error
        console.log(`❌ DNS query failed with status: ${data.Status}`);
        return null;
      }
      
      if (!data.Answer || data.Answer.length === 0) {
        console.log(`❌ No DMARC records found for: ${dmarcDomain}`);
        return null;
      }
      
      // Filter for TXT records and extract DMARC records
      const txtRecords = data.Answer.filter(record => record.type === 16); // TXT record type
      
      if (txtRecords.length === 0) {
        console.log(`❌ No TXT records found for: ${dmarcDomain}`);
        return null;
      }
      
      // Look for DMARC records (should start with "v=DMARC1")
      const dmarcRecords = txtRecords
        .map(record => record.data.replace(/^"/, '').replace(/"$/, '')) // Remove quotes
        .filter(record => record.startsWith('v=DMARC1'));
      
      if (dmarcRecords.length === 0) {
        console.log(`❌ No DMARC records found in TXT records for: ${dmarcDomain}`);
        return null;
      }
      
      if (dmarcRecords.length > 1) {
        console.log(`⚠️ Multiple DMARC records found for: ${dmarcDomain}`);
        throw new Error('Multiple DMARC records found');
      }
      
      console.log(`✅ Found DMARC record: ${dmarcRecords[0]}`);
      return dmarcRecords[0];
      
    } catch (error) {
      console.error(`❌ Error fetching DMARC record for ${domain}:`, error);
      throw error;
    }
  }

  /**
   * Parses a DMARC record string into structured data
   * @param rawRecord - The raw DMARC record string
   * @returns Parsed DMARC record object
   */
  private parseDMARCRecord(rawRecord: string): DMARCRecord {
    const record: DMARCRecord = {
      version: '',
      policy: 'none'
    };
    
    // Split the record into key-value pairs
    const parts = rawRecord.split(';').map(part => part.trim()).filter(part => part.length > 0);
    
    for (const part of parts) {
      const [key, value] = part.split('=').map(s => s.trim());
      
      if (!key || !value) continue;
      
      switch (key.toLowerCase()) {
        case 'v':
          record.version = value;
          break;
        case 'p':
          if (['none', 'quarantine', 'reject'].includes(value.toLowerCase())) {
            record.policy = value.toLowerCase() as DMARCPolicy;
          }
          break;
        case 'sp':
          if (['none', 'quarantine', 'reject'].includes(value.toLowerCase())) {
            record.subdomainPolicy = value.toLowerCase() as DMARCSubdomainPolicy;
          }
          break;
        case 'pct':
          const percentage = parseInt(value, 10);
          if (!isNaN(percentage) && percentage >= 0 && percentage <= 100) {
            record.percentage = percentage;
          }
          break;
        case 'rua':
        case 'ruf':
          // Parse report URIs
          if (!record.reports) record.reports = [];
          const uris = value.split(',').map(uri => uri.trim());
          for (const uri of uris) {
            const [reportUri, maxSize] = uri.split('!');
            record.reports.push({
              type: key.toLowerCase() === 'rua' ? 'afrf' : 'iodef',
              uri: reportUri,
              maxSize: maxSize ? parseInt(maxSize, 10) : undefined
            });
          }
          break;
        case 'fo':
          record.failureOptions = value.split(':').map(opt => opt.trim());
          break;
        case 'adkim':
          if (['r', 's'].includes(value.toLowerCase())) {
            record.adkim = value.toLowerCase() as 'r' | 's';
          }
          break;
        case 'aspf':
          if (['r', 's'].includes(value.toLowerCase())) {
            record.aspf = value.toLowerCase() as 'r' | 's';
          }
          break;
        default:
          // Store unknown tags in notes
          if (!record.notes) record.notes = '';
          record.notes += `${key}=${value}; `;
          break;
      }
    }
    
    return record;
  }

  /**
   * Fetches and parses DMARC record for a domain
   * @param domain - The domain to query
   * @returns Parsed DMARC record or null if not found
   */
  async getDMARCRecord(domain: string): Promise<{ raw: string; parsed: DMARCRecord } | null> {
    try {
      const rawRecord = await this.fetchDMARCRecord(domain);
      
      if (!rawRecord) {
        return null;
      }
      
      const parsed = this.parseDMARCRecord(rawRecord);
      
      return {
        raw: rawRecord,
        parsed
      };
      
    } catch (error) {
      console.error(`❌ Error getting DMARC record for ${domain}:`, error);
      throw error;
    }
  }

  /**
   * Main public method to get DMARC record for a domain
   * @param domain - The domain to query
   * @returns DMARC response or error response
   */
  async getDMARCRecordForDomain(domain: string): Promise<DMARCResponse | DMARCErrorResponse> {
    const startTime = Date.now();
    
    try {
      // Validate domain parameter
      const validation = this.validateDomain(domain);
      if (!validation.isValid) {
        return validation.error!;
      }
      
      console.log(`🔍 Processing DMARC request for domain: ${domain}`);
      
      // Fetch and parse DMARC record
      const dmarcRecord = await this.getDMARCRecord(domain);
      
      if (!dmarcRecord) {
        return this.createNotFoundError(domain);
      }
      
      // Format response
      const response = this.formatDMARCResponse(domain, dmarcRecord);
      
      console.log(`✅ DMARC record processed successfully for ${domain}`);
      return response;
      
    } catch (error) {
      console.error(`❌ Error processing DMARC request for ${domain}:`, error);
      
      // Check if it's a multiple records error
      if (error instanceof Error && error.message === 'Multiple DMARC records found') {
        return this.createMultipleRecordsError(domain);
      }
      
      return this.createErrorResponse(domain, error);
    }
  }

  /**
   * Type guard to check if a result is an error response
   * @param result - The result to check
   * @returns True if the result is an error response
   */
  isErrorResponse(result: DMARCResponse | DMARCErrorResponse): result is DMARCErrorResponse {
    return 'error' in result;
  }

  /**
   * Type guard to check if a result is a success response
   * @param result - The result to check
   * @returns True if the result is a success response
   */
  isSuccessResponse(result: DMARCResponse | DMARCErrorResponse): result is DMARCResponse {
    return 'domain' in result && 'record' in result && 'parsed' in result;
  }
} 