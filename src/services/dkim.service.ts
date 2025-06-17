import { DNSResponse, DNSRecord } from '../types/dns.types';
import { DKIMRecord } from '../types/dkim.types';
import { EXTERNAL_URLS } from '../config';

/**
 * DKIM Service - Unified DNS DKIM Record Service
 * 
 * Main Public Interface:
 * - getDKIMRecordForDomain(domain: string, selector?: string): Promise<DKIMResponse | DKIMErrorResponse>
 * - auditDKIMForDomain(domain: string): Promise<DKIMAuditResult>
 * - discoverDKIMSelectors(domain: string): Promise<{ selector: string; record: string }[]>
 * - getAllDKIMRecords(domain: string): Promise<DKIMRecordData[]>
 * - isErrorResponse(result): boolean
 * - isSuccessResponse(result): boolean
 * 
 * This service provides comprehensive DKIM record analysis including:
 * - Single selector queries with validation
 * - Multi-selector discovery and auditing
 * - Common selector checking (default, selector1, google, microsoft, etc.)
 * - DNS format validation (<selector>._domainkey.<domain>)
 * - Record parsing and analysis
 * - Recommendations for DKIM configuration
 * 
 * Can be used from any controller or service that needs DKIM record information.
 */

export interface DKIMRecordData {
  raw: string;
  parsed: DKIMRecord;
  selector?: string;
}

export interface DKIMResponse {
  domain: string;
  selector?: string;
  record: string;
  parsed: DKIMRecord;
  summary: {
    hasVersion: boolean;
    hasValidKeyType: boolean;
    hasValidPublicKey: boolean;
    keyLength: number;
    hashAlgorithms?: string[];
    flags?: string[];
  };
  metadata: {
    timestamp: string;
    requestId: string;
    processingTime: number;
  };
}

export interface DKIMErrorResponse {
  error: string;
  domain?: string;
  selector?: string;
  details?: string;
  example?: string;
  provided?: string;
  suggestion?: string;
  timestamp?: string;
}

export class DKIMService {
  /**
   * Common DKIM selectors used by various email providers
   * These are the most commonly used selectors that should be checked during audits
   */
  private readonly COMMON_SELECTORS = [
    'default',
    'selector1',
    'selector2',
    'google',
    'k1',
    'k2',
    'k3',
    's1',
    's2',
    'mx',
    'mte1',
    'mte2',
    'mx',
    'mx1',
    'mx2',
    'mx3',
    'mx4',
    'mx5',
    'mx6',
    'mx7',
    'mail',
    'mail2',
    'mail3',
    'everlytickey1',
    "everlytickey2",
    'fm1',
    'fm2',
    's1024',
    's2048',
    's4096',
    's8192',
    's16384',
    's32768',
    's65536',
    'arc-20160816',
    'dkim',
    'selector',
    'key1',
    'key2',
    'microsoft',
    'outlook',
    'office365',
    'm365',
    'sendgrid',
    'mailgun',
    'amazonses',
    'ses',
    'aws',
    'cloudflare',
    'cf',
    'zoho',
    'yandex',
    'protonmail',
    'tutanota'
  ];

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
   * Validates selector format
   * @param selector - Selector string to validate
   * @returns True if selector format is valid
   */
  private isValidSelector(selector: string): boolean {
    // Selector should be alphanumeric and hyphens, typically 1-63 characters
    const selectorRegex = /^[a-zA-Z0-9\-]+$/;
    return selectorRegex.test(selector) && selector.length > 0 && selector.length <= 63;
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
  validateDomain(domain: string): { isValid: boolean; error?: DKIMErrorResponse } {
    if (!domain) {
      return {
        isValid: false,
        error: {
          error: 'Domain parameter is required',
          example: '/dkim?domain=example.com'
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
   * Validates selector parameter and returns appropriate error response if invalid
   * @param selector - Selector string to validate
   * @returns Validation result with error response if invalid
   */
  validateSelector(selector: string): { isValid: boolean; error?: DKIMErrorResponse } {
    if (selector && !this.isValidSelector(selector)) {
      return {
        isValid: false,
        error: {
          error: 'Invalid selector format',
          provided: selector,
          example: 'default'
        }
      };
    }

    return { isValid: true };
  }

  /**
   * Formats DKIM record data into a comprehensive API response
   * @param domain - The domain that was queried
   * @param dkimRecord - The DKIM record data
   * @param selector - The selector used (optional)
   * @returns Formatted response object
   */
  formatDKIMResponse(domain: string, dkimRecord: DKIMRecordData, selector?: string): DKIMResponse {
    const startTime = Date.now();
    
    const response: DKIMResponse = {
      domain,
      selector,
      record: dkimRecord.raw,
      parsed: dkimRecord.parsed,
      summary: {
        hasVersion: !!dkimRecord.parsed.version,
        hasValidKeyType: !!dkimRecord.parsed.keyType,
        hasValidPublicKey: !!dkimRecord.parsed.publicKey,
        keyLength: dkimRecord.parsed.publicKey?.length || 0,
        hashAlgorithms: dkimRecord.parsed.hashAlgorithms,
        flags: dkimRecord.parsed.flags
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
   * @param domain - The domain that was not found
   * @param selector - The selector that was used (optional)
   * @returns Error response object
   */
  createNotFoundError(domain: string, selector?: string): DKIMErrorResponse {
    const selectorText = selector ? ` with selector '${selector}'` : '';
    return {
      error: `No DKIM record found for domain '${domain}'${selectorText}`,
      domain,
      selector,
      suggestion: 'Verify the domain and selector are correct, or try without a selector to find available records',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Creates a standardized error response for various error types
   * @param domain - The domain that was queried
   * @param error - The error that occurred
   * @param selector - The selector that was used (optional)
   * @returns Error response object
   */
  createErrorResponse(domain: string, error: unknown, selector?: string): DKIMErrorResponse {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      error: 'Failed to fetch DKIM record',
      domain,
      selector,
      details: errorMessage,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Fetches DKIM record from DNS using the correct format
   * @param domain - The domain to query
   * @param selector - The selector to use
   * @returns Raw DKIM record string or null if not found
   */
  private async fetchDKIMRecord(domain: string, selector: string): Promise<string | null> {
    try {
      // Correct DKIM DNS format: <selector>._domainkey.<domain>
      const dkimDomain = `${selector}._domainkey.${domain}`;
      console.log(`🔍 Fetching DKIM record for: ${dkimDomain}`);

      const response = await fetch(`${EXTERNAL_URLS.DNS.GOOGLE}?name=${dkimDomain}&type=TXT`);
      
      if (!response.ok) {
        throw new Error(`DNS query failed with status: ${response.status}`);
      }

      const dnsResponse: DNSResponse = await response.json();
      
      if (dnsResponse.Status !== 0) {
        console.log(`❌ DNS query failed with status: ${dnsResponse.Status}`);
        return null;
      }

      if (!dnsResponse.Answer || dnsResponse.Answer.length === 0) {
        console.log(`❌ No DKIM records found for ${dkimDomain}`);
        return null;
      }

      // Check for CNAME redirects first
      const cnameRecord = dnsResponse.Answer.find(record => record.type === 5); // CNAME type
      if (cnameRecord) {
        console.log(`🔄 Found CNAME redirect: ${dkimDomain} -> ${cnameRecord.data}`);
        // Follow the CNAME redirect
        const redirectResponse = await fetch(`${EXTERNAL_URLS.DNS.GOOGLE}?name=${cnameRecord.data}&type=TXT`);
        if (redirectResponse.ok) {
          const redirectDnsResponse: DNSResponse = await redirectResponse.json();
          if (redirectDnsResponse.Status === 0 && redirectDnsResponse.Answer && redirectDnsResponse.Answer.length > 0) {
            // Find the DKIM record in the redirected response
            const dkimRecord = redirectDnsResponse.Answer.find(record => {
              const data = record.data.toLowerCase();
              return data.includes('v=dkim1') || 
                     (data.includes('k=') && data.includes('p='));
            });
            if (dkimRecord) {
              console.log(`✅ Found DKIM record via CNAME redirect for ${dkimDomain}`);
              console.log(`${dkimRecord.data}`);
              return dkimRecord.data;
            }
          }
        }
      }

      // Find the DKIM record (should contain key type and public key)
      const dkimRecord = dnsResponse.Answer.find(record => {
        const data = record.data.toLowerCase();
        // Check for DKIM format: either has v=DKIM1 or contains k= and p= tags
        return data.includes('v=dkim1') || 
               (data.includes('k=') && data.includes('p='));
      });

      if (!dkimRecord) {
        console.log(`❌ No valid DKIM record found for ${dkimDomain}`);
        return null;
      }

      console.log(`✅ Found DKIM record for ${dkimDomain}`);
      return dkimRecord.data;
    } catch (error) {
      console.error(`❌ Error fetching DKIM record for ${domain}:`, error);
      throw error;
    }
  }

  /**
   * Parses raw DKIM record into structured data
   * @param rawRecord - The raw DKIM record string
   * @returns Parsed DKIM record data
   */
  private parseDKIMRecord(rawRecord: string): DKIMRecord {
    const parsed: DKIMRecord = {
      version: '',
      keyType: '',
      publicKey: '',
      notes: '',
      serviceType: '',
      granularity: '',
      hashAlgorithms: [],
      flags: []
    };

    // Handle multi-part TXT records (like Yahoo's format)
    // Remove quotes and concatenate all parts
    const cleanRecord = rawRecord
      .replace(/^"|"$/g, '')  // Remove outer quotes
      .replace(/"\s*"/g, '')  // Remove quotes between parts
      .replace(/\s+/g, ' ')   // Normalize whitespace
      .trim();
    
    // Split by semicolon and parse each tag
    const tags = cleanRecord.split(';').map(tag => tag.trim()).filter(tag => tag);
    
    for (const tag of tags) {
      const [key, value] = tag.split('=').map(part => part.trim());
      
      if (!key || !value) continue;
      
      switch (key) {
        case 'v':
          parsed.version = value;
          break;
        case 'k':
          parsed.keyType = value;
          break;
        case 'p':
          parsed.publicKey = value.replace(/\s+/g, ''); // Remove all whitespace including newlines
          break;
        case 'n':
          parsed.notes = value;
          break;
        case 's':
          parsed.serviceType = value;
          break;
        case 'g':
          parsed.granularity = value;
          break;
        case 'h':
          parsed.hashAlgorithms = value.split(':');
          break;
        case 't':
          parsed.flags = value.split(':');
          break;
      }
    }

    return parsed;
  }

  /**
   * Discovers all available DKIM selectors for a domain
   * @param domain - The domain to check
   * @returns Array of selectors that have valid DKIM records
   */
  async discoverDKIMSelectors(domain: string): Promise<{ selector: string; record: string }[]> {
    const discoveredSelectors: { selector: string; record: string }[] = [];
    
    console.log(`🔍 Discovering DKIM selectors for domain: ${domain}`);
    
    // Check common selectors in parallel for efficiency
    const promises = this.COMMON_SELECTORS.map(async (selector) => {
      try {
        const record = await this.fetchDKIMRecord(domain, selector);
        if (record) {
          return { selector, record };
        }
      } catch (error) {
        // Silently ignore errors for individual selectors
        console.log(`⚠️ Error checking selector '${selector}' for ${domain}:`, error);
      }
      return null;
    });

    const results = await Promise.all(promises);
    
    for (const result of results) {
      if (result) {
        discoveredSelectors.push(result);
      }
    }

    console.log(`✅ Discovered ${discoveredSelectors.length} DKIM selectors for ${domain}`);
    return discoveredSelectors;
  }

  /**
   * Gets DKIM record for a domain with optional selector
   * @param domain - The domain to query
   * @param selector - The selector to use (optional, defaults to 'default')
   * @returns DKIM record data or null if not found
   */
  async getDKIMRecord(domain: string, selector: string = 'default'): Promise<DKIMRecordData | null> {
    try {
      const rawRecord = await this.fetchDKIMRecord(domain, selector);
      
      if (!rawRecord) {
        return null;
      }

      const parsed = this.parseDKIMRecord(rawRecord);
      
      return {
        raw: rawRecord,
        parsed,
        selector
      };
    } catch (error) {
      console.error(`❌ Error getting DKIM record for ${domain}:`, error);
      throw error;
    }
  }

  /**
   * Gets all DKIM records for a domain by checking multiple selectors
   * @param domain - The domain to query
   * @returns Array of DKIM record data for all found selectors
   */
  async getAllDKIMRecords(domain: string): Promise<DKIMRecordData[]> {
    const discoveredSelectors = await this.discoverDKIMSelectors(domain);
    const dkimRecords: DKIMRecordData[] = [];

    for (const { selector, record } of discoveredSelectors) {
      try {
        const parsed = this.parseDKIMRecord(record);
        dkimRecords.push({
          raw: record,
          parsed,
          selector
        });
      } catch (error) {
        console.error(`❌ Error parsing DKIM record for selector '${selector}':`, error);
      }
    }

    return dkimRecords;
  }

  /**
   * Comprehensive DKIM audit for a domain
   * Checks multiple selectors and provides detailed analysis
   * @param domain - The domain to audit
   * @returns Comprehensive audit results
   */
  async auditDKIMForDomain(domain: string): Promise<{
    domain: string;
    selectorsFound: number;
    records: DKIMRecordData[];
    summary: {
      hasValidRecords: boolean;
      totalSelectorsChecked: number;
      commonSelectorsFound: string[];
      recommendations: string[];
    };
    metadata: {
      timestamp: string;
      requestId: string;
      processingTime: number;
    };
  }> {
    const startTime = Date.now();
    
    try {
      // Validate domain
      const domainValidation = this.validateDomain(domain);
      if (!domainValidation.isValid) {
        throw new Error(domainValidation.error!.error);
      }

      console.log(`🔍 Starting comprehensive DKIM audit for: ${domain}`);
      
      // Discover all DKIM selectors and records
      const allRecords = await this.getAllDKIMRecords(domain);
      
      // Analyze results
      const commonSelectorsFound = allRecords
        .map(record => record.selector)
        .filter((selector): selector is string => 
          selector !== undefined && this.COMMON_SELECTORS.includes(selector)
        );
      
      const recommendations: string[] = [];
      
      if (allRecords.length === 0) {
        recommendations.push('No DKIM records found. Consider implementing DKIM for email authentication.');
      } else if (allRecords.length === 1) {
        recommendations.push('Single DKIM record found. Consider implementing multiple selectors for redundancy.');
      } else {
        recommendations.push(`${allRecords.length} DKIM records found. Good redundancy configuration.`);
      }
      
      // Check for common issues
      for (const record of allRecords) {
        if (!record.parsed.publicKey) {
          recommendations.push(`Selector '${record.selector}' has no public key.`);
        }
        if (!record.parsed.keyType) {
          recommendations.push(`Selector '${record.selector}' has no key type specified.`);
        }
        if (record.parsed.publicKey && record.parsed.publicKey.length < 100) {
          recommendations.push(`Selector '${record.selector}' has a very short public key.`);
        }
      }
      
      const auditResult = {
        domain,
        selectorsFound: allRecords.length,
        records: allRecords,
        summary: {
          hasValidRecords: allRecords.length > 0,
          totalSelectorsChecked: this.COMMON_SELECTORS.length,
          commonSelectorsFound,
          recommendations
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: this.generateRequestId(),
          processingTime: Date.now() - startTime
        }
      };
      
      console.log(`✅ DKIM audit completed for ${domain}: ${allRecords.length} selectors found`);
      return auditResult;
      
    } catch (error) {
      console.error(`❌ Error in DKIM audit for ${domain}:`, error);
      throw error;
    }
  }

  /**
   * Main public method to get DKIM record for a domain
   * @param domain - The domain to query
   * @param selector - The selector to use (optional)
   * @returns Formatted response or error response
   */
  async getDKIMRecordForDomain(domain: string, selector?: string): Promise<DKIMResponse | DKIMErrorResponse | {
    domain: string;
    selectorsFound: number;
    records: DKIMRecordData[];
    summary: {
      hasValidRecords: boolean;
      totalSelectorsChecked: number;
      commonSelectorsFound: string[];
      recommendations: string[];
    };
    metadata: {
      timestamp: string;
      requestId: string;
      processingTime: number;
    };
  }> {
    const startTime = Date.now();
    
    try {
      // Validate domain
      const domainValidation = this.validateDomain(domain);
      if (!domainValidation.isValid) {
        return domainValidation.error!;
      }

      // If no selector provided, discover all selectors and return comprehensive results
      if (!selector) {
        console.log(`🔍 No selector provided, discovering all DKIM selectors for ${domain}`);
        return await this.auditDKIMForDomain(domain);
      }

      // Validate selector if provided
      const selectorValidation = this.validateSelector(selector);
      if (!selectorValidation.isValid) {
        return selectorValidation.error!;
      }

      // Get DKIM record for specific selector
      const dkimRecord = await this.getDKIMRecord(domain, selector);
      
      if (!dkimRecord) {
        return this.createNotFoundError(domain, selector);
      }

      // Format and return response
      return this.formatDKIMResponse(domain, dkimRecord, selector);
      
    } catch (error) {
      console.error(`❌ Error in getDKIMRecordForDomain for ${domain}:`, error);
      return this.createErrorResponse(domain, error, selector);
    }
  }

  /**
   * Type guard to check if a result is an error response
   * @param result - The result to check
   * @returns True if the result is an error response
   */
  isErrorResponse(result: DKIMResponse | DKIMErrorResponse | any): result is DKIMErrorResponse {
    return 'error' in result;
  }

  /**
   * Type guard to check if a result is a success response
   * @param result - The result to check
   * @returns True if the result is a success response
   */
  isSuccessResponse(result: DKIMResponse | DKIMErrorResponse | any): result is DKIMResponse {
    return !this.isErrorResponse(result) && 'record' in result;
  }

  /**
   * Type guard to check if a result is a comprehensive audit response
   * @param result - The result to check
   * @returns True if the result is a comprehensive audit response
   */
  isComprehensiveResponse(result: DKIMResponse | DKIMErrorResponse | any): result is {
    domain: string;
    selectorsFound: number;
    records: DKIMRecordData[];
    summary: {
      hasValidRecords: boolean;
      totalSelectorsChecked: number;
      commonSelectorsFound: string[];
      recommendations: string[];
    };
    metadata: {
      timestamp: string;
      requestId: string;
      processingTime: number;
    };
  } {
    return !this.isErrorResponse(result) && !this.isSuccessResponse(result) && 'selectorsFound' in result;
  }
} 