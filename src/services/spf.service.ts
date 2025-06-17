import { DNSResponse, DNSRecord } from '../types/dns.types';
import { SPFRedirect } from '../types/spf.types';

/**
 * SPF Service - Unified DNS SPF Record Service
 * 
 * Main Public Interface:
 * - getSPFRecordForDomain(domain: string): Promise<SPFResponse | SPFErrorResponse>
 * - isErrorResponse(result): boolean
 * - isSuccessResponse(result): boolean
 * 
 * This service provides a single entry point for fetching and analyzing SPF records.
 * It handles domain validation, DNS queries, redirect following, and response formatting.
 * Can be used from any controller or service that needs SPF record information.
 */

export interface SPFRecord {
  raw: string;
  mechanisms: {
    type: string;
    value: string;
    qualifier?: string;
  }[];
  modifiers: {
    type: string;
    value: string;
  }[];
  redirects?: SPFRedirect[];
  includes?: {
    domain: string;
    record: string;
    mechanisms: {
      type: string;
      value: string;
      qualifier?: string;
    }[];
    modifiers: {
      type: string;
      value: string;
    }[];
  }[];
  redirectedRecord?: {
    raw: string;
    mechanisms: {
      type: string;
      value: string;
      qualifier?: string;
    }[];
    modifiers: {
      type: string;
      value: string;
    }[];
  };
  // Tracking counts for recursive processing
  processedRedirects?: number;
  processedIncludes?: number;
}

export interface SPFResponse {
  domain: string;
  record: string;
  mechanisms: SPFRecord['mechanisms'];
  modifiers: SPFRecord['modifiers'];
  summary: {
    totalMechanisms: number;
    totalModifiers: number;
    hasRedirects: boolean;
    redirectCount: number;
    hasRedirectedRecord?: boolean;
    redirectedMechanisms?: number;
    redirectedModifiers?: number;
    processedRedirects: number;
    processedIncludes: number;
  };
  redirects?: SPFRedirect[];
  includes?: SPFRecord['includes'];
  hasRedirects?: boolean;
  finalDomain?: string;
  redirectedRecord?: {
    record: string;
    mechanisms: SPFRecord['mechanisms'];
    modifiers: SPFRecord['modifiers'];
  };
  metadata: {
    timestamp: string;
    requestId: string;
    processingTime: number;
  };
}

export interface SPFErrorResponse {
  error: string;
  domain?: string;
  details?: string;
  example?: string;
  provided?: string;
  suggestion?: string;
  timestamp?: string;
}

export class SPFService {
  /**
   * Validates domain format
   * Basic validation to ensure domain parameter is reasonable
   * @param domain - Domain string to validate
   * @returns True if domain format is valid
   */
  private isValidDomain(domain: string): boolean {
    // Basic domain validation - should contain at least one dot and valid characters
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
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
  validateDomain(domain: string): { isValid: boolean; error?: SPFErrorResponse } {
    if (!domain) {
      return {
        isValid: false,
        error: {
          error: 'Domain parameter is required',
          example: '/spf?domain=example.com'
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
   * Formats SPF record data into a comprehensive API response
   * @param domain - The domain that was queried
   * @param spfRecord - The SPF record data
   * @returns Formatted response object
   */
  formatSPFResponse(domain: string, spfRecord: SPFRecord): SPFResponse {
    const startTime = Date.now();
    
    // Prepare base response
    const response: SPFResponse = {
      domain,
      record: spfRecord.raw,
      mechanisms: spfRecord.mechanisms,
      modifiers: spfRecord.modifiers,
      summary: {
        totalMechanisms: spfRecord.mechanisms.length,
        totalModifiers: spfRecord.modifiers.length,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: spfRecord.processedRedirects || 0,
        processedIncludes: spfRecord.processedIncludes || 0
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: this.generateRequestId(),
        processingTime: Date.now() - startTime
      }
    };

    // Handle redirect information if present
    if (spfRecord.redirects && spfRecord.redirects.length > 0) {
      response.redirects = spfRecord.redirects;
      response.hasRedirects = true;
      response.finalDomain = spfRecord.redirects[spfRecord.redirects.length - 1]?.to || domain;
      response.summary.hasRedirects = true;
      response.summary.redirectCount = spfRecord.redirects.length;
      
      // Include redirected record if available
      if (spfRecord.redirectedRecord) {
        response.redirectedRecord = {
          record: spfRecord.redirectedRecord.raw,
          mechanisms: spfRecord.redirectedRecord.mechanisms,
          modifiers: spfRecord.redirectedRecord.modifiers
        };
        response.summary.hasRedirectedRecord = true;
        response.summary.redirectedMechanisms = spfRecord.redirectedRecord.mechanisms.length;
        response.summary.redirectedModifiers = spfRecord.redirectedRecord.modifiers.length;
      } else {
        response.summary.hasRedirectedRecord = false;
      }
    } else {
      response.hasRedirects = false;
      response.finalDomain = domain;
      response.summary.hasRedirects = false;
      response.summary.redirectCount = 0;
      response.summary.hasRedirectedRecord = false;
    }

    // Handle includes information if present
    if (spfRecord.includes && spfRecord.includes.length > 0) {
      response.includes = spfRecord.includes;
    }

    return response;
  }

  /**
   * Creates error response for when no SPF record is found
   * @param domain - The domain that was queried
   * @returns Error response object
   */
  createNotFoundError(domain: string): SPFErrorResponse {
    return {
      error: 'No SPF record found for the domain',
      domain: domain,
      suggestion: 'Check if the domain has a valid SPF record in DNS'
    };
  }

  /**
   * Creates error response for general failures
   * @param domain - The domain that was queried
   * @param error - The error that occurred
   * @returns Error response object
   */
  createErrorResponse(domain: string, error: unknown): SPFErrorResponse {
    return {
      error: 'Failed to fetch SPF record',
      domain: domain,
      details: error instanceof Error ? error.message : 'Internal server error',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Fetches SPF record from DNS for a given domain
   * Uses Cloudflare's DNS-over-HTTPS API to query TXT records
   * @param domain - The domain to fetch SPF record for
   * @returns Raw SPF record string or null if not found
   */
  private async fetchSPFRecord(domain: string): Promise<string | null> {
    console.log(`🔍 Fetching SPF record for domain: ${domain}`);
    
    try {
      const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {
        headers: {
          'Accept': 'application/dns-json',
        },
      });

      if (!response.ok) {
        console.error(`❌ Failed to fetch SPF record for ${domain}: ${response.statusText}`);
        throw new Error(`Failed to fetch SPF record: ${response.statusText}`);
      }

      const data: DNSResponse = await response.json();
      
      // Find SPF record in TXT records (SPF records start with "v=spf1")
      const spfRecord = data.Answer?.find((record: DNSRecord) => 
        record.type === 16 && // TXT record type
        record.data.startsWith('"v=spf1')
      );

      if (spfRecord) {
        const cleanRecord = spfRecord.data.replace(/^"|"$/g, '');
        console.log(`✅ Found SPF record for ${domain}: ${cleanRecord}`);
        return cleanRecord;
      } else {
        console.log(`⚠️ No SPF record found for domain: ${domain}`);
        return null;
      }
    } catch (error) {
      console.error(`❌ Error fetching SPF record for ${domain}:`, error);
      return null;
    }
  }

  /**
   * Parses a raw SPF record string into structured components
   * Separates mechanisms (like include, ip4, etc.) from modifiers (like redirect)
   * @param rawRecord - The raw SPF record string
   * @returns Parsed SPF record with mechanisms and modifiers
   */
  private parseSPFRecord(rawRecord: string): SPFRecord {
    console.log(`🔧 Parsing SPF record: ${rawRecord}`);
    
    const mechanisms: SPFRecord['mechanisms'] = [];
    const modifiers: SPFRecord['modifiers'] = [];
    
    // Remove v=spf1 prefix and split by spaces
    const parts = rawRecord.replace('v=spf1 ', '').split(' ');
    
    for (const part of parts) {
      if (!part) continue;
      
      // Handle mechanisms with qualifiers (+, -, ~, ?)
      if (part.startsWith('+') || part.startsWith('-') || part.startsWith('~') || part.startsWith('?')) {
        const qualifier = part[0];
        const mechanism = part.slice(1);
        const [type, value] = mechanism.split(':');
        
        mechanisms.push({
          type,
          value: value || '',
          qualifier,
        });
        console.log(`📋 Parsed mechanism: ${qualifier}${type}${value ? ':' + value : ''}`);
      } else if (part.includes('=')) {
        // Handle modifiers (redirect=domain, exp=domain, etc.)
        const [type, value] = part.split('=');
        modifiers.push({ type, value });
        console.log(`🔧 Parsed modifier: ${type}=${value}`);
      } else {
        // Handle mechanisms without qualifiers (defaults to +)
        const [type, value] = part.split(':');
        mechanisms.push({
          type,
          value: value || '',
          qualifier: '+', // Default qualifier
        });
        console.log(`📋 Parsed mechanism: +${type}${value ? ':' + value : ''}`);
      }
    }

    const parsedRecord = {
      raw: rawRecord,
      mechanisms,
      modifiers,
    };
    
    console.log(`✅ Parsed SPF record - Mechanisms: ${mechanisms.length}, Modifiers: ${modifiers.length}`);
    return parsedRecord;
  }

  /**
   * Gets SPF record for a domain, handling redirects recursively
   * This is the main method that orchestrates the SPF record retrieval process
   * 
   * @param domain - The domain to get SPF record for
   * @param visitedDomains - Set of domains already visited (prevents redirect loops)
   * @param isInitialCall - Whether this is the initial call (used to preserve original record)
   * @returns Complete SPF record with redirect information
   */
  async getSPFRecord(domain: string, visitedDomains: Set<string> = new Set(), isInitialCall: boolean = true): Promise<SPFRecord | null> {
    console.log(`🚀 Getting SPF record for domain: ${domain} (Initial call: ${isInitialCall})`);
    
    // Prevent infinite redirect loops by tracking visited domains
    if (visitedDomains.has(domain)) {
      console.warn(`⚠️ Redirect loop detected for domain: ${domain}`);
      console.warn(`📋 Visited domains: ${Array.from(visitedDomains).join(' -> ')}`);
      return null;
    }
    
    visitedDomains.add(domain);
    console.log(`📋 Updated visited domains: ${Array.from(visitedDomains).join(' -> ')}`);
    
    // Fetch the raw SPF record from DNS
    const rawRecord = await this.fetchSPFRecord(domain);
    if (!rawRecord) {
      console.log(`❌ No SPF record found for domain: ${domain}`);
      return null;
    }

    // Parse the SPF record into structured components
    const spfRecord = this.parseSPFRecord(rawRecord);
    const redirects: SPFRedirect[] = [];
    const includes: SPFRecord['includes'] = [];
    
    // Initialize counters for recursive processing
    let totalProcessedRedirects = 0;
    let totalProcessedIncludes = 0;

    // Check for redirect modifier in the SPF record
    const redirectModifier = spfRecord.modifiers.find(mod => mod.type === 'redirect');
    if (redirectModifier) {
      const redirectDomain = redirectModifier.value;
      console.log(`🔄 Found redirect modifier: ${domain} -> ${redirectDomain}`);
      
      // Increment redirect counter
      totalProcessedRedirects++;
      
      // Add current redirect to the tracking list
      redirects.push({
        from: domain,
        to: redirectDomain,
        record: rawRecord
      });
      console.log(`📝 Added redirect to chain: ${domain} -> ${redirectDomain}`);

      // Recursively fetch the redirected SPF record
      console.log(`🔄 Following redirect to: ${redirectDomain}`);
      const redirectedRecord = await this.getSPFRecord(redirectDomain, visitedDomains, false);
      
      if (redirectedRecord) {
        console.log(`✅ Successfully retrieved redirected record from: ${redirectDomain}`);
        
        // Add counts from redirected record
        totalProcessedRedirects += redirectedRecord.processedRedirects || 0;
        totalProcessedIncludes += redirectedRecord.processedIncludes || 0;
        
        // Process includes from the redirected record as well
        for (const mechanism of redirectedRecord.mechanisms) {
          if (mechanism.type === 'include') {
            const includeDomain = mechanism.value;
            console.log(`📋 Processing include mechanism from redirected record: ${includeDomain}`);
            
            // Increment include counter for includes from redirected record
            totalProcessedIncludes++;
            
            const includeRecord = await this.getSPFRecord(includeDomain, new Set([...visitedDomains]), false);
            
            if (includeRecord) {
              // Add counts from included record
              totalProcessedRedirects += includeRecord.processedRedirects || 0;
              totalProcessedIncludes += includeRecord.processedIncludes || 0;
              
              // Add include to tracking list (from redirected record)
              includes.push({
                domain: includeDomain,
                record: includeRecord.raw,
                mechanisms: includeRecord.mechanisms,
                modifiers: includeRecord.modifiers
              });
              
              if (includeRecord.redirects) {
                redirects.push(...includeRecord.redirects);
                console.log(`📝 Added ${includeRecord.redirects.length} redirects from include in redirected record: ${includeDomain}`);
              }
            }
          }
        }
        
        // Merge any redirects from the redirected record
        if (redirectedRecord.redirects) {
          redirects.push(...redirectedRecord.redirects);
          console.log(`📝 Merged ${redirectedRecord.redirects.length} redirects from ${redirectDomain}`);
        }
        
        // If this is the initial call, return original record with redirected record in separate section
        if (isInitialCall) {
          console.log(`💾 Returning original record with redirected record in separate section`);
          return {
            ...spfRecord, // Keep the original record as the main record
            redirects,
            redirectedRecord: {
              raw: redirectedRecord.raw,
              mechanisms: redirectedRecord.mechanisms,
              modifiers: redirectedRecord.modifiers
            },
            processedRedirects: totalProcessedRedirects,
            processedIncludes: totalProcessedIncludes
          };
        } else {
          // Return the redirected record with updated redirect chain
          console.log(`📤 Returning redirected record with ${redirects.length} redirects in chain`);
          return {
            ...redirectedRecord,
            redirects,
            processedRedirects: totalProcessedRedirects,
            processedIncludes: totalProcessedIncludes
          };
        }
      } else {
        console.error(`❌ Failed to retrieve redirected record from: ${redirectDomain}`);
      }
    }

    // Check for include mechanisms that might have their own redirects
    console.log(`🔍 Checking ${spfRecord.mechanisms.length} mechanisms for includes`);
    for (const mechanism of spfRecord.mechanisms) {
      if (mechanism.type === 'include') {
        const includeDomain = mechanism.value;
        console.log(`📋 Processing include mechanism: ${includeDomain}`);
        
        // Increment include counter
        totalProcessedIncludes++;
        
        const includeRecord = await this.getSPFRecord(includeDomain, new Set([...visitedDomains]), false);
        
        if (includeRecord) {
          // Add counts from included record
          totalProcessedRedirects += includeRecord.processedRedirects || 0;
          totalProcessedIncludes += includeRecord.processedIncludes || 0;
          
          // Add include to tracking list
          includes.push({
            domain: includeDomain,
            record: includeRecord.raw,
            mechanisms: includeRecord.mechanisms,
            modifiers: includeRecord.modifiers
          });
          
          if (includeRecord.redirects) {
            redirects.push(...includeRecord.redirects);
            console.log(`📝 Added ${includeRecord.redirects.length} redirects from include: ${includeDomain}`);
          }
        }
      }
    }

    // If this is the initial call and we have redirects from includes, preserve the original record
    if (isInitialCall && (redirects.length > 0 || includes.length > 0)) {
      console.log(`💾 Preserving original record (has ${redirects.length} redirects, ${includes.length} includes from processing)`);
      return {
        ...spfRecord,
        redirects: redirects.length > 0 ? redirects : undefined,
        includes: includes, // always an array
        processedRedirects: totalProcessedRedirects,
        processedIncludes: totalProcessedIncludes
      };
    }

    // Return the final result
    const result = {
      ...spfRecord,
      redirects: redirects.length > 0 ? redirects : undefined,
      includes: includes, // always an array
      processedRedirects: totalProcessedRedirects,
      processedIncludes: totalProcessedIncludes
    };
    
    console.log(`✅ Final SPF record for ${domain}: ${redirects.length} redirects, ${includes.length} includes, ${totalProcessedRedirects} total processed redirects, ${totalProcessedIncludes} total processed includes`);
    return result;
  }

  /**
   * Unified method to get SPF record for a domain
   * This is the main entry point that handles the complete flow:
   * 1. Domain validation
   * 2. SPF record fetching and parsing
   * 3. Response formatting
   * 
   * Usage examples:
   * 
   * // From a controller:
   * const spfService = new SPFService();
   * const result = await spfService.getSPFRecordForDomain('example.com');
   * if (spfService.isErrorResponse(result)) {
   *   // Handle error
   *   return c.json(result, 400);
   * }
   * // Use successful result
   * return c.json(result);
   * 
   * // From another service:
   * const spfService = new SPFService();
   * const spfResult = await spfService.getSPFRecordForDomain(domain);
   * if (spfService.isSuccessResponse(spfResult)) {
   *   // Process SPF data
   *   const mechanisms = spfResult.mechanisms;
   *   const hasRedirects = spfResult.hasRedirects;
   * }
   * 
   * @param domain - The domain to get SPF record for
   * @returns Promise that resolves to either SPFResponse or SPFErrorResponse
   */
  async getSPFRecordForDomain(domain: string): Promise<SPFResponse | SPFErrorResponse> {
    console.log(`🚀 SPFService.getSPFRecordForDomain called for: ${domain}`);
    
    // Step 1: Validate domain
    const validation = this.validateDomain(domain);
    if (!validation.isValid) {
      console.error(`❌ Domain validation failed: ${validation.error?.error}`);
      return validation.error!;
    }

    // Step 2: Fetch and process SPF record
    try {
      console.log(`🔍 Fetching SPF record for domain: ${domain}`);
      const spfRecord = await this.getSPFRecord(domain);
      
      if (!spfRecord) {
        console.log(`❌ No SPF record found for domain: ${domain}`);
        return this.createNotFoundError(domain);
      }

      console.log(`✅ SPF record retrieved successfully for: ${domain}`);
      console.log(`📊 Record details: ${spfRecord.mechanisms.length} mechanisms, ${spfRecord.modifiers.length} modifiers`);

      // Step 3: Format response
      const response = this.formatSPFResponse(domain, spfRecord);
      
      console.log(`📤 Response formatted for domain: ${domain}`);
      console.log(`📊 Response summary: ${response.summary.totalMechanisms} mechanisms, ${response.summary.redirectCount} redirects`);
      
      return response;
      
    } catch (error) {
      console.error(`❌ Error processing SPF record request for ${domain}:`, error);
      return this.createErrorResponse(domain, error);
    }
  }

  /**
   * Type guard to check if a result is an error response
   * @param result - The result from getSPFRecordForDomain
   * @returns True if the result is an error response
   */
  isErrorResponse(result: SPFResponse | SPFErrorResponse): result is SPFErrorResponse {
    return 'error' in result;
  }

  /**
   * Type guard to check if a result is a successful response
   * @param result - The result from getSPFRecordForDomain
   * @returns True if the result is a successful response
   */
  isSuccessResponse(result: SPFResponse | SPFErrorResponse): result is SPFResponse {
    return !this.isErrorResponse(result);
  }
} 