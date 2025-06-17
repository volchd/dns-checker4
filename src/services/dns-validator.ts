/**
 * DNS Validator Service
 * 
 * This service provides comprehensive validation of DNS (Domain Name System) records
 * for email domains. It uses DNS-over-HTTPS (DoH) to query DNS records securely
 * and validate domain existence and configuration.
 * 
 * Key Features:
 * - Validates domain existence through NS record queries
 * - Retrieves TXT records for SPF, DKIM, and other email authentication
 * - Uses Cloudflare's DNS-over-HTTPS for secure queries
 * - Handles root domain extraction for proper validation
 * - Provides detailed error reporting and debugging information
 * 
 * Security Considerations:
 * - Uses DNS-over-HTTPS for encrypted DNS queries
 * - Validates domain format before making queries
 * - Handles various TLD patterns and subdomain scenarios
 * - Provides comprehensive error handling and logging
 */

import { EXTERNAL_URLS } from '../config';

interface DNSValidatorResponse {
  exists: boolean;
  error?: string;
  details?: any; // Adding details field for debugging
}

interface DNSResponse {
  Status: number;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
  Authority?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
}

export class DNSValidator {
  // DNS-over-HTTPS endpoint for secure DNS queries
  private readonly dnsApiUrl = EXTERNAL_URLS.DNS.CLOUDFLARE;

  constructor() {
    console.log('[DNS Validator] Initialized with DNS-over-HTTPS endpoint:', this.dnsApiUrl);
  }

  /**
   * Validates DNS existence for a given domain
   * 
   * This method performs a comprehensive DNS validation by:
   * - Validating the domain format
   * - Extracting the root domain for proper NS record checking
   * - Querying NS records using DNS-over-HTTPS
   * - Analyzing the response for domain existence
   * 
   * @param domain - The domain to validate DNS records for
   * @returns Promise<DNSValidatorResponse> - DNS validation results with detailed information
   */
  async validateDNS(domain: string): Promise<DNSValidatorResponse> {
    console.log(`[DNS Validator] Starting DNS validation for domain: ${domain}`);
    
    try {
      // Step 1: Basic domain format validation
      console.log(`[DNS Validator] Validating domain format: ${domain}`);
      if (!this.isValidDomain(domain)) {
        console.error(`[DNS Validator] Invalid domain format: ${domain}`);
        return {
          exists: false,
          error: 'Invalid domain format',
        };
      }
      console.log(`[DNS Validator] ✓ Domain format is valid: ${domain}`);

      // Step 2: Extract the root domain for proper NS record checking
      const rootDomain = this.extractRootDomain(domain);
      console.log(`[DNS Validator] Extracted root domain: ${rootDomain} from ${domain}`);

      // Step 3: Check NS records using DNS-over-HTTPS
      console.log(`[DNS Validator] Querying NS records for root domain: ${rootDomain}`);
      const response = await fetch(
        `${this.dnsApiUrl}?name=${encodeURIComponent(rootDomain)}&type=NS`,
        {
          headers: {
            'Accept': 'application/dns-json',
          },
        }
      );

      if (!response.ok) {
        console.error(`[DNS Validator] DNS query failed: ${response.status} ${response.statusText}`);
        return {
          exists: false,
          error: `DNS query failed: ${response.statusText}`,
          details: {
            status: response.status,
            statusText: response.statusText,
            url: `${this.dnsApiUrl}?name=${encodeURIComponent(rootDomain)}&type=NS`
          }
        };
      }

      console.log(`[DNS Validator] ✓ DNS query successful: ${response.status} ${response.statusText}`);

      // Step 4: Parse and analyze DNS response
      const data = await response.json() as DNSResponse;
      console.log(`[DNS Validator] DNS response status: ${data.Status}`);
      console.log(`[DNS Validator] DNS response details:`, {
        answerCount: data.Answer?.length || 0,
        authorityCount: data.Authority?.length || 0,
        hasAnswer: !!data.Answer,
        hasAuthority: !!data.Authority
      });

      // Step 5: Check if we got any NS records (type 2)
      const hasNSRecords = Boolean(
        data.Answer?.some(record => record.type === 2) || 
        data.Authority?.some(record => record.type === 2)
      );

      console.log(`[DNS Validator] NS records found: ${hasNSRecords}`);
      if (hasNSRecords) {
        const nsRecords = [
          ...(data.Answer?.filter(record => record.type === 2) || []),
          ...(data.Authority?.filter(record => record.type === 2) || [])
        ];
        console.log(`[DNS Validator] NS record details:`, nsRecords.map(record => ({
          name: record.name,
          ttl: record.TTL,
          data: record.data
        })));
      }

      return {
        exists: hasNSRecords,
        details: {
          status: data.Status,
          answer: data.Answer,
          authority: data.Authority,
          rootDomain,
          originalDomain: domain
        }
      };
    } catch (error) {
      console.error(`[DNS Validator] Error during DNS validation for ${domain}:`, error);
      return {
        exists: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
        details: { 
          error,
          domain,
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  /**
   * Retrieves TXT records for a given domain
   * 
   * This method fetches all TXT records for a domain, which are commonly used for:
   * - SPF (Sender Policy Framework) records
   * - DKIM (DomainKeys Identified Mail) records
   * - DMARC (Domain-based Message Authentication, Reporting & Conformance) records
   * - Other email authentication and verification records
   * 
   * @param domain - The domain to fetch TXT records for
   * @returns Promise<string[]> - Array of TXT record values
   * @throws Error - If DNS query fails or domain is invalid
   */
  async getTXTRecords(domain: string): Promise<string[]> {
    console.log(`[DNS Validator] Fetching TXT records for domain: ${domain}`);
    
    try {
      // Step 1: Validate domain format
      if (!this.isValidDomain(domain)) {
        console.error(`[DNS Validator] Invalid domain format: ${domain}`);
        throw new Error('Invalid domain format');
      }
      console.log(`[DNS Validator] ✓ Domain format is valid: ${domain}`);

      // Step 2: Construct DNS query URL
      const url = `${this.dnsApiUrl}?name=${encodeURIComponent(domain)}&type=TXT`;
      console.log(`[DNS Validator] DNS query URL: ${url}`);

      // Step 3: Perform DNS-over-HTTPS query
      console.log(`[DNS Validator] Executing DNS-over-HTTPS query...`);
      const response = await fetch(url, {
        headers: {
          'Accept': 'application/dns-json',
        },
      });

      if (!response.ok) {
        console.error(`[DNS Validator] DNS query failed: ${response.status} ${response.statusText}`);
        throw new Error(`DNS query failed: ${response.statusText}`);
      }

      console.log(`[DNS Validator] ✓ DNS query successful: ${response.status} ${response.statusText}`);

      // Step 4: Parse DNS response
      const data = await response.json() as DNSResponse;
      console.log(`[DNS Validator] DNS response status: ${data.Status}`);
      console.log(`[DNS Validator] DNS response structure:`, {
        answerCount: data.Answer?.length || 0,
        authorityCount: data.Authority?.length || 0,
        hasAnswer: !!data.Answer,
        hasAuthority: !!data.Authority
      });
      
      // Step 5: Extract and process TXT records
      const txtRecords = (data.Answer || [])
        .filter(record => record.type === 16) // TXT record type (16)
        .map(record => record.data.replace(/^"|"$/g, '')); // Remove surrounding quotes
      
      console.log(`[DNS Validator] Extracted ${txtRecords.length} TXT record(s):`, txtRecords);
      
      // Step 6: Log TXT record analysis for debugging
      txtRecords.forEach((record, index) => {
        console.log(`[DNS Validator] TXT record ${index + 1}:`, {
          length: record.length,
          startsWithSPF: record.startsWith('v=spf1'),
          startsWithDKIM: record.includes('v=DKIM1'),
          startsWithDMARC: record.startsWith('v=DMARC1'),
          preview: record.substring(0, 100) + (record.length > 100 ? '...' : '')
        });
      });
      
      return txtRecords;
    } catch (error) {
      console.error(`[DNS Validator] Error fetching TXT records for ${domain}:`, error);
      throw error; // Re-throw to let the controller handle it
    }
  }

  /**
   * Validates if a string represents a valid domain format
   * 
   * This method uses a permissive domain validation regex that handles:
   * - Standard domains (example.com)
   * - Subdomains (sub.example.com)
   * - Internationalized domain names (IDN)
   * - Various TLD patterns
   * 
   * @param domain - The domain string to validate
   * @returns boolean - True if valid domain format, false otherwise
   */
  private isValidDomain(domain: string): boolean {
    // More permissive domain validation regex that handles real-world domains
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$/;
    const isValid = domainRegex.test(domain);
    
    if (!isValid) {
      console.warn(`[DNS Validator] Domain validation failed for: ${domain}`);
    }
    
    return isValid;
  }

  /**
   * Extracts the root domain from a given domain string
   * 
   * This method handles various domain scenarios:
   * - Simple domains (example.com -> example.com)
   * - Subdomains (sub.example.com -> example.com)
   * - Multi-level TLDs (example.co.uk -> example.co.uk)
   * - Complex subdomains (deep.sub.example.co.uk -> example.co.uk)
   * 
   * @param domain - The domain to extract root from
   * @returns string - The root domain
   */
  private extractRootDomain(domain: string): string {
    console.log(`[DNS Validator] Extracting root domain from: ${domain}`);
    
    const parts = domain.split('.');
    console.log(`[DNS Validator] Domain parts:`, parts);
    
    if (parts.length <= 2) {
      console.log(`[DNS Validator] Simple domain, returning as-is: ${domain}`);
      return domain;
    }
    
    // Handle common multi-level TLDs
    const commonTlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'jp'];
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    
    console.log(`[DNS Validator] TLD analysis:`, {
      tld,
      sld,
      isCommonTld: commonTlds.includes(tld),
      isCommonSld: commonTlds.includes(sld)
    });
    
    if (commonTlds.includes(tld) && commonTlds.includes(sld)) {
      const rootDomain = parts.slice(-3).join('.');
      console.log(`[DNS Validator] Multi-level TLD detected, root domain: ${rootDomain}`);
      return rootDomain;
    }
    
    const rootDomain = parts.slice(-2).join('.');
    console.log(`[DNS Validator] Standard TLD, root domain: ${rootDomain}`);
    return rootDomain;
  }
} 