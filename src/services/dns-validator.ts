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
  private readonly dnsApiUrl = 'https://cloudflare-dns.com/dns-query';

  async validateDNS(domain: string): Promise<DNSValidatorResponse> {
    try {
      // Basic domain validation
      if (!this.isValidDomain(domain)) {
        return {
          exists: false,
          error: 'Invalid domain format',
        };
      }

      // Extract the root domain (e.g., example.com from sub.example.com)
      const rootDomain = this.extractRootDomain(domain);
      console.log('Checking domain:', rootDomain); // Debug log

      // Check NS records using DNS-over-HTTPS
      const response = await fetch(
        `${this.dnsApiUrl}?name=${encodeURIComponent(rootDomain)}&type=NS`,
        {
          headers: {
            'Accept': 'application/dns-json',
          },
        }
      );

      if (!response.ok) {
        return {
          exists: false,
          error: `DNS query failed: ${response.statusText}`,
          details: {
            status: response.status,
            statusText: response.statusText
          }
        };
      }

      const data = await response.json() as DNSResponse;
      console.log('DNS Response:', data);

      // Check if we got any NS records
      const hasNSRecords = Boolean(
        data.Answer?.some(record => record.type === 2) || 
        data.Authority?.some(record => record.type === 2)
      );

      return {
        exists: hasNSRecords,
        details: {
          status: data.Status,
          answer: data.Answer,
          authority: data.Authority
        }
      };
    } catch (error) {
      return {
        exists: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
        details: { error }
      };
    }
  }

  private isValidDomain(domain: string): boolean {
    // Basic domain validation regex
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  }

  private extractRootDomain(domain: string): string {
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    
    // Handle common TLDs
    const commonTlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'jp'];
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    
    if (commonTlds.includes(tld) && commonTlds.includes(sld)) {
      return parts.slice(-3).join('.');
    }
    
    return parts.slice(-2).join('.');
  }
} 