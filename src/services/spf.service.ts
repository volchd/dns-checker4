import { DNSResponse, DNSRecord } from '../types/dns.types';

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
}

export class SPFService {
  private async fetchSPFRecord(domain: string): Promise<string | null> {
    try {
      const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {
        headers: {
          'Accept': 'application/dns-json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch SPF record: ${response.statusText}`);
      }

      const data: DNSResponse = await response.json();
      
      // Find SPF record in TXT records
      const spfRecord = data.Answer?.find((record: DNSRecord) => 
        record.type === 16 && // TXT record type
        record.data.startsWith('"v=spf1')
      );

      return spfRecord ? spfRecord.data.replace(/^"|"$/g, '') : null;
    } catch (error) {
      console.error('Error fetching SPF record:', error);
      return null;
    }
  }

  private parseSPFRecord(rawRecord: string): SPFRecord {
    const mechanisms: SPFRecord['mechanisms'] = [];
    const modifiers: SPFRecord['modifiers'] = [];
    
    // Remove v=spf1 prefix and split by spaces
    const parts = rawRecord.replace('v=spf1 ', '').split(' ');
    
    for (const part of parts) {
      if (!part) continue;
      
      // Handle mechanisms
      if (part.startsWith('+') || part.startsWith('-') || part.startsWith('~') || part.startsWith('?')) {
        const qualifier = part[0];
        const mechanism = part.slice(1);
        const [type, value] = mechanism.split(':');
        
        mechanisms.push({
          type,
          value: value || '',
          qualifier,
        });
      } else if (part.includes('=')) {
        // Handle modifiers
        const [type, value] = part.split('=');
        modifiers.push({ type, value });
      } else {
        // Handle mechanisms without qualifiers
        const [type, value] = part.split(':');
        mechanisms.push({
          type,
          value: value || '',
          qualifier: '+', // Default qualifier
        });
      }
    }

    return {
      raw: rawRecord,
      mechanisms,
      modifiers,
    };
  }

  async getSPFRecord(domain: string): Promise<SPFRecord | null> {
    const rawRecord = await this.fetchSPFRecord(domain);
    if (!rawRecord) {
      return null;
    }

    return this.parseSPFRecord(rawRecord);
  }
} 