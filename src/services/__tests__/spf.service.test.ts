import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SPFService } from '../spf.service';

describe('SPFService', () => {
  let spfService: SPFService;
  const mockDomain = 'example.com';
  const mockSPFRecord = '"v=spf1 include:_spf.google.com include:sendgrid.net ~all"';

  beforeEach(() => {
    spfService = new SPFService();
    vi.clearAllMocks();
  });

  describe('getSPFRecord', () => {
    it('should return parsed SPF record for valid domain', async () => {
      // Mock fetch response
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          Status: 0,
          Answer: [{
            name: mockDomain,
            type: 16,
            TTL: 300,
            data: mockSPFRecord
          }]
        })
      } as Response);
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecord(mockDomain);

      expect(result).not.toBeNull();
      expect(result?.raw).toBe(mockSPFRecord.replace(/^"|"$/g, ''));
      expect(result?.mechanisms).toHaveLength(3);
      expect(result?.mechanisms[0]).toEqual({
        type: 'include',
        value: '_spf.google.com',
        qualifier: '+'
      });
      expect(result?.mechanisms[1]).toEqual({
        type: 'include',
        value: 'sendgrid.net',
        qualifier: '+'
      });
      expect(result?.mechanisms[2]).toEqual({
        type: 'all',
        value: '',
        qualifier: '~'
      });
    });

    it('should return null when no SPF record is found', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          Status: 0,
          Answer: []
        })
      } as Response);
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecord(mockDomain);
      expect(result).toBeNull();
    });

    it('should return null when fetch fails', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecord(mockDomain);
      expect(result).toBeNull();
    });

    it('should handle SPF record with modifiers', async () => {
      const recordWithModifier = '"v=spf1 include:_spf.google.com redirect=_spf.example.com"';
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          Status: 0,
          Answer: [{
            name: mockDomain,
            type: 16,
            TTL: 300,
            data: recordWithModifier
          }]
        })
      } as Response);
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecord(mockDomain);

      expect(result).not.toBeNull();
      expect(result?.mechanisms).toHaveLength(1);
      expect(result?.modifiers).toHaveLength(1);
      expect(result?.modifiers[0]).toEqual({
        type: 'redirect',
        value: '_spf.example.com'
      });
    });

    it('should track recursive processing counts for redirects and includes', async () => {
      // Mock the main domain response
      const mockFetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            Status: 0,
            Answer: [{
              name: mockDomain,
              type: 16,
              TTL: 300,
              data: '"v=spf1 include:_spf.google.com redirect=redirected.com"'
            }]
          })
        } as Response)
        // Mock the redirected domain response
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            Status: 0,
            Answer: [{
              name: 'redirected.com',
              type: 16,
              TTL: 300,
              data: '"v=spf1 include:_spf.microsoft.com ~all"'
            }]
          })
        } as Response)
        // Mock the included domain response (from main domain)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            Status: 0,
            Answer: [{
              name: '_spf.google.com',
              type: 16,
              TTL: 300,
              data: '"v=spf1 ip4:192.168.0.1 ~all"'
            }]
          })
        } as Response)
        // Mock the redirected domain's included domain response
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            Status: 0,
            Answer: [{
              name: '_spf.microsoft.com',
              type: 16,
              TTL: 300,
              data: '"v=spf1 ip4:10.0.0.1 ~all"'
            }]
          })
        } as Response);
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecord(mockDomain);

      expect(result).not.toBeNull();
      expect(result?.processedRedirects).toBe(1); // One redirect from main domain
      expect(result?.processedIncludes).toBe(2); // One include from main domain + one from redirected domain
      expect(result?.redirects).toHaveLength(1);
      expect(result?.includes).toHaveLength(1); // Only includes from the main domain are tracked
    });
  });

  describe('getSPFRecordForDomain', () => {
    it('should return formatted response with recursive processing counts', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          Status: 0,
          Answer: [{
            name: mockDomain,
            type: 16,
            TTL: 300,
            data: '"v=spf1 ip4:192.168.0.1 ~all"'
          }]
        })
      } as Response);
      vi.stubGlobal('fetch', mockFetch);

      const result = await spfService.getSPFRecordForDomain(mockDomain);

      expect(spfService.isSuccessResponse(result)).toBe(true);
      if (spfService.isSuccessResponse(result)) {
        expect(result.summary.processedRedirects).toBe(0);
        expect(result.summary.processedIncludes).toBe(0); // No includes in this record
        expect(result.summary.totalMechanisms).toBe(2);
        expect(result.summary.redirectCount).toBe(0);
      }
    });

    it('should handle domain validation errors', async () => {
      const result = await spfService.getSPFRecordForDomain('');

      expect(spfService.isErrorResponse(result)).toBe(true);
      if (spfService.isErrorResponse(result)) {
        expect(result.error).toBe('Domain parameter is required');
      }
    });
  });
}); 