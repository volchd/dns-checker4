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
      vi.spyOn(window, 'fetch').mockResolvedValue({
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
      vi.spyOn(window, 'fetch').mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          Status: 0,
          Answer: []
        })
      } as Response);

      const result = await spfService.getSPFRecord(mockDomain);
      expect(result).toBeNull();
    });

    it('should return null when fetch fails', async () => {
      vi.spyOn(window, 'fetch').mockRejectedValue(new Error('Network error'));

      const result = await spfService.getSPFRecord(mockDomain);
      expect(result).toBeNull();
    });

    it('should handle SPF record with modifiers', async () => {
      const recordWithModifier = '"v=spf1 include:_spf.google.com redirect=_spf.example.com"';
      vi.spyOn(window, 'fetch').mockResolvedValue({
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

      const result = await spfService.getSPFRecord(mockDomain);

      expect(result).not.toBeNull();
      expect(result?.mechanisms).toHaveLength(1);
      expect(result?.modifiers).toHaveLength(1);
      expect(result?.modifiers[0]).toEqual({
        type: 'redirect',
        value: '_spf.example.com'
      });
    });
  });
}); 