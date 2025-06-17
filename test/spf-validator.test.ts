import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SPFValidator } from '../src/services/spf-validator';
import { DNSValidator } from '../src/services/dns-validator';

// Mock DNSValidator
vi.mock('../src/services/dns-validator', () => {
  return {
    DNSValidator: vi.fn().mockImplementation(() => ({
      getTXTRecords: vi.fn()
    }))
  };
});

describe('SPFValidator', () => {
  let validator: SPFValidator;
  let mockDNSValidator: ReturnType<typeof vi.mocked<DNSValidator>>;

  beforeEach(() => {
    vi.resetAllMocks();
    validator = new SPFValidator();
    mockDNSValidator = (validator as any).dnsValidator;
  });

  it('should validate a valid SPF record', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ip4:192.168.0.1 include:_spf.google.com ~all'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(true);
    expect(result.score).toBeGreaterThan(0);
    expect(result.issues).toHaveLength(0);
    expect(result.mechanisms).toHaveLength(3);
    expect(result.lookupCount).toBe(1); // include mechanism
  });

  it('should detect missing SPF record', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.score).toBe(0);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: 'No SPF record found'
      })
    );
  });

  it('should detect multiple SPF records', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ip4:192.168.0.1 ~all',
      'v=spf1 include:_spf.google.com ~all'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: 'Multiple SPF records found'
      })
    );
  });

  it('should detect missing all mechanism', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ip4:192.168.0.1 include:_spf.google.com'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: 'Missing all mechanism'
      })
    );
  });

  it('should detect +all mechanism', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ip4:192.168.0.1 +all'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: 'Using +all mechanism'
      })
    );
  });

  it('should detect deprecated mechanisms', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ptr:example.com ~all'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(true);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'warning',
        message: 'Deprecated mechanisms found'
      })
    );
  });

  it('should calculate lookup count correctly', async () => {
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      'v=spf1 ip4:192.168.0.1 include:_spf.google.com include:_spf.microsoft.com a mx ~all'
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.lookupCount).toBe(4); // include (2) + a (1) + mx (1)
  });

  it('should detect excessive lookups', async () => {
    const includes = Array(11).fill('include:_spf.example.com').join(' ');
    mockDNSValidator.getTXTRecords.mockResolvedValue([
      `v=spf1 ${includes} ~all`
    ]);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: expect.stringContaining('too many DNS lookups')
      })
    );
  });

  it('should score different all mechanisms appropriately', async () => {
    const testCases = [
      { record: 'v=spf1 ip4:192.168.0.1 -all', expectedScore: 5 },
      { record: 'v=spf1 ip4:192.168.0.1 ~all', expectedScore: 3 },
      { record: 'v=spf1 ip4:192.168.0.1 ?all', expectedScore: 0 },
      { record: 'v=spf1 ip4:192.168.0.1 +all', expectedScore: 0 }
    ];

    for (const { record, expectedScore } of testCases) {
      mockDNSValidator.getTXTRecords.mockResolvedValue([record]);
      const result = await validator.validateSPF('example.com');
      expect(result.score).toBe(expectedScore);
    }
  });

  describe('redirect handling', () => {
    it('should follow redirect mechanism and validate target domain', async () => {
      // Mock original domain with redirect
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirected.com'];
        }
        if (domain === 'redirected.com') {
          return ['v=spf1 ip4:192.168.0.1 ~all'];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(true);
      expect(result.mechanisms).toHaveLength(2); // ip4 and all from redirected domain
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'info',
          message: 'SPF record redirects to redirected.com'
        })
      );
    });

    it('should handle redirect loops', async () => {
      // Mock domains with circular redirect
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirected.com'];
        }
        if (domain === 'redirected.com') {
          return ['v=spf1 redirect=example.com'];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'error',
          message: 'Maximum redirect depth exceeded'
        })
      );
    });

    it('should preserve redirect context in issues', async () => {
      // Mock domains with issues in redirected domain
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirected.com'];
        }
        if (domain === 'redirected.com') {
          return ['v=spf1 +all']; // Invalid SPF record
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'error',
          message: expect.stringContaining('Redirect (redirected.com): Using +all mechanism')
        })
      );
    });

    it('should handle missing redirect target', async () => {
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=nonexistent.com'];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'error',
          message: expect.stringContaining('Redirect (nonexistent.com): No SPF record found')
        })
      );
    });

    it('should handle redirect with multiple records in target', async () => {
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirected.com'];
        }
        if (domain === 'redirected.com') {
          return [
            'v=spf1 ip4:192.168.0.1 ~all',
            'v=spf1 include:_spf.google.com ~all'
          ];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'error',
          message: expect.stringContaining('Redirect (redirected.com): Multiple SPF records found')
        })
      );
    });

    it('should track the complete chain of redirects', async () => {
      // Mock domains with a chain of redirects
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirect1.com'];
        }
        if (domain === 'redirect1.com') {
          return ['v=spf1 redirect=redirect2.com'];
        }
        if (domain === 'redirect2.com') {
          return ['v=spf1 ip4:192.168.0.1 ~all'];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.redirects).toHaveLength(2);
      expect(result.redirects).toEqual([
        {
          from: 'example.com',
          to: 'redirect1.com',
          record: 'v=spf1 redirect=redirect1.com'
        },
        {
          from: 'redirect1.com',
          to: 'redirect2.com',
          record: 'v=spf1 redirect=redirect2.com'
        }
      ]);
      expect(result.details.finalDomain).toBe('redirect2.com');
    });

    it('should include redirect chain in the response even when validation fails', async () => {
      // Mock domains with a redirect to an invalid record
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=invalid.com'];
        }
        if (domain === 'invalid.com') {
          return ['v=spf1 +all']; // Invalid SPF record
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.redirects).toHaveLength(1);
      expect(result.redirects[0]).toEqual({
        from: 'example.com',
        to: 'invalid.com',
        record: 'v=spf1 redirect=invalid.com'
      });
      expect(result.details.finalDomain).toBe('invalid.com');
    });

    it('should track redirects even when max depth is exceeded', async () => {
      // Mock domains with too many redirects
      mockDNSValidator.getTXTRecords.mockImplementation(async (domain) => {
        if (domain === 'example.com') {
          return ['v=spf1 redirect=redirect1.com'];
        }
        if (domain === 'redirect1.com') {
          return ['v=spf1 redirect=redirect2.com'];
        }
        if (domain === 'redirect2.com') {
          return ['v=spf1 redirect=redirect3.com'];
        }
        if (domain === 'redirect3.com') {
          return ['v=spf1 ip4:192.168.0.1 ~all'];
        }
        return [];
      });

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.redirects).toHaveLength(2); // Should track up to max depth
      expect(result.redirects).toEqual([
        {
          from: 'example.com',
          to: 'redirect1.com',
          record: 'v=spf1 redirect=redirect1.com'
        },
        {
          from: 'redirect1.com',
          to: 'redirect2.com',
          record: 'v=spf1 redirect=redirect2.com'
        }
      ]);
      expect(result.details.finalDomain).toBe('redirect2.com');
    });
  });
}); 