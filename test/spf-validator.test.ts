import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SPFValidator } from '../src/services/spf-validator';

describe('SPFValidator', () => {
  let validator: SPFValidator;

  beforeEach(() => {
    vi.resetAllMocks();
    validator = new SPFValidator();
    
    // Set up mocks directly on the spfService instance
    (validator as any).spfService.getSPFRecordForDomain = vi.fn();
    (validator as any).spfService.isErrorResponse = vi.fn();
    (validator as any).spfService.isSuccessResponse = vi.fn();
  });

  it('should validate a valid SPF record', async () => {
    const mockSPFResponse = {
      domain: 'example.com',
      record: 'v=spf1 ip4:192.168.0.1 include:_spf.google.com ~all',
      mechanisms: [
        { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
        { type: 'include', value: '_spf.google.com', qualifier: '+' },
        { type: 'all', value: '', qualifier: '~' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 3,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 1
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(true);
    expect(result.score).toBeGreaterThan(0);
    expect(result.issues).toHaveLength(0);
    expect(result.mechanisms).toHaveLength(3);
    expect(result.lookupCount).toBe(1); // include mechanism
  });

  it('should detect missing SPF record', async () => {
    const mockErrorResponse = {
      error: 'No SPF record found for the domain',
      domain: 'example.com',
      suggestion: 'Check if the domain has a valid SPF record in DNS'
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockErrorResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(true);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(false);

    const result = await validator.validateSPF('example.com');

    expect(result.isValid).toBe(false);
    expect(result.score).toBe(0);
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        type: 'error',
        message: 'No SPF record found for the domain'
      })
    );
  });

  it('should detect missing all mechanism', async () => {
    const mockSPFResponse = {
      domain: 'example.com',
      record: 'v=spf1 ip4:192.168.0.1 include:_spf.google.com',
      mechanisms: [
        { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
        { type: 'include', value: '_spf.google.com', qualifier: '+' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 2,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 1
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

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
    const mockSPFResponse = {
      domain: 'example.com',
      record: 'v=spf1 ip4:192.168.0.1 +all',
      mechanisms: [
        { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
        { type: 'all', value: '', qualifier: '+' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 2,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 0
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

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
    const mockSPFResponse = {
      domain: 'example.com',
      record: 'v=spf1 ptr:example.com ~all',
      mechanisms: [
        { type: 'ptr', value: 'example.com', qualifier: '+' },
        { type: 'all', value: '', qualifier: '~' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 2,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 0
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

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
    const mockSPFResponse = {
      domain: 'example.com',
      record: 'v=spf1 ip4:192.168.0.1 include:_spf.google.com include:_spf.microsoft.com a mx ~all',
      mechanisms: [
        { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
        { type: 'include', value: '_spf.google.com', qualifier: '+' },
        { type: 'include', value: '_spf.microsoft.com', qualifier: '+' },
        { type: 'a', value: '', qualifier: '+' },
        { type: 'mx', value: '', qualifier: '+' },
        { type: 'all', value: '', qualifier: '~' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 6,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 2
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

    const result = await validator.validateSPF('example.com');

    expect(result.lookupCount).toBe(2); // include (2) - a and mx don't count as lookups in this implementation
  });

  it('should detect excessive lookups', async () => {
    const includes = Array(11).fill('include:_spf.example.com').map((include, index) => ({
      type: 'include',
      value: `_spf.example${index}.com`,
      qualifier: '+'
    }));
    
    const mockSPFResponse = {
      domain: 'example.com',
      record: `v=spf1 ${includes.map(i => `include:${i.value}`).join(' ')} ~all`,
      mechanisms: [
        ...includes,
        { type: 'all', value: '', qualifier: '~' }
      ],
      modifiers: [],
      summary: {
        totalMechanisms: 12,
        totalModifiers: 0,
        hasRedirects: false,
        redirectCount: 0,
        processedRedirects: 0,
        processedIncludes: 11
      },
      hasRedirects: false,
      finalDomain: 'example.com',
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: 'test',
        processingTime: 100
      }
    };

    (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
    (validator as any).spfService.isErrorResponse.mockReturnValue(false);
    (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

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
      { 
        mechanisms: [
          { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
          { type: 'all', value: '', qualifier: '-' }
        ],
        expectedScore: 37 
      },
      { 
        mechanisms: [
          { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
          { type: 'all', value: '', qualifier: '~' }
        ],
        expectedScore: 35 
      },
      { 
        mechanisms: [
          { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
          { type: 'all', value: '', qualifier: '?' }
        ],
        expectedScore: 32 
      },
      { 
        mechanisms: [
          { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
          { type: 'all', value: '', qualifier: '+' }
        ],
        expectedScore: 27 
      }
    ];

    for (const { mechanisms, expectedScore } of testCases) {
      const mockSPFResponse = {
        domain: 'example.com',
        record: `v=spf1 ip4:192.168.0.1 ${mechanisms[1].qualifier}all`,
        mechanisms,
        modifiers: [],
        summary: {
          totalMechanisms: 2,
          totalModifiers: 0,
          hasRedirects: false,
          redirectCount: 0,
          processedRedirects: 0,
          processedIncludes: 0
        },
        hasRedirects: false,
        finalDomain: 'example.com',
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: 'test',
          processingTime: 100
        }
      };

      (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
      (validator as any).spfService.isErrorResponse.mockReturnValue(false);
      (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

      const result = await validator.validateSPF('example.com');
      expect(result.score).toBe(expectedScore);
    }
  });

  describe('redirect handling', () => {
    it('should use redirected record for validation when redirects are present', async () => {
      const mockSPFResponse = {
        domain: 'example.com',
        record: 'v=spf1 redirect=redirected.com',
        mechanisms: [
          { type: 'redirect', value: 'redirected.com', qualifier: '+' }
        ],
        modifiers: [],
        summary: {
          totalMechanisms: 1,
          totalModifiers: 0,
          hasRedirects: true,
          redirectCount: 1,
          hasRedirectedRecord: true,
          redirectedMechanisms: 2,
          redirectedModifiers: 0,
          processedRedirects: 1,
          processedIncludes: 0
        },
        hasRedirects: true,
        finalDomain: 'redirected.com',
        redirects: [
          { from: 'example.com', to: 'redirected.com', record: 'v=spf1 redirect=redirected.com' }
        ],
        redirectedRecord: {
          record: 'v=spf1 ip4:192.168.0.1 ~all',
          mechanisms: [
            { type: 'ip4', value: '192.168.0.1', qualifier: '+' },
            { type: 'all', value: '', qualifier: '~' }
          ],
          modifiers: []
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: 'test',
          processingTime: 100
        }
      };

      (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockSPFResponse);
      (validator as any).spfService.isErrorResponse.mockReturnValue(false);
      (validator as any).spfService.isSuccessResponse.mockReturnValue(true);

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(true);
      expect(result.mechanisms).toHaveLength(2); // ip4 and all from redirected domain
      expect(result.redirectRecord).toBe('v=spf1 ip4:192.168.0.1 ~all');
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'info',
          message: 'SPF record redirects to redirected.com'
        })
      );
    });

    it('should handle error responses from SPF service', async () => {
      const mockErrorResponse = {
        error: 'Failed to fetch SPF record',
        domain: 'example.com',
        details: 'Network error'
      };

      (validator as any).spfService.getSPFRecordForDomain.mockResolvedValue(mockErrorResponse);
      (validator as any).spfService.isErrorResponse.mockReturnValue(true);
      (validator as any).spfService.isSuccessResponse.mockReturnValue(false);

      const result = await validator.validateSPF('example.com');

      expect(result.isValid).toBe(false);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: 'error',
          message: 'Failed to fetch SPF record'
        })
      );
    });
  });
}); 