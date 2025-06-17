/**
 * External URLs Configuration
 * 
 * This file contains all external URLs used throughout the application.
 * Centralizing these URLs makes it easier to:
 * - Change DNS providers without modifying multiple files
 * - Configure different endpoints for different environments
 * - Maintain consistency across the application
 * - Test with different DNS services
 */

export const EXTERNAL_URLS = {
  // DNS-over-HTTPS endpoints
  DNS: {
    // Cloudflare DNS-over-HTTPS (used by SPF and DNS validator services)
    CLOUDFLARE: 'https://cloudflare-dns.com/dns-query',
    
    // Google DNS-over-HTTPS (used by DKIM service)
    GOOGLE: 'https://dns.google/resolve'
  }
} as const;

// Type for the configuration to ensure type safety
export type ExternalUrlsConfig = typeof EXTERNAL_URLS;

// Helper function to get DNS URL by provider
export function getDnsUrl(provider: 'cloudflare' | 'google'): string {
  switch (provider) {
    case 'cloudflare':
      return EXTERNAL_URLS.DNS.CLOUDFLARE;
    case 'google':
      return EXTERNAL_URLS.DNS.GOOGLE;
    default:
      throw new Error(`Unknown DNS provider: ${provider}`);
  }
}

// Default DNS provider configuration
export const DNS_CONFIG = {
  DEFAULT_PROVIDER: 'cloudflare' as const,
  FALLBACK_PROVIDER: 'google' as const
} as const; 