# Configuration

This directory contains configuration files for the DNS Checker application.

## External URLs Configuration

The `external-urls.ts` file centralizes all external URLs used throughout the application.

### Benefits

- **Centralized Management**: All external URLs are defined in one place
- **Easy Maintenance**: Change DNS providers without modifying multiple files
- **Environment Flexibility**: Configure different endpoints for different environments
- **Consistency**: Ensure all services use the same endpoints
- **Testing**: Easily switch to different DNS services for testing

### Usage

```typescript
import { EXTERNAL_URLS, getDnsUrl, DNS_CONFIG } from '../config';

// Use predefined URLs
const cloudflareUrl = EXTERNAL_URLS.DNS.CLOUDFLARE;
const googleUrl = EXTERNAL_URLS.DNS.GOOGLE;

// Use helper function
const dnsUrl = getDnsUrl('cloudflare');

// Use default configuration
const defaultProvider = DNS_CONFIG.DEFAULT_PROVIDER;
```

### Available DNS Providers

- **Cloudflare**: `https://cloudflare-dns.com/dns-query`
  - Used by SPF and DNS validator services
  - Fast and reliable DNS-over-HTTPS service

- **Google**: `https://dns.google/resolve`
  - Used by DKIM service
  - Google's public DNS service

### Adding New Providers

To add a new DNS provider:

1. Add the URL to `EXTERNAL_URLS.DNS` in `external-urls.ts`
2. Update the `getDnsUrl` function to handle the new provider
3. Update any services that should use the new provider

### Environment-Specific Configuration

For different environments (development, staging, production), you can:

1. Create environment-specific configuration files
2. Use environment variables to override URLs
3. Implement a configuration loader that reads from environment variables

Example with environment variables:

```typescript
export const EXTERNAL_URLS = {
  DNS: {
    CLOUDFLARE: process.env.CLOUDFLARE_DNS_URL || 'https://cloudflare-dns.com/dns-query',
    GOOGLE: process.env.GOOGLE_DNS_URL || 'https://dns.google/resolve'
  }
} as const;
``` 