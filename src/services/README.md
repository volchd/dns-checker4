# Services

This directory contains all the service classes that provide business logic for the DNS checker application.

## Available Services

### DNS Services
- **DNSValidator** (`dns-validator.ts`) - Validates DNS existence and retrieves TXT records
- **DNSController** (`../controllers/dns.controller.ts`) - Handles DNS-related HTTP requests

### SPF Services
- **SPFService** (`spf.service.ts`) - Retrieves and parses SPF records
- **SPFValidator** (`spf-validator.ts`) - Validates SPF records and provides scoring
- **SPFController** (`../controllers/spf.controller.ts`) - Handles SPF-related HTTP requests
- **SPFValidatorController** (`../controllers/spf-validator.controller.ts`) - Handles SPF validation HTTP requests

### DKIM Services
- **DKIMService** (`dkim.service.ts`) - Retrieves and parses DKIM records
- **DKIMValidator** (`dkim-validator.ts`) - Validates DKIM records and provides scoring
- **DKIMController** (`../controllers/dkim.controller.ts`) - Handles DKIM-related HTTP requests
- **DKIMValidatorController** (`../controllers/dkim-validator.controller.ts`) - Handles DKIM validation HTTP requests

### DMARC Services
- **DMARCService** (`dmarc.service.ts`) - Retrieves and parses DMARC records
- **DMARCValidator** (`dmarc-validator.ts`) - Validates DMARC records and provides scoring
- **DMARCController** (`../controllers/dmarc.controller.ts`) - Handles DMARC-related HTTP requests
- **DMARCValidatorController** (`../controllers/dmarc-validator.controller.ts`) - Handles DMARC validation HTTP requests

### Domain Validation Services
- **ValidateDomainService** (`validate-domain.service.ts`) - Comprehensive domain validation including DNS, SPF, DKIM, and DMARC
- **ValidateDomainController** (`../controllers/validate-domain.controller.ts`) - Handles comprehensive domain validation HTTP requests

## ValidateDomainService

The `ValidateDomainService` provides comprehensive validation of email domains by:

1. **DNS Existence Validation** - Uses DNS-over-HTTPS to verify the domain exists
2. **SPF Record Validation** - Validates SPF records and provides security scoring (0-20 points)
3. **DKIM Record Validation** - Validates DKIM records and provides security scoring (0-17 points)
4. **DMARC Record Validation** - Validates DMARC records and provides security scoring (0-29 points)
5. **Total Security Score** - Combines all scores for a comprehensive security assessment (0-100 points)

### Usage Example

```typescript
import { ValidateDomainService } from './validate-domain.service';

const service = new ValidateDomainService();

// Validate a domain
const result = await service.validateDomain('example.com');

if (service.isSuccessResponse(result)) {
  console.log(`Total Score: ${result.total_score}/${result.total_max_score}`);
  console.log(`SPF Score: ${result.spf_result.score}/20`);
  console.log(`DKIM Score: ${result.kdim_result.score}/17`);
  console.log(`DMARC Score: ${result.dmarc_result.score}/29`);
} else {
  console.error('Validation failed:', result.error);
}
```

### API Endpoint

The service is exposed via the `/validate-domain` endpoint:

```
GET /validate-domain?domain=example.com
```

### Response Format

The service returns a comprehensive validation result matching the structure in `sample.json`:

```json
{
  "total_score": 66,
  "total_max_score": 100,
  "spf_result": { /* SPF validation details */ },
  "kdim_result": { /* DKIM validation details */ },
  "dmarc_result": { /* DMARC validation details */ }
}
```

### Error Handling

The service provides detailed error responses for:
- Missing domain parameter
- Invalid domain format
- Non-existent domains
- DNS query failures

## Example Usage Files

- `spf-example-usage.ts` - SPF service usage examples
- `dkim-example-usage.ts` - DKIM service usage examples
- `dmarc-example-usage.ts` - DMARC service usage examples
- `validate-domain-example-usage.ts` - Comprehensive domain validation usage examples

## Testing

All services include comprehensive test suites in the `__tests__` directories:

- `src/services/__tests__/` - Service-specific tests
- `test/` - Integration and end-to-end tests

Run tests with:
```bash
npm test
``` 