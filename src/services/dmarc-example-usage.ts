import { DMARCService } from './dmarc.service';

/**
 * Example usage of the DMARC Service
 * 
 * This file demonstrates how to use the DMARC service to:
 * - Fetch DMARC records for domains
 * - Handle different response types
 * - Process DMARC record data
 */

async function exampleDMARCUsage() {
  const dmarcService = new DMARCService();
  
  // Example domains to test
  const domains = [
    'google.com',
    'microsoft.com',
    'github.com',
    'example.com' // This likely won't have DMARC
  ];
  
  console.log('🔍 DMARC Record Examples\n');
  
  for (const domain of domains) {
    console.log(`\n--- Checking DMARC for ${domain} ---`);
    
    try {
      const result = await dmarcService.getDMARCRecordForDomain(domain);
      
      if (dmarcService.isErrorResponse(result)) {
        console.log(`❌ Error: ${result.error}`);
        if (result.details) {
          console.log(`   Details: ${result.details}`);
        }
        if (result.suggestion) {
          console.log(`   Suggestion: ${result.suggestion}`);
        }
      } else {
        console.log(`✅ DMARC Record Found:`);
        console.log(`   Raw Record: ${result.record}`);
        console.log(`   Policy: ${result.parsed.policy}`);
        console.log(`   Subdomain Policy: ${result.parsed.subdomainPolicy || 'Not set'}`);
        console.log(`   Percentage: ${result.parsed.percentage || '100 (default)'}`);
        console.log(`   Reports: ${result.summary.reportCount}`);
        
        if (result.parsed.reports && result.parsed.reports.length > 0) {
          console.log(`   Report URIs:`);
          result.parsed.reports.forEach((report, index) => {
            console.log(`     ${index + 1}. ${report.type}: ${report.uri}`);
          });
        }
        
        if (result.parsed.adkim) {
          console.log(`   ADKIM: ${result.parsed.adkim}`);
        }
        
        if (result.parsed.aspf) {
          console.log(`   ASPF: ${result.parsed.aspf}`);
        }
        
        console.log(`   Processing Time: ${result.metadata.processingTime}ms`);
      }
      
    } catch (error) {
      console.error(`💥 Unexpected error for ${domain}:`, error);
    }
  }
}

// Example of validating a domain before processing
function exampleDomainValidation() {
  const dmarcService = new DMARCService();
  
  const testDomains = [
    '',
    'invalid-domain',
    'example.com',
    'subdomain.example.com'
  ];
  
  console.log('\n🔍 Domain Validation Examples\n');
  
  for (const domain of testDomains) {
    const validation = dmarcService.validateDomain(domain);
    
    if (validation.isValid) {
      console.log(`✅ "${domain}" is valid`);
    } else {
      console.log(`❌ "${domain}" is invalid: ${validation.error?.error}`);
    }
  }
}

// Example of parsing DMARC records manually
function exampleDMARCParsing() {
  const dmarcService = new DMARCService();
  
  const sampleRecords = [
    'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    'v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com',
    'v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1; adkim=r; aspf=s'
  ];
  
  console.log('\n🔍 DMARC Record Parsing Examples\n');
  
  for (const record of sampleRecords) {
    console.log(`\nRaw Record: ${record}`);
    
    const parsed = dmarcService['parseDMARCRecord'](record);
    
    console.log(`Parsed:`);
    console.log(`  Version: ${parsed.version}`);
    console.log(`  Policy: ${parsed.policy}`);
    console.log(`  Subdomain Policy: ${parsed.subdomainPolicy || 'Not set'}`);
    console.log(`  Percentage: ${parsed.percentage || '100 (default)'}`);
    console.log(`  Reports: ${parsed.reports?.length || 0}`);
    console.log(`  Failure Options: ${parsed.failureOptions?.join(', ') || 'None'}`);
    console.log(`  ADKIM: ${parsed.adkim || 'Not set'}`);
    console.log(`  ASPF: ${parsed.aspf || 'Not set'}`);
  }
}

// Run examples if this file is executed directly
if (require.main === module) {
  (async () => {
    await exampleDMARCUsage();
    exampleDomainValidation();
    exampleDMARCParsing();
  })();
}

export {
  exampleDMARCUsage,
  exampleDomainValidation,
  exampleDMARCParsing
}; 