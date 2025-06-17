import { DMARCValidator } from './dmarc-validator';

/**
 * DMARC Validator Example Usage
 * 
 * This file demonstrates how to use the DMARC Validator service to validate
 * DMARC records for email domains. The validator provides comprehensive
 * analysis including syntax validation, policy evaluation, and security scoring.
 * 
 * Example DMARC records:
 * - v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;
 * - v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com;
 * - v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=0;
 */

async function demonstrateDMARCValidation() {
  console.log('🔍 DMARC Validator Example Usage\n');

  const validator = new DMARCValidator();

  // Example 1: Validate a domain with comprehensive DMARC configuration
  console.log('📧 Example 1: Validating example.com (comprehensive DMARC setup)');
  try {
    const result1 = await validator.validateDMARC('example.com');
    
    console.log(`✅ Validation Result:`);
    console.log(`   Valid: ${result1.isValid}`);
    console.log(`   Score: ${result1.score}/22`);
    console.log(`   Record: ${result1.record}`);
    console.log(`   Issues: ${result1.issues.length}`);
    console.log(`   Recommendations: ${result1.recommendations.length}`);
    
    if (result1.issues.length > 0) {
      console.log(`   Issues found:`);
      result1.issues.forEach((issue, index) => {
        console.log(`     ${index + 1}. [${issue.type.toUpperCase()}] ${issue.message}`);
        if (issue.recommendation) {
          console.log(`        Recommendation: ${issue.recommendation}`);
        }
      });
    }
    
    if (result1.recommendations.length > 0) {
      console.log(`   Recommendations:`);
      result1.recommendations.forEach((rec, index) => {
        console.log(`     ${index + 1}. ${rec}`);
      });
    }
    
    console.log(`   Details:`);
    console.log(`     Has Version: ${result1.details.hasVersion}`);
    console.log(`     Has Valid Policy: ${result1.details.hasValidPolicy}`);
    console.log(`     Has Subdomain Policy: ${result1.details.hasSubdomainPolicy}`);
    console.log(`     Has Percentage: ${result1.details.hasPercentage}`);
    console.log(`     Has Reports: ${result1.details.hasReports}`);
    console.log(`     Final Domain: ${result1.details.finalDomain}`);
    
  } catch (error) {
    console.error(`❌ Error validating example.com:`, error);
  }

  console.log('\n' + '='.repeat(60) + '\n');

  // Example 2: Validate a domain with reporting configuration
  console.log('📧 Example 2: Validating google.com (with reporting)');
  try {
    const result2 = await validator.validateDMARC('google.com');
    
    console.log(`✅ Validation Result:`);
    console.log(`   Valid: ${result2.isValid}`);
    console.log(`   Score: ${result2.score}/22`);
    console.log(`   Record: ${result2.record}`);
    console.log(`   Issues: ${result2.issues.length}`);
    console.log(`   Recommendations: ${result2.recommendations.length}`);
    
    if (result2.recommendations.length > 0) {
      console.log(`   Recommendations:`);
      result2.recommendations.forEach((rec, index) => {
        console.log(`     ${index + 1}. ${rec}`);
      });
    }
    
  } catch (error) {
    console.error(`❌ Error validating google.com:`, error);
  }

  console.log('\n' + '='.repeat(60) + '\n');

  // Example 3: Validate a domain without DMARC record
  console.log('📧 Example 3: Validating non-existent domain (no DMARC record)');
  try {
    const result3 = await validator.validateDMARC('this-domain-definitely-does-not-exist-12345.com');
    
    console.log(`❌ Validation Result:`);
    console.log(`   Valid: ${result3.isValid}`);
    console.log(`   Score: ${result3.score}/22`);
    console.log(`   Record: ${result3.record || '(no record)'}`);
    console.log(`   Issues: ${result3.issues.length}`);
    
    if (result3.issues.length > 0) {
      console.log(`   Issues found:`);
      result3.issues.forEach((issue, index) => {
        console.log(`     ${index + 1}. [${issue.type.toUpperCase()}] ${issue.message}`);
        if (issue.recommendation) {
          console.log(`        Recommendation: ${issue.recommendation}`);
        }
      });
    }
    
  } catch (error) {
    console.error(`❌ Error validating non-existent domain:`, error);
  }

  console.log('\n' + '='.repeat(60) + '\n');

  // Example 4: Batch validation of multiple domains
  console.log('📧 Example 4: Batch validation of multiple domains');
  const domains = ['microsoft.com', 'github.com', 'cloudflare.com'];
  
  for (const domain of domains) {
    try {
      console.log(`\n🔍 Validating ${domain}...`);
      const result = await validator.validateDMARC(domain);
      
      console.log(`   Valid: ${result.isValid}`);
      console.log(`   Score: ${result.score}/22`);
      console.log(`   Policy: ${result.details.hasValidPolicy ? 'Valid' : 'Invalid'}`);
      console.log(`   Reports: ${result.details.hasReports ? 'Configured' : 'Not configured'}`);
      
    } catch (error) {
      console.error(`   ❌ Error validating ${domain}:`, error);
    }
  }

  console.log('\n' + '='.repeat(60) + '\n');
  console.log('✅ DMARC Validator Example Usage Complete!');
}

export { demonstrateDMARCValidation }; 