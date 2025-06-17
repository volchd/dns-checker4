import { ValidateDomainService } from './validate-domain.service';

/**
 * Example usage of the ValidateDomainService
 * 
 * This example demonstrates how to use the comprehensive domain validation service
 * that checks DNS existence, SPF, DKIM, and DMARC records for a given domain.
 */

async function exampleUsage() {
  console.log('🔍 Domain Validation Service Example Usage\n');

  // Initialize the service
  const validateDomainService = new ValidateDomainService();

  // Example 1: Validate a well-configured domain
  console.log('📋 Example 1: Validating google.com');
  try {
    const result1 = await validateDomainService.validateDomain('google.com');
    
    if (validateDomainService.isSuccessResponse(result1)) {
      console.log('✅ Validation successful!');
      console.log(`📊 Total Score: ${result1.total_score}/${result1.total_max_score}`);
      console.log(`🔒 SPF Score: ${result1.spf_result.score}/20`);
      console.log(`🔑 DKIM Score: ${result1.kdim_result.score}/17`);
      console.log(`📧 DMARC Score: ${result1.dmarc_result.score}/29`);
      console.log(`📝 SPF Issues: ${result1.spf_result.issues.length}`);
      console.log(`📝 DKIM Issues: ${result1.kdim_result.issues.length}`);
      console.log(`📝 DMARC Issues: ${result1.dmarc_result.issues.length}`);
    } else {
      console.log('❌ Validation failed:', result1.error);
    }
  } catch (error) {
    console.error('❌ Error during validation:', error);
  }

  console.log('\n' + '='.repeat(50) + '\n');

  // Example 2: Validate a domain without proper configuration
  console.log('📋 Example 2: Validating example.com');
  try {
    const result2 = await validateDomainService.validateDomain('example.com');
    
    if (validateDomainService.isSuccessResponse(result2)) {
      console.log('✅ Validation successful!');
      console.log(`📊 Total Score: ${result2.total_score}/${result2.total_max_score}`);
      console.log(`🔒 SPF Score: ${result2.spf_result.score}/20`);
      console.log(`🔑 DKIM Score: ${result2.kdim_result.score}/17`);
      console.log(`📧 DMARC Score: ${result2.dmarc_result.score}/29`);
    } else {
      console.log('❌ Validation failed:', result2.error);
    }
  } catch (error) {
    console.error('❌ Error during validation:', error);
  }

  console.log('\n' + '='.repeat(50) + '\n');

  // Example 3: Handle invalid domain format
  console.log('📋 Example 3: Validating invalid domain format');
  try {
    const result3 = await validateDomainService.validateDomain('invalid-domain-format');
    
    if (validateDomainService.isSuccessResponse(result3)) {
      console.log('✅ Validation successful!');
    } else {
      console.log('❌ Validation failed:', result3.error);
    }
  } catch (error) {
    console.error('❌ Error during validation:', error);
  }

  console.log('\n' + '='.repeat(50) + '\n');

  // Example 4: Handle non-existent domain
  console.log('📋 Example 4: Validating non-existent domain');
  try {
    const result4 = await validateDomainService.validateDomain('nonexistentdomain12345.com');
    
    if (validateDomainService.isSuccessResponse(result4)) {
      console.log('✅ Validation successful!');
    } else {
      console.log('❌ Validation failed:', result4.error);
    }
  } catch (error) {
    console.error('❌ Error during validation:', error);
  }

  console.log('\n🎉 Example usage completed!');
}

// Run the example if this file is executed directly
if (require.main === module) {
  exampleUsage().catch(console.error);
}

export { exampleUsage }; 