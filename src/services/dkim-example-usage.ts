import { DKIMService } from './dkim.service';

/**
 * Example usage of the DKIM Service
 * Demonstrates the corrected logic for DKIM record retrieval and auditing
 */

async function demonstrateDKIMService() {
  const dkimService = new DKIMService();
  
  console.log('🔍 DKIM Service Example Usage\n');
  
  // Example 1: Single selector query
  console.log('1. Single Selector Query:');
  try {
    const result = await dkimService.getDKIMRecordForDomain('yahoo.com', 's1024');
    if (dkimService.isSuccessResponse(result)) {
      console.log(`✅ Found DKIM record for yahoo.com with selector 's1024':`);
      console.log(`   Record: ${result.record.substring(0, 100)}...`);
      console.log(`   Key Type: ${result.parsed.keyType}`);
      console.log(`   Key Length: ${result.summary.keyLength}`);
      console.log(`   Notes: ${result.parsed.notes}`);
    } else {
      console.log(`❌ Error: ${result.error}`);
    }
  } catch (error) {
    console.log(`❌ Exception: ${error}`);
  }
  
  // Example 2: Auto-discover all selectors (no selector provided)
  console.log('\n2. Auto-Discover All Selectors:');
  try {
    const result: any = await dkimService.getDKIMRecordForDomain('yahoo.com');
    if ('error' in result) {
      console.log(`❌ Error: ${result.error}`);
    } else if ('record' in result) {
      console.log(`✅ Single DKIM record found for yahoo.com:`);
      console.log(`   Selector: ${result.selector}`);
      console.log(`   Record: ${result.record.substring(0, 100)}...`);
      console.log(`   Key Type: ${result.parsed.keyType}`);
      console.log(`   Key Length: ${result.summary.keyLength}`);
    } else if ('selectorsFound' in result) {
      console.log(`✅ Comprehensive DKIM results for yahoo.com:`);
      console.log(`   Selectors Found: ${result.selectorsFound}`);
      console.log(`   Total Checked: ${result.summary.totalSelectorsChecked}`);
      console.log(`   Common Selectors: ${result.summary.commonSelectorsFound.join(', ')}`);
      
      if (result.records.length > 0) {
        console.log('\n   All Found Records:');
        result.records.forEach((record: any, index: number) => {
          console.log(`   ${index + 1}. Selector: ${record.selector}`);
          console.log(`      Key Type: ${record.parsed.keyType}`);
          console.log(`      Key Length: ${record.parsed.publicKey?.length || 0}`);
          console.log(`      Notes: ${record.parsed.notes}`);
          console.log(`      Raw Record: ${record.raw.substring(0, 80)}...`);
        });
      }
      
      if (result.summary.recommendations.length > 0) {
        console.log('\n   Recommendations:');
        result.summary.recommendations.forEach((rec: string, index: number) => {
          console.log(`   ${index + 1}. ${rec}`);
        });
      }
    }
  } catch (error) {
    console.log(`❌ Exception: ${error}`);
  }
  
  console.log('\n3. Comprehensive DKIM Audit:');
  try {
    const auditResult = await dkimService.auditDKIMForDomain('yahoo.com');
    console.log(`✅ DKIM Audit for yahoo.com:`);
    console.log(`   Selectors Found: ${auditResult.selectorsFound}`);
    console.log(`   Total Checked: ${auditResult.summary.totalSelectorsChecked}`);
    console.log(`   Common Selectors: ${auditResult.summary.commonSelectorsFound.join(', ')}`);
    console.log(`   Recommendations: ${auditResult.summary.recommendations.length}`);
    
    if (auditResult.records.length > 0) {
      console.log('\n   Found Records:');
      auditResult.records.forEach((record, index) => {
        console.log(`   ${index + 1}. Selector: ${record.selector}`);
        console.log(`      Key Type: ${record.parsed.keyType}`);
        console.log(`      Key Length: ${record.parsed.publicKey?.length || 0}`);
        console.log(`      Notes: ${record.parsed.notes}`);
      });
    }
  } catch (error) {
    console.log(`❌ Audit Exception: ${error}`);
  }
  
  console.log('\n4. Selector Discovery:');
  try {
    const selectors = await dkimService.discoverDKIMSelectors('yahoo.com');
    console.log(`✅ Discovered ${selectors.length} DKIM selectors for yahoo.com:`);
    selectors.forEach(({ selector, record }) => {
      console.log(`   - ${selector}: ${record.substring(0, 50)}...`);
    });
  } catch (error) {
    console.log(`❌ Discovery Exception: ${error}`);
  }
}

// Run the example
demonstrateDKIMService().catch(console.error); 