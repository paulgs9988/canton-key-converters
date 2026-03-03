#!/usr/bin/env node

/**
 * Extract Raw Ed25519 Private Key for Canton Loop Wallet
 * 
 * Canton Loop expects just the 32-byte raw private key in hex format,
 * not the full PKCS8 encoded version.
 */

import crypto from 'crypto';

/**
 * Generate an Ed25519 key pair and extract the raw private key
 */
function generateCantonLoopKey() {
  // Generate Ed25519 key pair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  });

  // Export private key as raw bytes (this is what we need!)
  const privateKeyObject = crypto.createPrivateKey(privateKey);
  
  // Export as JWK to get the raw key bytes
  const jwk = privateKeyObject.export({ format: 'jwk' });
  
  // The 'd' field in JWK contains the raw private key (base64url encoded)
  const rawPrivateKeyBase64 = jwk.d;
  
  // Convert base64url to hex
  const rawPrivateKeyBuffer = Buffer.from(rawPrivateKeyBase64, 'base64url');
  const rawPrivateKeyHex = rawPrivateKeyBuffer.toString('hex');
  
  // Also get the public key in raw format
  const publicKeyObject = crypto.createPublicKey(publicKey);
  const publicJwk = publicKeyObject.export({ format: 'jwk' });
  const rawPublicKeyBase64 = publicJwk.x;
  const rawPublicKeyBuffer = Buffer.from(rawPublicKeyBase64, 'base64url');
  const rawPublicKeyHex = rawPublicKeyBuffer.toString('hex');

  // Create fingerprint
  const hash = crypto.createHash('sha256');
  hash.update(rawPublicKeyBuffer);
  const fingerprint = hash.digest('hex').substring(0, 64);

  return {
    rawPrivateKeyHex,
    rawPublicKeyHex,
    privateKeyPEM: privateKey,
    publicKeyPEM: publicKey,
    fingerprint
  };
}

/**
 * Extract raw private key from existing PKCS8 hex
 */
function extractRawKeyFromPKCS8Hex(pkcs8Hex) {
  try {
    const buffer = Buffer.from(pkcs8Hex, 'hex');
    
    // Create private key from DER
    const privateKeyObject = crypto.createPrivateKey({
      key: buffer,
      format: 'der',
      type: 'pkcs8'
    });
    
    // Export as JWK to get raw key
    const jwk = privateKeyObject.export({ format: 'jwk' });
    const rawPrivateKeyBase64 = jwk.d;
    const rawPrivateKeyBuffer = Buffer.from(rawPrivateKeyBase64, 'base64url');
    const rawPrivateKeyHex = rawPrivateKeyBuffer.toString('hex');
    
    return rawPrivateKeyHex;
  } catch (error) {
    console.error('Error extracting key:', error.message);
    return null;
  }
}

/**
 * Display key information for Canton Loop import
 */
function displayCantonLoopInfo(keyData) {
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('    Canton Loop Wallet Import Information');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  console.log('📧 Email Address:');
  console.log('   Enter your email address\n');
  
  console.log('🔑 Private Key (COPY THIS FOR CANTON LOOP):');
  console.log('   ' + keyData.rawPrivateKeyHex);
  console.log('   (' + keyData.rawPrivateKeyHex.length + ' characters - this is the 32-byte raw key)\n');
  
  console.log('📌 Public Key (Raw Hex):');
  console.log('   ' + keyData.rawPublicKeyHex + '\n');
  
  console.log('🆔 Canton Fingerprint:');
  console.log('   ' + keyData.fingerprint + '\n');
  
  console.log('═══════════════════════════════════════════════════════════');
  console.log('HOW TO IMPORT TO CANTON LOOP:');
  console.log('1. Go to https://cantonloop.com');
  console.log('2. Click "Import Wallet"');
  console.log('3. Enter your email address');
  console.log('4. Paste the Private Key shown above');
  console.log('5. Complete the setup');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  console.log('⚠️  SECURITY WARNING:');
  console.log('• Keep this private key secret!');
  console.log('• Never share it with anyone');
  console.log('• Store it securely (password manager, hardware wallet)');
  console.log('═══════════════════════════════════════════════════════════\n');
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  return {
    extract: args.includes('--extract') || args.includes('-e'),
    pkcs8Hex: args.find(arg => !arg.startsWith('--') && !arg.startsWith('-')),
    help: args.includes('--help') || args.includes('-h')
  };
}

/**
 * Display help
 */
function displayHelp() {
  console.log(`
Canton Loop Wallet Key Generator

USAGE:
  node canton_loop_key.js [OPTIONS]
  node canton_loop_key.js --extract <PKCS8_HEX>

OPTIONS:
  --extract, -e <hex>   Extract raw key from existing PKCS8 hex
  --help, -h            Display this help message

EXAMPLES:
  # Generate new key for Canton Loop
  node canton_loop_key.js

  # Extract raw key from existing PKCS8 hex
  node canton_loop_key.js --extract 302e020100300506032b657004220420abcd...

WHAT YOU GET:
  - Raw 32-byte private key in hex (64 characters)
  - This is what Canton Loop wallet expects
  - Not the full PKCS8 encoded version
`);
}

// Main execution
function main() {
  const options = parseArgs();
  
  if (options.help) {
    displayHelp();
    return;
  }
  
  if (options.extract && options.pkcs8Hex) {
    console.log('Extracting raw private key from PKCS8 hex...\n');
    const rawKey = extractRawKeyFromPKCS8Hex(options.pkcs8Hex);
    if (rawKey) {
      console.log('Raw Private Key (for Canton Loop):');
      console.log(rawKey);
      console.log(`\n✓ Length: ${rawKey.length} characters (32 bytes)`);
    }
    return;
  }
  
  console.log('Generating new Ed25519 key for Canton Loop wallet...\n');
  
  const keyData = generateCantonLoopKey();
  displayCantonLoopInfo(keyData);
}

// Run the script
main();

export { generateCantonLoopKey, extractRawKeyFromPKCS8Hex };