#!/usr/bin/env node

/**
 * Secure Private Key Generator for Canton Network
 * 
 * Canton Network uses Ed25519 (EC-Curve25519) as its default signing algorithm.
 * This script generates cryptographically secure Ed25519 key pairs.
 * 
 * USAGE: node generate_canton_key.js
 * 
 * SECURITY WARNING: 
 * - Store private keys securely and never share them
 * - Consider using hardware wallets or KMS for production use
 * - This script generates keys in memory - ensure secure environment
 */

const crypto = require('crypto');
const fs = require('fs');

/**
 * Generate an Ed25519 key pair for Canton Network
 * Ed25519 is Canton's default signing algorithm
 */
function generateEd25519KeyPair() {
  // Generate Ed25519 key pair using Node.js crypto
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

  // Export keys in DER format for hex representation
  const privateKeyDER = crypto.createPrivateKey(privateKey).export({
    type: 'pkcs8',
    format: 'der'
  });
  
  const publicKeyDER = crypto.createPublicKey(publicKey).export({
    type: 'spki',
    format: 'der'
  });

  const privateKeyHex = privateKeyDER.toString('hex');
  const publicKeyHex = publicKeyDER.toString('hex');

  return {
    privateKey,
    publicKey,
    privateKeyHex,
    publicKeyHex,
    keyFormat: 'PKCS8/SPKI',
    algorithm: 'Ed25519 (EC-Curve25519)'
  };
}

/**
 * Generate an ECDSA key pair using P-256 curve
 * Canton also supports EC-P-256 as an alternative
 */
function generateECDSAP256KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P-256
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  });

  const privateKeyDER = crypto.createPrivateKey(privateKey).export({
    type: 'pkcs8',
    format: 'der'
  });
  
  const publicKeyDER = crypto.createPublicKey(publicKey).export({
    type: 'spki',
    format: 'der'
  });

  return {
    privateKey,
    publicKey,
    privateKeyHex: privateKeyDER.toString('hex'),
    publicKeyHex: publicKeyDER.toString('hex'),
    keyFormat: 'PKCS8/SPKI',
    algorithm: 'ECDSA P-256'
  };
}

/**
 * Create a Canton-compatible party identifier fingerprint
 */
function createFingerprint(publicKeyHex) {
  const hash = crypto.createHash('sha256');
  hash.update(Buffer.from(publicKeyHex, 'hex'));
  return hash.digest('hex').substring(0, 64);
}

/**
 * Save keys to files securely
 * WARNING: This saves to disk - ensure proper file permissions
 */
function saveKeysToFile(keyPair, privateKeyPath, publicKeyPath) {
  // Save with restrictive permissions (owner read/write only)
  fs.writeFileSync(privateKeyPath, keyPair.privateKey, { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, keyPair.publicKey, { mode: 0o644 });
  
  console.log(`\n✓ Private key saved to: ${privateKeyPath}`);
  console.log(`✓ Public key saved to: ${publicKeyPath}`);
  console.log(`⚠️  IMPORTANT: Protect your private key! Permissions set to 600`);
}

/**
 * Display key information securely
 */
function displayKeyInfo(keyPair, showPrivateKey = false) {
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('         Canton Network Key Pair Generated');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  console.log(`Algorithm: ${keyPair.algorithm}`);
  console.log(`Key Format: ${keyPair.keyFormat}\n`);
  
  console.log('Public Key (PEM):');
  console.log(keyPair.publicKey);
  
  console.log('Public Key (Hex):');
  console.log(keyPair.publicKeyHex);
  
  if (keyPair.cantonFingerprint) {
    console.log(`\nCanton Fingerprint: ${keyPair.cantonFingerprint}`);
  }
  
  if (showPrivateKey) {
    console.log('\n⚠️  PRIVATE KEY - KEEP SECURE ⚠️');
    console.log('Private Key (PEM):');
    console.log(keyPair.privateKey);
    console.log('\nPrivate Key (Hex):');
    console.log(keyPair.privateKeyHex);
  } else {
    console.log('\n🔒 Private key hidden for security');
    console.log('   Run with --show-private flag to display');
  }
  
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('SECURITY REMINDERS:');
  console.log('• Never share your private key with anyone');
  console.log('• Store private keys in a secure location (hardware wallet/KMS)');
  console.log('• Make encrypted backups of your keys');
  console.log('• For production, use a Key Management Service (KMS)');
  console.log('═══════════════════════════════════════════════════════════\n');
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  return {
    showPrivate: args.includes('--show-private') || args.includes('-s'),
    saveToFile: args.includes('--save') || args.includes('-f'),
    algorithm: args.includes('--p256') ? 'p256' : 'ed25519',
    help: args.includes('--help') || args.includes('-h')
  };
}

/**
 * Display help information
 */
function displayHelp() {
  console.log(`
Canton Network Private Key Generator

USAGE:
  node generate_canton_key.js [OPTIONS]

OPTIONS:
  --show-private, -s    Display the private key (use with caution!)
  --save, -f            Save keys to files (canton_private.pem, canton_public.pem)
  --p256                Generate ECDSA P-256 key instead of Ed25519
  --help, -h            Display this help message

EXAMPLES:
  node generate_canton_key.js
  node generate_canton_key.js --show-private
  node generate_canton_key.js --save
  node generate_canton_key.js --show-private --save

SECURITY WARNING:
  Only use --show-private in secure, trusted environments.
  Never commit private keys to version control or share them.
`);
}

// Main execution
function main() {
  const options = parseArgs();
  
  if (options.help) {
    displayHelp();
    return;
  }
  
  console.log('Generating Canton Network compatible key pair...\n');
  
  // Generate key pair based on selected algorithm
  let keyPair;
  if (options.algorithm === 'p256') {
    console.log('Using ECDSA P-256 algorithm...\n');
    keyPair = generateECDSAP256KeyPair();
  } else {
    console.log('Using Ed25519 algorithm (Canton default)...\n');
    keyPair = generateEd25519KeyPair();
  }
  
  // Add fingerprint
  const fingerprint = createFingerprint(keyPair.publicKeyHex);
  keyPair.cantonFingerprint = fingerprint;
  
  // Display key information
  displayKeyInfo(keyPair, options.showPrivate);
  
  // Optionally save to files
  if (options.saveToFile) {
    saveKeysToFile(keyPair, './canton_private.pem', './canton_public.pem');
  }
  
  console.log('💡 TIP: Run with --help to see all available options\n');
}

// Run the script
main();

// Export functions for use as module
module.exports = {
  generateEd25519KeyPair,
  generateECDSAP256KeyPair,
  createFingerprint,
  saveKeysToFile,
  displayKeyInfo
};