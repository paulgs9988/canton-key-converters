import * as readline from 'readline';
import { HDNodeWallet } from 'ethers';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('=== Secure Mnemonic to Private Key Converter ===');
console.log('WARNING: Never share your mnemonic or private key with anyone!\n');

rl.question('Enter your 12-word mnemonic phrase: ', async (mnemonic: string) => {
  try {
    // Trim and normalize whitespace
    const normalizedMnemonic = mnemonic.trim().replace(/\s+/g, ' ');
    
    // Create HD wallet from mnemonic with derivation path
    // This creates the wallet at the specified path directly
    const wallet = HDNodeWallet.fromPhrase(normalizedMnemonic, undefined, "m/44'/60'/0'/0/0");
    
    console.log('\n=== Results ===');
    console.log('Address:', wallet.address);
    console.log('Private Key:', wallet.privateKey);
    console.log('\n⚠️  SECURITY REMINDER:');
    console.log('- Clear your terminal history');
    console.log('- Never share this private key');
    console.log('- Store it securely offline');
    
  } catch (error) {
    console.error('\n❌ Error:', (error as Error).message);
    console.log('Please check your mnemonic phrase and try again.');
  } finally {
    // Clear sensitive data
    mnemonic = '';
    rl.close();
    process.exit(0);
  }
});