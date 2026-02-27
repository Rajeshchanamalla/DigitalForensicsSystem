/**
 * Blockchain Integration Utilities
 * Ethereum/Smart Contract Integration
 * Supports: External Ganache (local dev) OR Embedded Ganache (cloud deploy)
 */

const { Web3 } = require('web3');
const mysql = require('mysql2/promise');
const config = require('../config');
const fs = require('fs');
const path = require('path');

// Create connection pool
const pool = mysql.createPool(config.database);

// Blockchain configuration
const deployContract = require('../../smart-contracts/deploy');

// Blockchain configuration
let contractData = null;
let embeddedGanache = null;  // Holds the embedded Ganache server instance

function loadContractData() {
    try {
        const dataPath = path.resolve(__dirname, '../../blockchain-data.json');
        if (fs.existsSync(dataPath)) {
            contractData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
            return contractData;
        }
    } catch (error) {
        console.warn('Could not load blockchain contract data:', error.message);
    }
    return null;
}

contractData = loadContractData();

// If BLOCKCHAIN_NETWORK is not set, use embedded Ganache on a random port
const useEmbeddedGanache = !process.env.BLOCKCHAIN_NETWORK;
const EMBEDDED_GANACHE_PORT = 8547;

const BLOCKCHAIN_CONFIG = {
    network: process.env.BLOCKCHAIN_NETWORK || `http://127.0.0.1:${EMBEDDED_GANACHE_PORT}`,
    contractAddress: contractData ? contractData.address : process.env.CONTRACT_ADDRESS,
    enabled: process.env.BLOCKCHAIN_ENABLED !== 'false'  // enabled unless explicitly set to 'false'
};

/**
 * Start an embedded Ganache instance for cloud deployments
 * (used when BLOCKCHAIN_NETWORK env var is not configured)
 */
async function startEmbeddedGanache() {
    if (!useEmbeddedGanache) return;
    try {
        const ganache = require('ganache');
        console.log('🔗 Starting embedded Ganache blockchain...');
        embeddedGanache = ganache.server({
            wallet: { deterministic: true, totalAccounts: 10 },
            chain: { networkId: 1337, chainId: 1337 },
            miner: { blockGasLimit: 30000000 },
            logging: { quiet: true }  // Suppress verbose logs in production
        });
        await embeddedGanache.listen(EMBEDDED_GANACHE_PORT);
        console.log(`✅ Embedded Ganache started on port ${EMBEDDED_GANACHE_PORT}`);

        // Clear saved contract data since embedded Ganache starts fresh on each restart
        contractData = null;
        BLOCKCHAIN_CONFIG.contractAddress = null;
    } catch (error) {
        console.warn('⚠️ Could not start embedded Ganache:', error.message);
    }
}

let web3 = null;
let contract = null;

async function initializeBlockchain() {
    if (!BLOCKCHAIN_CONFIG.enabled) return;

    // Start embedded Ganache first if no external blockchain is configured
    await startEmbeddedGanache();

    try {
        const HttpProvider = Web3.providers.HttpProvider;
        const provider = new HttpProvider(BLOCKCHAIN_CONFIG.network);
        web3 = new Web3(provider);

        console.log(`🔌 Attempting to connect to Blockchain at ${BLOCKCHAIN_CONFIG.network}...`);

        // Check if connected
        try {
            await web3.eth.net.isListening();
        } catch (e) {
            console.error('❌ Blockchain Not Reachable. Is Ganache running?');
            return;
        }

        // Check Contract
        let address = BLOCKCHAIN_CONFIG.contractAddress;
        let requiresDeploy = false;

        if (!address) {
            console.warn('⚠️ No contract address found in config.');
            requiresDeploy = true;
        } else {
            const code = await web3.eth.getCode(address);
            if (code === '0x' || code === '0x0') {
                console.warn(`⚠️ Contract at ${address} has no code (Chain reset?). Redeploying...`);
                requiresDeploy = true;
            }
        }

        if (requiresDeploy) {
            console.log('🚀 Triggering Auto-Deployment...');
            const newConfig = await deployContract();
            if (newConfig && newConfig.address) {
                contractData = newConfig;
                BLOCKCHAIN_CONFIG.contractAddress = newConfig.address;
                console.log(`✅ Auto-Deployment Successful. New Address: ${newConfig.address}`);
            } else {
                console.error('❌ Auto-Deployment Failed.');
                return;
            }
        }

        if (contractData && contractData.abi && BLOCKCHAIN_CONFIG.contractAddress) {
            contract = new web3.eth.Contract(contractData.abi, BLOCKCHAIN_CONFIG.contractAddress);
            console.log('✅ Blockchain Contract Initialized:', BLOCKCHAIN_CONFIG.contractAddress);
        }

    } catch (error) {
        console.warn('❌ Blockchain initialization error:', error.message);
    }
}

/**
 * Store evidence hash on blockchain
 */
async function storeEvidenceOnBlockchain(evidenceId, caseId, evidenceHash, ipfsCID, role = 'Investigator') {
    if (!BLOCKCHAIN_CONFIG.enabled || !web3) {
        return { success: false, message: 'Blockchain not enabled' };
    }

    try {
        const accounts = await web3.eth.getAccounts();
        const account = accounts[0];

        if (contract) {
            // Store via Smart Contract
            let transactionHash = null;
            try {
                // Ensure role is a string and not empty
                const uploaderRole = role || 'Investigator';

                console.log('Sending to Blockchain:', {
                    caseId: caseId,
                    hashLen: evidenceHash ? evidenceHash.length : 0,
                    cidLen: ipfsCID ? ipfsCID.length : 0,
                    role: uploaderRole
                });

                const receipt = await contract.methods.addEvidence(
                    caseId,
                    evidenceHash,
                    ipfsCID,
                    uploaderRole
                ).send({ from: account, gas: 500000, gasPrice: '2000000000' });

                transactionHash = receipt.transactionHash;
                console.log('Evidence stored on blockchain, tx:', transactionHash);
                console.log('\n--- Blockchain Receipt ---');
                console.log(`Case ID:       ${caseId}`);
                console.log(`Evidence Hash: ${evidenceHash}`);
                console.log(`IPFS CID:      ${ipfsCID}`);
                console.log('--------------------------\n');

                // Parse Event to get the ID
                const event = receipt.events.EvidenceStored;
                const blockchainId = event ? event.returnValues.id : null;

                // Store transaction in database (Confirmed)
                await pool.execute(
                    `INSERT INTO blockchain_transactions 
                     (evidence_id, transaction_hash, network, contract_address, status, created_at, confirmed_at) 
                     VALUES (?, ?, ?, ?, 'confirmed', NOW(), NOW())`,
                    [evidenceId, transactionHash, 'ethereum', BLOCKCHAIN_CONFIG.contractAddress]
                );

                return {
                    success: true,
                    transactionHash: transactionHash,
                    blockchainId: blockchainId,
                    message: 'Evidence metadata stored on blockchain'
                };
            } catch (txError) {
                console.error('Smart Contract Transaction Failed:', txError);

                // Use a random hash for failures to avoid duplicate key errors
                const failedTxHash = '0xfailed' + require('crypto').randomBytes(28).toString('hex');

                await pool.execute(
                    `INSERT INTO blockchain_transactions 
                     (evidence_id, transaction_hash, network, contract_address, status, created_at) 
                     VALUES (?, ?, ?, ?, 'failed', NOW())`,
                    [evidenceId, failedTxHash, 'ethereum', BLOCKCHAIN_CONFIG.contractAddress]
                );

                return { success: false, error: 'Smart Contract Error: ' + txError.message };
            }
        } else {
            console.warn('Contract not initialized, falling back to simulated tx');
            // Fallback (Simulated)
            return await storeTransactionHash(evidenceId, caseId, evidenceHash, ipfsCID);
        }
    } catch (error) {
        console.error('Blockchain storage error:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Store transaction hash (simulated)
 */
async function storeTransactionHash(evidenceId, caseId, evidenceHash, ipfsCID) {
    // Generate a simulated transaction hash
    const txHash = '0x' + require('crypto').randomBytes(32).toString('hex');

    // Store in database
    await pool.execute(
        `INSERT INTO blockchain_transactions 
         (evidence_id, transaction_hash, network, status, created_at) 
         VALUES (?, ?, ?, 'pending', NOW())`,
        [evidenceId, txHash, 'ethereum']
    );

    return {
        success: true,
        transactionHash: txHash,
        message: 'Transaction hash stored (blockchain integration simulated)'
    };
}

// ... (previous code)

/**
 * Print all blockchain history (Startup Log)
 */
async function printBlockchainHistory() {
    if (!BLOCKCHAIN_CONFIG.enabled || !web3 || !contract) {
        console.log('Blockchain history skipped: Not connected.');
        return;
    }

    try {
        console.log('\n============================================================');
        console.log('🔗 BLOCKCHAIN LEDGER HISTORY');
        console.log('============================================================');

        const count = await contract.methods.evidenceCount().call();
        console.log(`Total Evidence Records on Chain: ${count}`);

        if (count > 0) {
            console.log('\n--- Past Evidence Records ---');
            for (let i = 1; i <= count; i++) {
                try {
                    const data = await contract.methods.getEvidence(i).call();
                    console.log(`\n[Record #${i}]`);
                    console.log(`Case ID:      ${data.caseId}`);
                    console.log(`Hash:         ${data.evidenceHash}`);
                    console.log(`IPFS CID:     ${data.ipfsCid}`);
                    console.log(`Uploader:     ${data.uploadedBy}`);
                    console.log(`Timestamp:    ${new Date(Number(data.timestamp) * 1000).toLocaleString()}`);
                    console.log('-----------------------------');
                } catch (recordError) {
                    console.error(`\n[Record #${i}] Error retrieving data: ${recordError.message}`);
                }
            }
        }
        console.log('============================================================\n');
    } catch (error) {
        console.error('Error printing blockchain history:', error.message);
    }
}

/**
 * Verify evidence on blockchain
 */
async function verifyEvidenceOnBlockchain(evidenceHash, ipfsCID) {
    if (!BLOCKCHAIN_CONFIG.enabled || !web3) {
        return { verified: false, message: 'Blockchain not enabled' };
    }

    try {
        if (contract) {
            // New logic: Check by hash if we don't have ID, or rely on chain data iteration (expensive but accurate for small sets)
            // Or use the Transaction Hash from DB if available.

            // First, try DB lookup for transaction hash
            const [rows] = await pool.execute(
                `SELECT transaction_hash FROM blockchain_transactions 
                 WHERE evidence_id IN (SELECT id FROM evidence WHERE evidence_hash = ?) 
                 ORDER BY created_at DESC LIMIT 1`,
                [evidenceHash]
            );

            if (rows.length > 0) {
                // We have a tx hash, let's just verify the content exists on chain by re-fetching
                // Optimization: Loop count downwards to find match (assuming recent)
                const count = await contract.methods.evidenceCount().call();
                for (let i = Number(count); i >= 1; i--) {
                    const data = await contract.methods.getEvidence(i).call();
                    if (data.evidenceHash === evidenceHash) {
                        return {
                            verified: true,
                            onChainData: {
                                blockchainId: i, // Return the actual on-chain index
                                evidenceHash: data.evidenceHash,
                                ipfsCID: data.ipfsCid,
                                caseId: data.caseId,
                                uploader: data.uploadedBy,
                                timestamp: new Date(Number(data.timestamp) * 1000).toISOString()
                            }
                        };
                    }
                }
            }

            // Fallback scan if DB fail or no match
            const count = await contract.methods.evidenceCount().call();
            for (let i = Number(count); i >= 1; i--) {
                const data = await contract.methods.getEvidence(i).call();
                // Verify if hashes match
                if (data.evidenceHash.toLowerCase() === evidenceHash.toLowerCase()) {

                    // Result
                    return {
                        verified: true,
                        onChainData: {
                            blockchainId: 0, // Not available without search
                            evidenceHash: evidenceHash,
                            ipfsCID: ipfsCID || 'N/A', // We don't have this if we just verifying content hash
                            timestamp: new Date().toISOString()
                        }
                    };
                }
            }
            // If loop finishes without finding a match
            return { verified: false, message: 'Evidence not found on blockchain' };

        } else {
            console.warn('Contract not initialized, cannot verify evidence on blockchain.');
            return { verified: false, message: 'Blockchain contract not initialized' };
        }
    } catch (error) {
        console.error('Error verifying evidence on blockchain:', error);
        return { verified: false, message: error.message };
    }
}

module.exports = {
    storeEvidenceOnBlockchain,
    verifyEvidenceOnBlockchain,
    printBlockchainHistory,
    initializeBlockchain,
    BLOCKCHAIN_CONFIG
};
