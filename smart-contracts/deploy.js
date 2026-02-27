const { Web3 } = require('web3');
const fs = require('fs');
const path = require('path');
const solc = require('solc');

async function deploy() {
    console.log('Connecting to blockchain network...');
    const ganacheUrl = process.env.BLOCKCHAIN_NETWORK || 'http://127.0.0.1:8547';
    const provider = new Web3.providers.HttpProvider(ganacheUrl);
    const web3 = new Web3(provider);

    const dataPath = path.resolve(__dirname, '../blockchain-data.json');

    // CHECK FOR EXISTING CONTRACT
    if (fs.existsSync(dataPath)) {
        try {
            const existingData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
            if (existingData.address) {
                const code = await web3.eth.getCode(existingData.address);
                if (code && code !== '0x') {
                    console.log('\n==========================================================');
                    console.log('⚠️  CONTRACT ALREADY DEPLOYED');
                    console.log('==========================================================');
                    console.log(`Address: ${existingData.address}`);
                    console.log('To force redeploy (and LOSE links to old data), delete blockchain-data.json');
                    console.log('or run with --force flag.');
                    console.log('==========================================================\n');
                    return;
                }
            }
        } catch (err) {
            console.warn('Could not read existing contract data, proceeding with new deployment.');
        }
    }

    try {
        const accounts = await web3.eth.getAccounts();
        // Select account with sufficient funds
        let deployer = null;
        for (const account of accounts) {
            const balance = await web3.eth.getBalance(account);
            const balanceEth = web3.utils.fromWei(balance, 'ether');
            if (parseFloat(balanceEth) > 5) {
                deployer = account;
                console.log('\nHD Wallet');
                console.log('==================');
                console.log(`Selected Account:  ${deployer}`);
                console.log(`Balance:           ${balanceEth} ETH`);
                break;
            }
        }

        if (!deployer) {
            console.error('No account with sufficient funds (> 5 ETH) found. Please restart Ganache or check configuration.');
            return;
        }

        // Compile Contract
        const contractPath = path.resolve(__dirname, 'EvidenceLedger.sol');
        const source = fs.readFileSync(contractPath, 'utf8');

        const input = {
            language: 'Solidity',
            sources: { 'EvidenceLedger.sol': { content: source } },
            settings: {
                optimizer: {
                    enabled: true,
                    runs: 200
                },
                evmVersion: 'paris',
                outputSelection: { '*': { '*': ['*'] } }
            }
        };

        const output = JSON.parse(solc.compile(JSON.stringify(input)));

        if (output.errors) {
            const errors = output.errors.filter(e => e.severity === 'error');
            if (errors.length > 0) {
                console.error('Compilation Errors:', errors);
                return;
            }
        }

        const contractFile = output.contracts['EvidenceLedger.sol']['EvidenceLedger'];
        const abi = contractFile.abi;
        const bytecode = contractFile.evm.bytecode.object;

        // Deploy Contract
        const contract = new web3.eth.Contract(abi);
        console.log('\nDeploying EvidenceLedger contract...');

        const deployTx = contract.deploy({ data: bytecode });

        const deployedContract = await deployTx.send({
            from: deployer,
            gas: 5000000,
            gasPrice: await web3.eth.getGasPrice(),
        });

        const contractAddress = deployedContract.options.address;

        const latestBlock = await web3.eth.getBlock('latest');
        const txHash = latestBlock.transactions[latestBlock.transactions.length - 1]; // Assume last tx in block
        const txHashString = (typeof txHash === 'object') ? txHash.hash : txHash;

        const receipt = await web3.eth.getTransactionReceipt(txHashString);

        console.log('\nContract created: ' + contractAddress);
        console.log('Transaction:      ' + txHashString);
        console.log('Gas usage:        ' + receipt.gasUsed);

        // Save ABI
        const blockchainData = {
            network: 'local',
            address: contractAddress,
            abi: abi,
            deployedAt: new Date().toISOString()
        };

        fs.writeFileSync(dataPath, JSON.stringify(blockchainData, null, 2));
        console.log('\nContract data saved to: ' + dataPath);
        console.log('Ready for backend connection.');

        return blockchainData;

    } catch (error) {
        console.error('Deployment failed:', error);
        throw error;
    }
}

if (require.main === module) {
    deploy().catch(console.error);
}

module.exports = deploy;
