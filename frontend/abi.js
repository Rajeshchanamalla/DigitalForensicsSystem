const EvidenceLedgerABI = [
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "internalType": "uint256",
                "name": "id",
                "type": "uint256"
            },
            {
                "indexed": false,
                "internalType": "string",
                "name": "evidenceHash",
                "type": "string"
            },
            {
                "indexed": false,
                "internalType": "string",
                "name": "caseId",
                "type": "string"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "name": "EvidenceStored",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_caseId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_hash",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_cid",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_uploadedBy",
                "type": "string"
            }
        ],
        "name": "addEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "evidenceCount",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "name": "evidences",
        "outputs": [
            {
                "internalType": "string",
                "name": "caseId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "evidenceHash",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "ipfsCid",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "uploadedBy",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "_id",
                "type": "uint256"
            }
        ],
        "name": "getEvidence",
        "outputs": [
            {
                "components": [
                    {
                        "internalType": "string",
                        "name": "caseId",
                        "type": "string"
                    },
                    {
                        "internalType": "string",
                        "name": "evidenceHash",
                        "type": "string"
                    },
                    {
                        "internalType": "string",
                        "name": "ipfsCid",
                        "type": "string"
                    },
                    {
                        "internalType": "string",
                        "name": "uploadedBy",
                        "type": "string"
                    },
                    {
                        "internalType": "uint256",
                        "name": "timestamp",
                        "type": "uint256"
                    }
                ],
                "internalType": "struct EvidenceLedger.Evidence",
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getEvidenceCount",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
];
