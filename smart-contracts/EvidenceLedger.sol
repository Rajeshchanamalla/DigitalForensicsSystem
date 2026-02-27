// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EvidenceLedger
 * @dev Stores forensic evidence metadata on the blockchain.
 * Optimized for Gas usage and Safety.
 */
contract EvidenceLedger {

    struct Evidence {
        string caseId;
        string evidenceHash;
        string ipfsCid;
        string uploadedBy;
        uint256 timestamp;
    }

    // Mapping from Evidence ID to Evidence Data
    mapping(uint256 => Evidence) public evidences;
    uint256 public evidenceCount;

    // Event for easier tracking and logging
    event EvidenceStored(uint256 indexed id, string evidenceHash, string caseId, uint256 timestamp);

    /**
     * @notice Adds new evidence metadata to the ledger.
     * @dev Uses 'calldata' for string arguments to save gas.
     * @param _caseId The unique identifier of the case.
     * @param _hash The SHA-256 hash of the evidence file.
     * @param _cid The IPFS Content Identifier.
     * @param _uploadedBy The identifier of the uploader (e.g. Investigator ID).
     */
    function addEvidence(
        string memory _caseId,
        string memory _hash,
        string memory _cid,
        string memory _uploadedBy
    ) public {
        // Increment count
        evidenceCount++;

        // Store evidence
        evidences[evidenceCount] = Evidence(
            _caseId,
            _hash,
            _cid,
            _uploadedBy,
            block.timestamp
        );

        // Emit event for off-chain listeners (Backend/Logs)
        emit EvidenceStored(evidenceCount, _hash, _caseId, block.timestamp);
    }

    /**
     * @notice Returns the total number of evidence records.
     * @return uint256 count
     */
    function getEvidenceCount() external view returns (uint256) {
        return evidenceCount;
    }
    
    /**
     * @notice Retrieves evidence details by ID.
     * @param _id The ID of the evidence.
     * @return Evidence struct memory.
     */
    function getEvidence(uint256 _id) external view returns (Evidence memory) {
        return evidences[_id];
    }
}
