// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BlockchainForensics {

    struct Evidence {
        string caseId;
        string evidenceHash;  // SHA-256 hash
        string ipfsCID;       // IPFS Content Identifier
        uint timestamp;
        address investigator;
    }

    Evidence[] public evidences;

    // Mapping for case-based evidence lookup
    mapping(string => uint[]) public caseEvidenceIndexes;

    event EvidenceAdded(
        uint indexed evidenceIndex,
        string caseId,
        string evidenceHash,
        string ipfsCID,
        uint timestamp,
        address investigator
    );

    function addEvidence(
        string memory _caseId,
        string memory _evidenceHash,
        string memory _ipfsCID
    ) public {
        uint index = evidences.length;
        evidences.push(
            Evidence(
                _caseId,
                _evidenceHash,
                _ipfsCID,
                block.timestamp,
                msg.sender
            )
        );

        // Index evidence by case ID
        caseEvidenceIndexes[_caseId].push(index);

        emit EvidenceAdded(
            index,
            _caseId,
            _evidenceHash,
            _ipfsCID,
            block.timestamp,
            msg.sender
        );
    }

    function getEvidence(uint index) public view returns (
        string memory caseId,
        string memory evidenceHash,
        string memory ipfsCID,
        uint timestamp,
        address investigator
    ) {
        require(index < evidences.length, "Evidence index out of bounds");
        Evidence memory e = evidences[index];
        return (
            e.caseId,
            e.evidenceHash,
            e.ipfsCID,
            e.timestamp,
            e.investigator
        );
    }

    function getEvidenceCount() public view returns (uint) {
        return evidences.length;
    }

    function getCaseEvidenceCount(string memory _caseId) public view returns (uint) {
        return caseEvidenceIndexes[_caseId].length;
    }

    function getCaseEvidenceIndex(string memory _caseId, uint caseIndex) public view returns (uint) {
        require(caseIndex < caseEvidenceIndexes[_caseId].length, "Case evidence index out of bounds");
        return caseEvidenceIndexes[_caseId][caseIndex];
    }
}
