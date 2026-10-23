// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Implementations must be reviewed, version-pinned proof verifiers.
/// The eligibility proof must bind membership, scope, nullifier, and ballot hash.
/// The ballot proof must prove the ciphertext encodes exactly one allowed choice.
interface IElectionProofVerifier {
    function verifyEligibility(
        bytes calldata proof,
        bytes32 groupRoot,
        bytes32 scope,
        bytes32 nullifier,
        bytes32 ballotHash
    ) external view returns (bool);

    function verifyEncryptedBallot(
        bytes calldata proof,
        bytes calldata ciphertext,
        bytes32 manifestHash,
        bytes32 electionPublicKeyHash
    ) external view returns (bool);
}

/// @notice Verifies that a published aggregate tally follows from the accepted
/// ballot commitment and the election's encrypted tally protocol.
interface ITallyProofVerifier {
    function verifyTally(
        bytes32 acceptedBallotsHash,
        bytes32 resultHash,
        bytes32 manifestHash,
        bytes calldata proof
    ) external view returns (bool);
}

/// @notice Immutable ballot box for one election.
/// Candidate selections are never accepted as plaintext inputs and are never
/// emitted in events. Ballot proof, encryption, trustee, and tally schemes are
/// intentionally supplied through verifier contracts rather than mocked here.
contract SecureElection {
    bytes32 public immutable electionId;
    bytes32 public immutable manifestHash;
    bytes32 public immutable voterGroupRoot;
    bytes32 public immutable electionPublicKeyHash;
    uint64 public immutable votingStartsAt;
    uint64 public immutable votingEndsAt;
    IElectionProofVerifier public immutable proofVerifier;
    ITallyProofVerifier public immutable tallyVerifier;

    mapping(bytes32 nullifier => bool used) public nullifierUsed;

    // A deterministic commitment to the ordered list of accepted ballots.
    // Independent verifiers should also reconstruct the list from chain data.
    bytes32 public acceptedBallotsHash;
    bytes32 public resultHash;
    bool public tallyFinalized;

    event EncryptedBallotAccepted(
        bytes32 indexed electionId,
        bytes32 indexed nullifier,
        bytes32 indexed ballotHash,
        bytes ciphertext
    );
    event TallyPublished(bytes32 indexed electionId, bytes32 resultHash);

    error InvalidConfiguration();
    error VotingNotOpen();
    error VotingStillOpen();
    error NullifierAlreadyUsed();
    error InvalidNullifier();
    error InvalidEligibilityProof();
    error InvalidEncryptedBallot();
    error TallyAlreadyFinalized();
    error InvalidTallyProof();

    constructor(
        bytes32 electionId_,
        bytes32 manifestHash_,
        bytes32 voterGroupRoot_,
        bytes32 electionPublicKeyHash_,
        uint64 votingStartsAt_,
        uint64 votingEndsAt_,
        address proofVerifier_,
        address tallyVerifier_
    ) {
        if (
            electionId_ == bytes32(0) ||
            manifestHash_ == bytes32(0) ||
            voterGroupRoot_ == bytes32(0) ||
            electionPublicKeyHash_ == bytes32(0) ||
            votingStartsAt_ >= votingEndsAt_ ||
            proofVerifier_.code.length == 0 ||
            tallyVerifier_.code.length == 0
        ) revert InvalidConfiguration();

        electionId = electionId_;
        manifestHash = manifestHash_;
        voterGroupRoot = voterGroupRoot_;
        electionPublicKeyHash = electionPublicKeyHash_;
        votingStartsAt = votingStartsAt_;
        votingEndsAt = votingEndsAt_;
        proofVerifier = IElectionProofVerifier(proofVerifier_);
        tallyVerifier = ITallyProofVerifier(tallyVerifier_);
    }

    /// @notice Domain-separated scope prevents proof reuse across elections,
    /// contracts, and chains.
    function electionScope() public view returns (bytes32) {
        return keccak256(
            abi.encode(block.chainid, address(this), electionId, manifestHash)
        );
    }

    function votingOpen() public view returns (bool) {
        return block.timestamp >= votingStartsAt && block.timestamp < votingEndsAt;
    }

    /// @param nullifier Election-scoped public double-vote prevention value.
    /// @param ciphertext Encrypted ballot bytes; never a plaintext candidate ID.
    /// @param eligibilityProof Anonymous membership proof bound to ballotHash.
    /// @param ballotProof Proof the ciphertext encodes one allowed selection.
    function castEncryptedBallot(
        bytes32 nullifier,
        bytes calldata ciphertext,
        bytes calldata eligibilityProof,
        bytes calldata ballotProof
    ) external {
        if (!votingOpen() || tallyFinalized) revert VotingNotOpen();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed();
        // Effects before external verifier calls; a failed proof reverts this write.
        nullifierUsed[nullifier] = true;

        bytes32 ballotHash = keccak256(ciphertext);
        if (
            !proofVerifier.verifyEligibility(
                eligibilityProof,
                voterGroupRoot,
                electionScope(),
                nullifier,
                ballotHash
            )
        ) revert InvalidEligibilityProof();

        if (
            !proofVerifier.verifyEncryptedBallot(
                ballotProof,
                ciphertext,
                manifestHash,
                electionPublicKeyHash
            )
        ) revert InvalidEncryptedBallot();

        acceptedBallotsHash = keccak256(
            abi.encode(acceptedBallotsHash, nullifier, ballotHash)
        );

        // Publish ciphertext bytes so independent tally operators can retrieve
        // the encrypted ballots. Benchmark event data costs before deployment.
        emit EncryptedBallotAccepted(electionId, nullifier, ballotHash, ciphertext);
    }

    /// @notice Anyone may publish a tally after close if its public proof checks.
    function publishTally(bytes32 resultHash_, bytes calldata tallyProof) external {
        if (block.timestamp < votingEndsAt) revert VotingStillOpen();
        if (tallyFinalized) revert TallyAlreadyFinalized();
        // A rejected proof reverts this state change atomically.
        tallyFinalized = true;
        if (
            resultHash_ == bytes32(0) ||
            !tallyVerifier.verifyTally(
                acceptedBallotsHash,
                resultHash_,
                manifestHash,
                tallyProof
            )
        ) revert InvalidTallyProof();

        resultHash = resultHash_;
        emit TallyPublished(electionId, resultHash_);
    }
}
