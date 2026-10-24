// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Tally proof verifier remains an independently supplied, version-pinned contract.
interface ITallyProofVerifier {
    function verifyTally(
        bytes32 acceptedBallotsHash,
        bytes32 resultHash,
        bytes32 manifestHash,
        bytes calldata proof
    ) external view returns (bool);
}

/// @notice Ballot box for one election. Eligibility and Ristretto ballot proofs
/// are verified by the server before an EIP-712 attestation is signed. This
/// contract trusts that attestor and records the encrypted ballot bytes,
/// ballot digest, and Semaphore nullifier on chain.
/// @dev This is an explicit trusted-relayer boundary. It is not a trustless ZK verifier.
contract SecureElection {
    bytes32 public immutable electionId;
    bytes32 public immutable manifestHash;
    bytes32 public immutable electionPublicKey;
    bytes32 public immutable semaphoreGroupRoot;
    uint256 public immutable semaphoreScope;
    uint64 public immutable votingStartsAt;
    uint64 public immutable votingEndsAt;
    address public immutable verificationAuthority;
    ITallyProofVerifier public immutable tallyVerifier;

    bytes32 public acceptedBallotsHash;
    bytes32 public resultHash;
    bool public tallyFinalized;
    mapping(bytes32 nullifier => bytes32 ballotHash) public ballotHashByNullifier;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant BALLOT_TYPEHASH = keccak256(
        "VerifiedBallot(bytes32 electionId,bytes32 manifestHash,bytes32 semaphoreGroupRoot,uint256 semaphoreScope,bytes32 nullifier,bytes32 ballotHash)"
    );
    bytes32 private constant NAME_HASH = keccak256("SecureElection");
    bytes32 private constant VERSION_HASH = keccak256("2");
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    event EncryptedBallotAccepted(
        bytes32 indexed electionId,
        bytes32 indexed nullifier,
        bytes32 indexed ballotHash,
        bytes encryptedBallot,
        bytes attestationSignature
    );
    event TallyPublished(bytes32 indexed electionId, bytes32 resultHash);

    error InvalidConfiguration();
    error VotingNotOpen();
    error VotingStillOpen();
    error NullifierAlreadyUsed();
    error InvalidNullifier();
    error InvalidBallotDigest();
    error InvalidAttestation();
    error TallyAlreadyFinalized();
    error InvalidTallyProof();

    constructor(
        bytes32 electionId_,
        bytes32 manifestHash_,
        bytes32 electionPublicKey_,
        bytes32 semaphoreGroupRoot_,
        uint256 semaphoreScope_,
        uint64 votingStartsAt_,
        uint64 votingEndsAt_,
        address verificationAuthority_,
        address tallyVerifier_
    ) {
        if (
            electionId_ == bytes32(0) ||
            manifestHash_ == bytes32(0) ||
            electionPublicKey_ == bytes32(0) ||
            semaphoreGroupRoot_ == bytes32(0) ||
            semaphoreScope_ == 0 ||
            votingStartsAt_ >= votingEndsAt_ ||
            verificationAuthority_ == address(0) ||
            tallyVerifier_.code.length == 0
        ) revert InvalidConfiguration();

        electionId = electionId_;
        manifestHash = manifestHash_;
        electionPublicKey = electionPublicKey_;
        semaphoreGroupRoot = semaphoreGroupRoot_;
        semaphoreScope = semaphoreScope_;
        votingStartsAt = votingStartsAt_;
        votingEndsAt = votingEndsAt_;
        verificationAuthority = verificationAuthority_;
        tallyVerifier = ITallyProofVerifier(tallyVerifier_);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            NAME_HASH,
            VERSION_HASH,
            block.chainid,
            address(this)
        ));
    }

    function electionScope() external view returns (bytes32) {
        return bytes32(semaphoreScope);
    }

    function votingOpen() public view returns (bool) {
        return block.timestamp >= votingStartsAt && block.timestamp < votingEndsAt;
    }

    /// @notice Relay a ballot only after the verification authority has checked
    /// its Semaphore membership proof and Ristretto one-hot validity proofs.
    /// @param nullifier Semaphore's election-scoped field element, padded to bytes32.
    /// @param encryptedBallot Canonical JSON bytes whose SHA-256 digest is ballotHash.
    /// @param attestationSignature EIP-712 signature from verificationAuthority.
    function relayVerifiedBallot(
        bytes32 nullifier,
        bytes calldata encryptedBallot,
        bytes calldata attestationSignature
    ) external {
        if (!votingOpen() || tallyFinalized) revert VotingNotOpen();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (ballotHashByNullifier[nullifier] != bytes32(0)) revert NullifierAlreadyUsed();

        bytes32 ballotHash = sha256(encryptedBallot);
        if (ballotHash == bytes32(0)) revert InvalidBallotDigest();
        bytes32 structHash = keccak256(abi.encode(
            BALLOT_TYPEHASH,
            electionId,
            manifestHash,
            semaphoreGroupRoot,
            semaphoreScope,
            nullifier,
            ballotHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        if (_recover(digest, attestationSignature) != verificationAuthority) revert InvalidAttestation();

        ballotHashByNullifier[nullifier] = ballotHash;
        acceptedBallotsHash = keccak256(abi.encode(acceptedBallotsHash, nullifier, ballotHash));
        emit EncryptedBallotAccepted(electionId, nullifier, ballotHash, encryptedBallot, attestationSignature);
    }

    function publishTally(bytes32 resultHash_, bytes calldata tallyProof) external {
        if (block.timestamp < votingEndsAt) revert VotingStillOpen();
        if (tallyFinalized) revert TallyAlreadyFinalized();
        tallyFinalized = true;
        if (
            resultHash_ == bytes32(0) ||
            !tallyVerifier.verifyTally(acceptedBallotsHash, resultHash_, manifestHash, tallyProof)
        ) revert InvalidTallyProof();

        resultHash = resultHash_;
        emit TallyPublished(electionId, resultHash_);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        if (signature.length != 65) revert InvalidAttestation();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_N || (v != 27 && v != 28)) revert InvalidAttestation();
        signer = ecrecover(digest, v, r, s);
    }
}
