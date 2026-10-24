import { createHash } from "node:crypto";
import {
  Contract,
  JsonRpcProvider,
  Wallet,
  getAddress,
  toBeHex,
  toUtf8Bytes
} from "ethers";
import { canonicalEncryptedBallotJson } from "../lib/crypto/proofs.ts";

const ABI = [
  "function electionId() view returns (bytes32)",
  "function manifestHash() view returns (bytes32)",
  "function electionPublicKey() view returns (bytes32)",
  "function semaphoreGroupRoot() view returns (bytes32)",
  "function semaphoreScope() view returns (uint256)",
  "function verificationAuthority() view returns (address)",
  "function ballotHashByNullifier(bytes32) view returns (bytes32)",
  "function relayVerifiedBallot(bytes32 nullifier, bytes encryptedBallot, bytes attestationSignature)"
];

const TYPES = {
  VerifiedBallot: [
    { name: "electionId", type: "bytes32" },
    { name: "manifestHash", type: "bytes32" },
    { name: "semaphoreGroupRoot", type: "bytes32" },
    { name: "semaphoreScope", type: "uint256" },
    { name: "nullifier", type: "bytes32" },
    { name: "ballotHash", type: "bytes32" }
  ]
};

function bytes32FromUuid(value) {
  const hex = String(value).replaceAll("-", "").toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(hex)) throw new TypeError("Invalid election UUID for EVM relay.");
  return `0x${hex.padStart(64, "0")}`;
}

function nullifierBytes32(value) {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,76}$/.test(value)) throw new TypeError("Invalid Semaphore nullifier.");
  return toBeHex(BigInt(value), 32);
}

function assertConfiguration() {
  const rpcUrl = process.env.EVM_RPC_URL;
  const contractAddress = process.env.ELECTION_CONTRACT_ADDRESS;
  const privateKey = process.env.RELAYER_PRIVATE_KEY;
  if (!rpcUrl || !contractAddress || !privateKey) throw new Error("The EVM relay is not configured.");
  return { rpcUrl, contractAddress: getAddress(contractAddress), privateKey };
}

export async function relayVerifiedBallot({ election, ballot, nullifier }) {
  const { rpcUrl, contractAddress, privateKey } = assertConfiguration();
  const encryptedBallot = toUtf8Bytes(canonicalEncryptedBallotJson(ballot));
  const ballotHash = createHash("sha256").update(encryptedBallot).digest("hex");
  if (ballotHash !== ballot.ballotHash) throw new Error("Canonical ballot bytes do not match the client ballot hash.");

  const provider = new JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(privateKey, provider);
  const contract = new Contract(contractAddress, ABI, wallet);
  const network = await provider.getNetwork();
  const electionId = bytes32FromUuid(election.id);
  const manifestHash = `0x${election.manifestHash}`;
  const publicKey = `0x${election.electionPublicKey}`;
  if (!election.semaphoreGroupRoot) throw new Error("The Semaphore group must be frozen before contract relay.");
  const groupRoot = toBeHex(BigInt(election.semaphoreGroupRoot), 32);
  const scope = BigInt(`0x${election.id.replaceAll("-", "")}`);
  const nullifierHex = nullifierBytes32(nullifier);

  const [onChainElectionId, onChainManifestHash, onChainKey, onChainRoot, onChainScope, authority] = await Promise.all([
    contract.electionId(), contract.manifestHash(), contract.electionPublicKey(),
    contract.semaphoreGroupRoot(), contract.semaphoreScope(), contract.verificationAuthority()
  ]);
  if (onChainElectionId.toLowerCase() !== electionId.toLowerCase() ||
      onChainManifestHash.toLowerCase() !== manifestHash.toLowerCase() ||
      onChainKey.toLowerCase() !== publicKey.toLowerCase() ||
      onChainRoot.toLowerCase() !== groupRoot.toLowerCase() || BigInt(onChainScope) !== scope ||
      getAddress(authority) !== wallet.address) {
    throw new Error("The deployed election contract does not match the published election configuration.");
  }

  const existingHash = await contract.ballotHashByNullifier(nullifierHex);
  if (existingHash !== `0x${"00".repeat(32)}`) {
    if (existingHash.toLowerCase() !== `0x${ballotHash}`.toLowerCase()) {
      throw new Error("This nullifier is already committed to another ballot on chain.");
    }
    return { transactionHash: null, alreadyRelayed: true, ballotHash };
  }

  const signature = await wallet.signTypedData(
    { name: "SecureElection", version: "2", chainId: network.chainId, verifyingContract: contractAddress },
    TYPES,
    { electionId, manifestHash, semaphoreGroupRoot: groupRoot, semaphoreScope: scope,
      nullifier: nullifierHex, ballotHash: `0x${ballotHash}` }
  );
  const transaction = await contract.relayVerifiedBallot(nullifierHex, encryptedBallot, signature);
  const receipt = await transaction.wait();
  if (!receipt || receipt.status !== 1) throw new Error("The election contract did not confirm the ballot relay.");
  return { transactionHash: transaction.hash, alreadyRelayed: false, ballotHash };
}
