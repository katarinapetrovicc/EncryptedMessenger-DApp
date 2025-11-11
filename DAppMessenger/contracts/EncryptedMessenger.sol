// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title EncryptedMessenger
/// @notice Čuva isključivo metapodatke poruka: pošiljalac, primalac, vreme, hash sadržaja (SHA-256),
///         referencu na off-chain skladište (CID) i šifrovani simetrični ključ (RSA-OAEP).
///         Autentičnost pošiljaoca se dokazuje digitalnim potpisom metapodataka.
contract EncryptedMessenger {
    using ECDSA for bytes32;

    struct MessageMeta {
        address sender;
        address recipient;
        uint64 timestamp;
        bytes32 contentHash;  // SHA-256(ENCRYPTED_PAYLOAD)
        string cid;           // IPFS CID ili druga referenca na off-chain
        bytes keyCiphertext;  // AES ključ enkriptovan javnim RSA ključem primaoca
        bytes signature;      // potpis pošiljaoca nad dataHash-om (vidi _dataHash)
    }

    struct PubKeyRecord {
        bytes32 pubKeyHash;
        string pubKeyUri;     // IPFS/HTTPS link do public key materijala
    }

    mapping(address => PubKeyRecord) public pubkeys;
    mapping(uint256  => MessageMeta)  private messages;
    mapping(address  => uint256[])    private inboxIds;
    mapping(address  => uint256[])    private sentIds;

    uint256 public nextId = 1;

    // anti-spam 
    uint256 public minIntervalSecs = 30;
    uint256 public maxPerMinute    = 12;

    mapping(address => uint256) public lastSentAt;
    mapping(address => uint256) public sentCountInWindow;
    mapping(address => uint256) public windowStart;

    event PublicKeyRegistered(address indexed user, bytes32 pubKeyHash, string pubKeyUri);
    event MessageSent(
        uint256 indexed id,
        address indexed from,
        address indexed to,
        bytes32 contentHash,
        string cid,
        uint64 timestamp
    );

    //  API 

    function registerPublicKey(bytes32 pubKeyHash, string calldata pubKeyUri) external {
        require(pubKeyHash != bytes32(0), "Bad pubKeyHash");
        pubkeys[msg.sender] = PubKeyRecord(pubKeyHash, pubKeyUri);
        emit PublicKeyRegistered(msg.sender, pubKeyHash, pubKeyUri);
    }

    /// @notice upis metapodataka poruke
    function sendMessage(
        address to,
        bytes32 contentHash,
        string calldata cid,
        bytes calldata keyCiphertext,
        bytes calldata signature
    ) external returns (uint256 id) {
        require(to != address(0) && to != msg.sender, "Invalid recipient");
        require(contentHash != bytes32(0), "Invalid hash");
        require(bytes(cid).length > 0, "Missing CID");
        require(keyCiphertext.length > 0, "Missing key");

        // --- anti-spam ---
        uint256 minuteNow = block.timestamp / 60;
        if (windowStart[msg.sender] != minuteNow) {
            windowStart[msg.sender] = minuteNow;
            sentCountInWindow[msg.sender] = 0;
        }
        require(sentCountInWindow[msg.sender] < maxPerMinute, "Rate limit exceeded");
        require(block.timestamp - lastSentAt[msg.sender] >= minIntervalSecs, "Too frequent");

        //  verifikacija potpisa 
        bytes32 dataHash = _dataHash(msg.sender, to, contentHash, cid);
        bytes32 ethSigned = MessageHashUtils.toEthSignedMessageHash(dataHash);
        address recovered = ECDSA.recover(ethSigned, signature);
        require(recovered == msg.sender, "Invalid signature");

        //  upis 
        id = nextId++;
        messages[id] = MessageMeta({
            sender: msg.sender,
            recipient: to,
            timestamp: uint64(block.timestamp),
            contentHash: contentHash,
            cid: cid,
            keyCiphertext: keyCiphertext,
            signature: signature
        });
        inboxIds[to].push(id);
        sentIds[msg.sender].push(id);

        lastSentAt[msg.sender] = block.timestamp;
        sentCountInWindow[msg.sender] += 1;

        emit MessageSent(id, msg.sender, to, contentHash, cid, uint64(block.timestamp));
    }

    /// @notice čita metapodatke poruke — samo pošiljalac i primalac imaju pristup
    function getMessage(uint256 id) external view returns (MessageMeta memory) {
        MessageMeta memory m = messages[id];
        require(m.sender != address(0), "Not found");
        require(msg.sender == m.sender || msg.sender == m.recipient, "Access denied");
        return m;
    }

    function getInboxIds(address user) external view returns (uint256[] memory) {
        return inboxIds[user];
    }

    function getSentIds(address user) external view returns (uint256[] memory) {
        return sentIds[user];
    }

    /// @notice proverava da li zapisani potpis odgovara posiljaocu
    function verifySignature(uint256 id) external view returns (bool) {
        MessageMeta memory m = messages[id];
        if (m.sender == address(0) || m.signature.length == 0) return false;
        bytes32 dHash = _dataHash(m.sender, m.recipient, m.contentHash, m.cid);
        bytes32 ethSigned = MessageHashUtils.toEthSignedMessageHash(dHash);
        address recovered = ECDSA.recover(ethSigned, m.signature);
        return recovered == m.sender;
    }

    /// @notice izracunava hash CID-a radi integritet testa
    function computeCidHash(string memory cid) public pure returns (bytes32) {
        return keccak256(bytes(cid));
    }

    //  helpers 
    function _dataHash(
        address from,
        address to,
        bytes32 contentHash,
        string memory cid
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(from, to, contentHash, keccak256(bytes(cid))));
    }
}
