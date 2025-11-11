import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;

describe("EncryptedMessenger", function () {
  it("deploy + sendMessage emituje event i cuva metapodatke", async function () {
    const [sender, receiver] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("EncryptedMessenger");
    const contract = await Factory.deploy();
    await contract.deployed(); 

    // pripremi parametre
    const contentHash = "0x" + "11".repeat(32);
    const cid = "local:deadbeef";
    const keyCipher = ethers.utils.formatBytes32String("rsa-wrapped-aes"); 

    // dataHash = keccak256(abi.encodePacked(from, to, contentHash, keccak256(bytes(cid))))
    const dataHash = ethers.utils.keccak256(
      ethers.utils.solidityPack(
        ["address", "address", "bytes32", "bytes32"],
        [
          sender.address,
          receiver.address,
          contentHash,
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)),
        ]
      )
    );

    const signature = await sender.signMessage(ethers.utils.arrayify(dataHash)); // ✅ arrayify u v5

    await expect(
      contract
        .connect(sender)
        .sendMessage(receiver.address, contentHash, cid, keyCipher, signature)
    ).to.emit(contract, "MessageSent");

    const ids = await contract.getSentIds(sender.address);
    expect(ids.length).to.equal(1);

    const m = await contract.getMessage(ids[0]);
    expect(m.sender).to.equal(sender.address);
    expect(m.recipient).to.equal(receiver.address);
    expect(m.contentHash).to.equal(contentHash);

    const ok = await contract.verifySignature(ids[0]);
    expect(ok).to.equal(true);
  });

  it("anti-spam: drugi poziv odmah treba da revertuje", async function () {
    const [sender, receiver] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("EncryptedMessenger");
    const contract = await Factory.deploy();
    await contract.deployed();

    const h = "0x" + "22".repeat(32);
    const cid = "local:cid";
    const key = ethers.utils.toUtf8Bytes("k");

    const dataHash = ethers.utils.keccak256(
      ethers.utils.solidityPack(
        ["address", "address", "bytes32", "bytes32"],
        [
          sender.address,
          receiver.address,
          h,
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)),
        ]
      )
    );
    const sig = await sender.signMessage(ethers.utils.arrayify(dataHash));

    await contract.connect(sender).sendMessage(receiver.address, h, cid, key, sig);

    await expect(
      contract.connect(sender).sendMessage(receiver.address, h, cid, key, sig)
    ).to.be.revertedWith("Too frequent");
  });

  it("odbacuje poruku sa nevalidnim potpisom", async function () {
    const [sender, receiver, attacker] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EncryptedMessenger");
    const contract = await Factory.deploy();
    await contract.deployed();

    const contentHash = "0x" + "33".repeat(32);
    const cid = "local:invalid";
    const key = ethers.utils.toUtf8Bytes("k");

    const fakeHash = ethers.utils.keccak256(
      ethers.utils.solidityPack(
        ["address", "address", "bytes32", "bytes32"],
        [
          sender.address,
          receiver.address,
          contentHash,
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)),
        ]
      )
    );
    const fakeSig = await attacker.signMessage(ethers.utils.arrayify(fakeHash));

    await expect(
      contract.connect(sender).sendMessage(receiver.address, contentHash, cid, key, fakeSig)
    ).to.be.revertedWith("Invalid signature");
  });

  it("zabranjuje čitanje poruke neautorizovanom nalogu", async function () {
    const [sender, receiver, outsider] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EncryptedMessenger");
    const contract = await Factory.deploy();
    await contract.deployed();

    const h = "0x" + "44".repeat(32);
    const cid = "local:cid";
    const key = ethers.utils.toUtf8Bytes("k");

    const dataHash = ethers.utils.keccak256(
      ethers.utils.solidityPack(
        ["address", "address", "bytes32", "bytes32"],
        [
          sender.address,
          receiver.address,
          h,
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)),
        ]
      )
    );
    const sig = await sender.signMessage(ethers.utils.arrayify(dataHash));

    await contract.connect(sender).sendMessage(receiver.address, h, cid, key, sig);
    const ids = await contract.getSentIds(sender.address);

    await expect(contract.connect(outsider).getMessage(ids[0])).to.be.revertedWith(
      "Access denied"
    );
  });

  it("verifikuje integritet poruke (hash odgovara sadržaju)", async function () {
    const [sender, receiver] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EncryptedMessenger");
    const contract = await Factory.deploy();
    await contract.deployed();

    const contentHash = "0x" + "55".repeat(32);
    const cid = "local:test";
    const key = ethers.utils.toUtf8Bytes("keydata");

    const dataHash = ethers.utils.keccak256(
      ethers.utils.solidityPack(
        ["address", "address", "bytes32", "bytes32"],
        [
          sender.address,
          receiver.address,
          contentHash,
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)),
        ]
      )
    );
    const sig = await sender.signMessage(ethers.utils.arrayify(dataHash));

    await contract.connect(sender).sendMessage(receiver.address, contentHash, cid, key, sig);
    const ids = await contract.getSentIds(sender.address);
    const m = await contract.getMessage(ids[0]);

    expect(m.contentHash).to.equal(contentHash);
    const cidHash = await contract.computeCidHash(m.cid);
    expect(cidHash).to.equal(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(cid)));

    const ok = await contract.verifySignature(ids[0]);
    expect(ok).to.equal(true);
  });
});
