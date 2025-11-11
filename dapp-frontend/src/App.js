import React, { useEffect, useState } from "react";
import { ethers } from "ethers";

const CONTRACT_ADDRESS = "0x82ef29d7d88aE211a35aD3Bf359Ec057BC18ace9";

const CONTRACT_ABI = [
  {
    inputs: [
      { internalType: "bytes32", name: "pubKeyHash", type: "bytes32" },
      { internalType: "string", name: "pubKeyUri", type: "string" },
    ],
    name: "registerPublicKey",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { internalType: "address", name: "to", type: "address" },
      { internalType: "bytes32", name: "contentHash", type: "bytes32" },
      { internalType: "string", name: "cid", type: "string" },
      { internalType: "bytes", name: "keyCiphertext", type: "bytes" },
      { internalType: "bytes", name: "signature", type: "bytes" },
    ],
    name: "sendMessage",
    outputs: [{ internalType: "uint256", name: "id", type: "uint256" }],
    stateMutability: "nonpayable",
    type: "function",
  },
];

// storage kljucevi po nalogu
const msgKey = (addr) => `messages_${addr?.toLowerCase() || "unknown"}`;
const pubKeyName = (addr) => `rsa_pub_${addr?.toLowerCase() || "unknown"}`;
const privKeyName = (addr) => `rsa_priv_${addr?.toLowerCase() || "unknown"}`;

function ab2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b642ab(b64) {
  if (!b64 || typeof b64 !== "string") {
    throw new Error("b642ab: nevalidan Base64 string (undefined ili nije string)");
  }
  b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function b64ToHex(b64) {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  let hex = "";
  for (let i = 0; i < bin.length; i++) {
    hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return hex;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/* SHA-256 hes (za contentHash) */
async function sha256HexFromArrayBuffer(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return (
    "0x" +
    Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

async function encryptAES(plainText) {
  const aesKeyRaw = crypto.getRandomValues(new Uint8Array(32)); // 256-bit ključ
  const key = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plainText));

  return {
    aesKeyRaw: aesKeyRaw.buffer,
    ivB64: ab2b64(iv.buffer),
    ciphertextB64: ab2b64(cipherBuf),
  };
}

async function decryptAES(aesKeyRawBuf, ivB64, ciphertextB64) {
  const key = await crypto.subtle.importKey("raw", aesKeyRawBuf, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  const iv = new Uint8Array(b642ab(ivB64));
  const cipher = b642ab(ciphertextB64);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return dec.decode(plainBuf);
}

async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  return { pubJwk, privJwk };
}

async function importRSAPublic(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

async function importRSAPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

// RSA encrypt/decrypt (za AES ključ)
async function encryptRSA(pubJwk, dataArrayBuffer) {
  const pub = await importRSAPublic(pubJwk);
  const out = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, dataArrayBuffer);
  return ab2b64(out);
}
async function decryptRSA(privJwk, b64Cipher) {
  const priv = await importRSAPrivate(privJwk);
  const out = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b642ab(b64Cipher));
  return out;
}

/* REACT APP */
export default function App() {
  const [account, setAccount] = useState(null);
  const [status, setStatus] = useState("Niste povezani sa MetaMask nalogom.");
  const [to, setTo] = useState("");
  const [msg, setMsg] = useState("");

  const [haveRSA, setHaveRSA] = useState(false);
  const [pubJwk, setPubJwk] = useState(null);

  const [sentMessages, setSentMessages] = useState([]);
  const [receivedMessages, setReceivedMessages] = useState([]);
  const [showMessages, setShowMessages] = useState(false);

  // ucitaj poruke kad se promeni nalog
  useEffect(() => {
    if (!account) {
      setSentMessages([]);
      setReceivedMessages([]);
      setHaveRSA(false);
      setPubJwk(null);
      return;
    }

    const pubStr = localStorage.getItem(pubKeyName(account));
    const privStr = localStorage.getItem(privKeyName(account));
    setHaveRSA(!!(pubStr && privStr));
    setPubJwk(pubStr ? JSON.parse(pubStr) : null);

    const all = JSON.parse(localStorage.getItem(msgKey(account)) || "[]");
    const sent = all.filter((m) => (m.from || "").toLowerCase() === account.toLowerCase());
    const recv = all.filter((m) => (m.to || "").toLowerCase() === account.toLowerCase());
    setSentMessages(sent);
    setReceivedMessages(recv);
  }, [account]);

  /* Wallet */
  async function connectWallet() {
    if (!window.ethereum) return alert("Instaliraj MetaMask!");
    const provider = new ethers.BrowserProvider(window.ethereum);
    const signer = await provider.getSigner();
    const addr = await signer.getAddress();
    setAccount(addr);
    setStatus("Povezan nalog: " + addr);
  }

  /* RSA generisanje */
  async function generateAndPublishRSA() {
    if (!account) return alert("Poveži MetaMask!");
    setStatus("Generišem RSA ključeve...");

    const { pubJwk, privJwk } = await generateRSAKeyPair();
    localStorage.setItem(pubKeyName(account), JSON.stringify(pubJwk));
    localStorage.setItem(privKeyName(account), JSON.stringify(privJwk));
    setHaveRSA(true);
    setPubJwk(pubJwk);

    const pubStr = JSON.stringify(pubJwk);
    const pubHash = ethers.keccak256(ethers.toUtf8Bytes(pubStr));
    const pubUri = `local:rsa_pub:${account.toLowerCase()}`;

    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.registerPublicKey(pubHash, pubUri);
      await tx.wait();
      setStatus("RSA ključ generisan i registrovan na blockchainu!");
    } catch (e) {
      console.error(e);
      setStatus("Ključ generisan lokalno, ali on-chain registracija nije uspela: " + (e?.message || e));
    }
  }

  /* Slanje poruke */
  async function sendMessage() {
    if (!account || !to || !msg) return alert("Popuni sva polja!");
    if (!ethers.isAddress(to)) return alert("Primaoc nije validna Ethereum adresa.");

    const toPubStr = localStorage.getItem(pubKeyName(to));
    if (!toPubStr) return alert("Primaoc nema RSA ključ. Generiši ga na njegovom nalogu.");

    const toPubJwk = JSON.parse(toPubStr);
    setStatus("Šifrujem i šaljem poruku...");

    try {
      const { aesKeyRaw, ivB64, ciphertextB64 } = await encryptAES(msg);
      const keyCipherB64 = await encryptRSA(toPubJwk, aesKeyRaw);
      const keyCipherBytes = ethers.getBytes("0x" + b64ToHex(keyCipherB64));

      const cipherBuf = b642ab(ciphertextB64);
      const contentHash = await sha256HexFromArrayBuffer(cipherBuf);

      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const sig = await signer.signMessage(ethers.getBytes(contentHash));

      const localId = "local_" + contentHash.slice(2, 10);

      const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
      const tx = await contract.sendMessage(to, contentHash, localId, keyCipherBytes, sig);
      await tx.wait();

      const payload = {
        to,
        from: account,
        timestamp: new Date().toLocaleString(),
        ref: localId,
        hash: contentHash,
        ciphertextB64,
        ivB64,
        keyCipherB64,
      };

      const sKey = msgKey(account);
      const sArr = JSON.parse(localStorage.getItem(sKey) || "[]");
      sArr.push(payload);
      localStorage.setItem(sKey, JSON.stringify(sArr));
      setSentMessages(sArr.filter((m) => (m.from || "").toLowerCase() === account.toLowerCase()));

      const rKey = msgKey(to);
      const rArr = JSON.parse(localStorage.getItem(rKey) || "[]");
      rArr.push(payload);
      localStorage.setItem(rKey, JSON.stringify(rArr));

      setMsg("");
      setStatus("Poruka šifrovana i metapodaci upisani on-chain.");
    } catch (err) {
      console.error(err);
      setStatus("Greška pri slanju: " + (err?.message || err));
    }
  }

  /* Dekripcija */
  async function decryptIncoming(index) {
    try {
      const privStr = localStorage.getItem(privKeyName(account));
      if (!privStr) return alert("Nemate privatni RSA ključ. Generišite ga prvo.");
      const privJwk = JSON.parse(privStr);

      const msgObj = receivedMessages[index];
      if (!msgObj || !msgObj.keyCipherB64) {
        alert("Poruka nema validan RSA ključ (možda je stara).");
        return;
      }

      const aesKeyRawBuf = await decryptRSA(privJwk, msgObj.keyCipherB64);
      const plain = await decryptAES(aesKeyRawBuf, msgObj.ivB64, msgObj.ciphertextB64);

      const clone = [...receivedMessages];
      clone[index] = { ...clone[index], decryptedText: plain };
      setReceivedMessages(clone);
    } catch (e) {
      console.error(e);
      alert("Dekripcija nije uspela: " + (e?.message || e));
    }
  }

  /* ---------- UI ---------- */
  return (
    <div style={{ fontFamily: "Segoe UI, sans-serif", background: "#f8f9fa", minHeight: "100vh", padding: 30 }}>
      <div
        style={{
          maxWidth: 720,
          margin: "0 auto",
          background: "#fff",
          padding: 24,
          borderRadius: 16,
          boxShadow: "0 0 12px rgba(0,0,0,0.1)",
        }}
      >
        <h1 style={{ textAlign: "center" }}>App Messenger</h1>
        <p style={{ textAlign: "center", color: "#666" }}>{status}</p>

        {!account && (
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <button
              onClick={connectWallet}
              style={{ padding: "10px 18px", borderRadius: 8, cursor: "pointer" }}
            >
              Poveži MetaMask
            </button>
          </div>
        )}

        {account && (
          <>
            <div
              style={{
                display: "flex",
                gap: 12,
                justifyContent: "center",
                marginBottom: 12,
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  padding: "6px 10px",
                  background: "#eef6ff",
                  borderRadius: 8,
                  fontSize: 13,
                }}
              >
                Nalog: <b>{account}</b>
              </span>
              <span
                style={{
                  padding: "6px 10px",
                  background: haveRSA ? "#e9f9ee" : "#fff5e6",
                  borderRadius: 8,
                  fontSize: 13,
                }}
              >
                RSA ključ: <b>{haveRSA ? "spreman" : "nije generisan"}</b>
              </span>
              <button
                onClick={generateAndPublishRSA}
                style={{
                  padding: "8px 12px",
                  borderRadius: 8,
                  background: "#28a745",
                  color: "#fff",
                  border: "none",
                }}
              >
                Generiši & registruj RSA
              </button>
            </div>

            <div style={{ marginBottom: 10 }}>
              <label>Primaoc (adresa):</label>
              <input
                value={to}
                onChange={(e) => setTo(e.target.value)}
                placeholder="Unesi adresu primaoca..."
                style={{
                  width: "100%",
                  padding: 10,
                  borderRadius: 8,
                  border: "1px solid #ccc",
                  marginTop: 5,
                }}
              />
            </div>

            <div style={{ marginBottom: 10 }}>
              <label>Poruka:</label>
              <textarea
                value={msg}
                onChange={(e) => setMsg(e.target.value)}
                placeholder="Unesi tekst poruke..."
                style={{
                  width: "100%",
                  minHeight: 100,
                  padding: 10,
                  borderRadius: 8,
                  border: "1px solid #ccc",
                  marginTop: 5,
                }}
              />
            </div>

            <div style={{ display: "flex", gap: 12, marginBottom: 18 }}>
              <button
                onClick={sendMessage}
                style={{
                  flex: 1,
                  background: "#007bff",
                  color: "#fff",
                  padding: "10px 15px",
                  border: "none",
                  borderRadius: 8,
                  cursor: "pointer",
                }}
              >
                Pošalji (AES+RSA)
              </button>
              <button
                onClick={() => setShowMessages((s) => !s)}
                style={{
                  flex: 1,
                  background: "#6c757d",
                  color: "#fff",
                  padding: "10px 15px",
                  border: "none",
                  borderRadius: 8,
                  cursor: "pointer",
                }}
              >
                {showMessages ? "Sakrij poruke" : "Prikaži poruke"}
              </button>
            </div>
          </>
        )}

        {account && showMessages && (
          <div style={{ marginTop: 14 }}>
            <h3 style={{ borderBottom: "2px solid #eee", paddingBottom: 6 }}>
              Poslate poruke ({sentMessages.length})
            </h3>
            {sentMessages.length === 0 && <p style={{ color: "#666" }}>Nema poslatih poruka.</p>}
            {sentMessages.map((m, i) => (
              <div
                key={`s-${i}`}
                style={{
                  background: "#eaf4ff",
                  borderRadius: 10,
                  padding: "10px 14px",
                  marginBottom: 10,
                }}
              >
                <div>
                  <b>Primaoc:</b> {m.to}
                </div>
                <div>
                  <b>Vreme:</b> {m.timestamp}
                </div>
                <div>
                  <b>Hash (on-chain):</b> {m.hash}
                </div>
                <div>
                  <b>Ref (CID/Local):</b> {m.ref}
                </div>
                <details style={{ marginTop: 6 }}>
                  <summary>Kriptovani sadržaj (off-chain)</summary>
                  <div>
                    <b>IV:</b> {m.ivB64}
                  </div>
                  <div>
                    <b>Ciphertext:</b>{" "}
                    <code style={{ wordBreak: "break-all" }}>{m.ciphertextB64}</code>
                  </div>
                  <div>
                    <b>Key(RSA):</b>{" "}
                    <code style={{ wordBreak: "break-all" }}>{m.keyCipherB64}</code>
                  </div>
                </details>
              </div>
            ))}

            <h3 style={{ borderBottom: "2px solid #eee", paddingBottom: 6, marginTop: 16 }}>
              Primljene poruke ({receivedMessages.length})
            </h3>
            {receivedMessages.length === 0 && <p style={{ color: "#666" }}>Nema primljenih poruka.</p>}
            {receivedMessages.map((m, i) => (
              <div
                key={`r-${i}`}
                style={{
                  background: "#f9f9f9",
                  borderRadius: 10,
                  padding: "10px 14px",
                  marginBottom: 10,
                }}
              >
                <div>
                  <b>Od:</b> {m.from}
                </div>
                <div>
                  <b>Vreme:</b> {m.timestamp}
                </div>
                <div>
                  <b>Hash (on-chain):</b> {m.hash}
                </div>
                <div>
                  <b>Ref (CID/Local):</b> {m.ref}
                </div>

                {m.decryptedText ? (
                  <div
                    style={{
                      marginTop: 8,
                      background: "#e9f9ee",
                      borderRadius: 8,
                      padding: "8px 10px",
                    }}
                  >
                    <b>Tekst:</b> {m.decryptedText}
                  </div>
                ) : (
                  <button
                    onClick={() => decryptIncoming(i)}
                    style={{
                      marginTop: 8,
                      padding: "6px 10px",
                      borderRadius: 8,
                      background: "#198754",
                      color: "#fff",
                      border: "none",
                      cursor: "pointer",
                    }}
                  >
                    Dekriptuj poruku
                  </button>
                )}

                <details style={{ marginTop: 6 }}>
                  <summary>Kriptovani sadržaj (off-chain)</summary>
                  <div>
                    <b>IV:</b> {m.ivB64}
                  </div>
                  <div>
                    <b>Ciphertext:</b>{" "}
                    <code style={{ wordBreak: "break-all" }}>{m.ciphertextB64}</code>
                  </div>
                  <div>
                    <b>Key(RSA):</b>{" "}
                    <code style={{ wordBreak: "break-all" }}>{m.keyCipherB64}</code>
                  </div>
                </details>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
