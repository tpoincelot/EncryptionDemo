// High-level skeleton using WebCrypto APIs
// Functions: generateKeyPair(), exportPublicKey(), importPeerKey(), deriveSharedSecret(),
// hkdfExpand(), encryptAesCbc(), decryptAesCbc(), hmac()

async function generateKeyPair() {
  // ECDH with P-256 (supported broadly). Alternatively use X25519 if available.
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  return keyPair;
}

async function exportPublicKey(key) {
  const spki = await window.crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(spki);
}

async function importPublicKey(rawBase64) {
  const raw = base64ToArrayBuffer(rawBase64);
  return await window.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

async function deriveSharedSecret(privateKey, peerPublicKey) {
  const bits = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256
  );
  return bits; // ArrayBuffer
}

async function hkdfExpand(rawSecret, info = new Uint8Array([]), length = 32) {
  // Derive AES and HMAC keys using HKDF with SHA-256
  const salt = new Uint8Array(32); // zeros OK if ephemeral secret
  const key = await window.crypto.subtle.importKey("raw", rawSecret, "HKDF", false, ["deriveKey"]);
  const derived = await window.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    key,
    { name: "AES-CBC", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  // For HMAC key derive separately
  const hmacKey = await window.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new Uint8Array([1]) },
    key,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"]
  );
  return { aesKey: derived, hmacKey };
}

async function encryptAesCbc(aesKey, hmacKey, plaintext) {
  const iv = window.crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder().encode(plaintext);
  const ct = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, enc);
  // compute HMAC over iv + ciphertext (encrypt-then-MAC)
  const ivCt = concatBuffers(iv.buffer, ct);
  const mac = await window.crypto.subtle.sign("HMAC", hmacKey, ivCt);
  return { ciphertext: arrayBufferToBase64(ct), iv: arrayBufferToBase64(iv.buffer), hmac: arrayBufferToBase64(mac) };
}

async function decryptAesCbc(aesKey, hmacKey, iv_b64, ct_b64, hmac_b64) {
  const iv = base64ToArrayBuffer(iv_b64);
  const ct = base64ToArrayBuffer(ct_b64);
  const mac = base64ToArrayBuffer(hmac_b64);
  // verify HMAC
  const ivCt = concatBuffers(iv, ct);
  const valid = await window.crypto.subtle.verify("HMAC", hmacKey, mac, ivCt);
  if (!valid) throw new Error("HMAC verification failed");
  const pt = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(iv) }, aesKey, ct);
  return new TextDecoder().decode(pt);
}

// Utility helpers: arrayBufferToBase64, base64ToArrayBuffer, concatBuffers
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function concatBuffers(a,b) {
  const aa = new Uint8Array(a), bb = new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out.buffer;
}

// Demo integration
async function cryptoDemoInit(username) {
  // create UI hooks and implement simple exchange via server APIs
  // This file should be expanded with fetch calls to /api/public_key and /api/messages
  // See server endpoints in app.py
  console.log("Init crypto demo for", username);
}