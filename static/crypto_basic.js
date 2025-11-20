// Basic demo: classic (modp) Diffie-Hellman (BigInt) + HKDF -> AES-CBC + HMAC-SHA256
// NO external libraries. Uses only WebCrypto for primitives.

const P_HEX = (
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
).toLowerCase();
const G = 2n;
const P = BigInt("0x" + P_HEX);

function bigIntToUint8Array(bn, fixedLength = null) {
  if (bn === 0n) return new Uint8Array([0]);
  let hex = bn.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const len = hex.length / 2;
  const outLen = fixedLength || len;
  const u8 = new Uint8Array(outLen);
  // write into right-aligned to preserve fixed length
  for (let i = 0; i < len; i++) {
    u8[outLen - len + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return u8;
}
function uint8ArrayToBigInt(u8) {
  let hex = "";
  for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
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
function concatArrayBuffers(a, b) {
  const aa = new Uint8Array(a), bb = new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out.buffer;
}

////////////////////////////////////////////////////////////////////////////////
// Fast modular exponentiation: base^exp mod modulus
////////////////////////////////////////////////////////////////////////////////
function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    exponent >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}

////////////////////////////////////////////////////////////////////////////////
// DH keypair generation and simple validation
////////////////////////////////////////////////////////////////////////////////
function randomPrivateKeyBits(bitLength = 256) {
  // produce at least bitLength entropy for the private exponent
  const byteLen = Math.ceil(bitLength / 8);
  const arr = new Uint8Array(byteLen);
  crypto.getRandomValues(arr);
  // ensure positive BigInt
  return uint8ArrayToBigInt(arr);
}

function serializePublic(pubBig) {
  const modByteLen = Math.ceil(P.toString(16).length / 2);
  return arrayBufferToBase64(bigIntToUint8Array(pubBig, modByteLen).buffer);
}

function deserializePublic(pubB64) {
  return uint8ArrayToBigInt(new Uint8Array(base64ToArrayBuffer(pubB64)));
}

function validatePeerPublic(peerPubBig) {
  // Basic checks: 2 <= pub <= p-2
  if (peerPubBig <= 1n) return false;
  if (peerPubBig >= P - 1n) return false;
  return true;
}

async function generateDHKeypair({ privBits = 256 } = {}) {
  const priv = randomPrivateKeyBits(privBits);
  const pub = modPow(G, priv, P);
  const pubB64 = serializePublic(pub);
  // per-handshake salt (16 bytes)
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const saltB64 = arrayBufferToBase64(salt.buffer);
  return { priv, pubB64, saltB64 };
}

////////////////////////////////////////////////////////////////////////////////
// Derive AES and HMAC keys from the shared secret using HKDF (WebCrypto)
////////////////////////////////////////////////////////////////////////////////
async function deriveKeysFromShared(sharedBig, saltB64) {
  // serialize shared to fixed length
  const modByteLen = Math.ceil(P.toString(16).length / 2);
  const sharedU8 = bigIntToUint8Array(sharedBig, modByteLen);

  // import as raw key to use HKDF
  const sharedKey = await crypto.subtle.importKey(
    "raw",
    sharedU8.buffer,
    "HKDF",
    false,
    ["deriveKey", "deriveBits"]
  );

  const salt = base64ToArrayBuffer(saltB64);

  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new Uint8Array([0x01]) },
    sharedKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  const hmacKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new Uint8Array([0x02]) },
    sharedKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"]
  );

  return { aesKey, hmacKey };
}

// High-level function to derive keys given your priv and peer's pubB64 + salt
async function deriveKeysFromPeer(priv, peerPubB64, saltB64) {
  const peerPubBig = deserializePublic(peerPubB64);
  if (!validatePeerPublic(peerPubBig)) throw new Error("Invalid peer public value");
  const shared = modPow(peerPubBig, priv, P);
  return await deriveKeysFromShared(shared, saltB64);
}

////////////////////////////////////////////////////////////////////////////////
// AES-CBC encrypt + HMAC-SHA256 (Encrypt-then-MAC)
////////////////////////////////////////////////////////////////////////////////
async function encryptAndHmac(aesKey, hmacKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder().encode(plaintext);
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, enc);
  const ivCt = concatArrayBuffers(iv.buffer, ct);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, ivCt);
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(ct),
    hmac: arrayBufferToBase64(mac)
  };
}

async function verifyAndDecrypt(aesKey, hmacKey, ivB64, ciphertextB64, hmacB64) {
  const ivBuf = base64ToArrayBuffer(ivB64);
  const ctBuf = base64ToArrayBuffer(ciphertextB64);
  const macBuf = base64ToArrayBuffer(hmacB64);
  const ivCt = concatArrayBuffers(ivBuf, ctBuf);
  const ok = await crypto.subtle.verify("HMAC", hmacKey, macBuf, ivCt);
  if (!ok) throw new Error("HMAC verification failed");
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(ivBuf) }, aesKey, ctBuf);
  return new TextDecoder().decode(ptBuf);
}


// Exported API for demo code to call
window.DHBasic = {
  // keypair generation
  generateDHKeypair,    // -> { priv:BigInt, pubB64, saltB64 }
  deriveKeysFromPeer,   // (priv, peerPubB64, saltB64) -> { aesKey, hmacKey }
  // encrypt/decrypt
  encryptAndHmac,       // (aesKey, hmacKey, plaintext) -> { iv, ciphertext, hmac }
  verifyAndDecrypt,     // (aesKey, hmacKey, ivB64, ciphertextB64, hmacB64) -> plaintext
  _P, _G: { P, G }
};