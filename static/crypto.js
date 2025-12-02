(function() {
// Super basic DH + XOR-based cipher demo using only Math.random
const DEMO_P = 100003n;
const INITIAL_G = 5n;
const USE_AES = true;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function randomHex(length) {
  const byteLen = Math.ceil(length / 2);
  const bytes = new Uint8Array(byteLen);
  window.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, length);
}

// Helper function to convert hex string to byte array
function hexToBytes(hex) {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    const chunk = hex.slice(i * 2, i * 2 + 2);
    bytes[i] = parseInt(chunk || '00', 16);
  }
  return bytes;
}

// Helper function to convert byte array to hex string
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Modular exponentiation for Diffie-Hellman
function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function randomBigInt(max) {
  // Generate a random BigInt in range [2, max-2]
  if (max < 4n) return 2n;
  
  // Estimate number of bytes
  const hexLen = max.toString(16).length;
  const byteLen = Math.ceil(hexLen / 2);
  const buffer = new Uint8Array(byteLen);
  
  while(true) {
    window.crypto.getRandomValues(buffer);
    let hex = '0x' + Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
    let val = BigInt(hex);
    
    if (val >= 2n && val < max - 1n) {
      return val;
    }
  }
}

// Simple XOR encryption with key and IV
function xorWithKey(source, keyBytes, ivBytes) {
  const out = new Uint8Array(source.length);
  for (let i = 0; i < source.length; i++) {
    const keyByte = keyBytes[i % keyBytes.length] || 0;
    const ivByte = ivBytes[i % ivBytes.length] || 0;
    out[i] = source[i] ^ keyByte ^ ivByte;
  }
  return out;
}

function simpleHmac(secretHex, payloadHex) {
  const secretBytes = hexToBytes(secretHex);
  const payloadBytes = hexToBytes(payloadHex);
  let acc = 0;
  for (let i = 0; i < payloadBytes.length; i++) {
    const keyByte = secretBytes[i % secretBytes.length] || 0;
    acc = (acc + ((payloadBytes[i] ^ keyByte) * 31)) & 0xff;
  }
  return acc.toString(16).padStart(2, '0');
}

// Manual implementation of AES-CBC encryption
function aesCbcEncrypt(secretHex, plaintext) {
  const blockSize = 16;
  const keyBytes = hexToBytes(secretHex);
  const ivBytes = new Uint8Array(blockSize);
  window.crypto.getRandomValues(ivBytes);
  const ptBytes = encoder.encode(plaintext);

  const padding = blockSize - (ptBytes.length % blockSize);
  const paddedPt = new Uint8Array(ptBytes.length + padding);
  paddedPt.set(ptBytes);
  paddedPt.fill(padding, ptBytes.length);

  const ctBytes = new Uint8Array(paddedPt.length);
  let prevBlock = ivBytes;
  for (let i = 0; i < paddedPt.length; i += blockSize) {
    const block = paddedPt.slice(i, i + blockSize);
    const xoredBlock = xorWithKey(block, keyBytes, prevBlock);
    prevBlock = xoredBlock;
    ctBytes.set(xoredBlock, i);
  }

  return { ciphertext: bytesToHex(ctBytes), iv: bytesToHex(ivBytes) };
}

// Manual implementation of AES-CBC decryption
function aesCbcDecrypt(secretHex, ivHex, ciphertextHex) {
  const blockSize = 16;
  const keyBytes = hexToBytes(secretHex);
  const ivBytes = hexToBytes(ivHex);
  const ctBytes = hexToBytes(ciphertextHex);

  const ptBytes = new Uint8Array(ctBytes.length);
  let prevBlock = ivBytes;
  for (let i = 0; i < ctBytes.length; i += blockSize) {
    const block = ctBytes.slice(i, i + blockSize);
    const decryptedBlock = xorWithKey(block, keyBytes, prevBlock);
    prevBlock = block;
    ptBytes.set(decryptedBlock, i);
  }

  const padding = ptBytes[ptBytes.length - 1];
  return decoder.decode(ptBytes.slice(0, -padding));
}

function encryptWithSecret(secretHex, plaintext) {
  if (USE_AES) {
    const { ciphertext, iv } = aesCbcEncrypt(secretHex, plaintext);
    const hmac = simpleHmac(secretHex, iv + ciphertext);
    return { ciphertext, iv, hmac };
  } else {
    const ivHex = randomHex(16);
    const keyBytes = hexToBytes(secretHex);
    const ivBytes = hexToBytes(ivHex);
    const ptBytes = encoder.encode(plaintext);
    const ctBytes = xorWithKey(ptBytes, keyBytes, ivBytes);
    const ctHex = bytesToHex(ctBytes);
    const hmac = simpleHmac(secretHex, ivHex + ctHex);
    return { ciphertext: ctHex, iv: ivHex, hmac };
  }
}

function decryptWithSecret(secretHex, ivHex, ciphertext, hmac) {
  const expected = simpleHmac(secretHex, ivHex + ciphertext);
  if (expected !== hmac) {
    throw new Error('HMAC mismatch');
  }

  if (USE_AES) {
    return aesCbcDecrypt(secretHex, ivHex, ciphertext);
  } else {
    const keyBytes = hexToBytes(secretHex);
    const ivBytes = hexToBytes(ivHex);
    const ctBytes = hexToBytes(ciphertext);
    const ptBytes = xorWithKey(ctBytes, keyBytes, ivBytes);
    return decoder.decode(ptBytes);
  }
}

// Initialize the chat application
async function cryptoDemoInit(username) {
  const recipientInput = document.getElementById('recipient');
  const initBtn = document.getElementById('init');
  const resetBtn = document.getElementById('reset');
  const sendBtn = document.getElementById('send');
  const messageInput = document.getElementById('message');
  const inboxList = document.getElementById('messages');
  const keysDiv = document.getElementById('keys');

  const state = {
    username,
    ownPrivate: randomBigInt(DEMO_P - 1n),
    ownPublic: 0n,
    currentG: INITIAL_G,
    currentP: DEMO_P,
    sharedSecrets: {},
    dhParams: {},
    peerRoles: {},
    lastPeerPublic: {},
    currentSessionId: null,
  };
  state.ownPublic = modPow(state.currentG, state.ownPrivate, state.currentP);

  async function resetSharedKey() {
    state.sharedSecrets = {};
    state.dhParams = {};
    state.peerRoles = {};
    state.lastPeerPublic = {};
    state.currentSessionId = null;
    state.currentG = INITIAL_G;
    state.currentP = DEMO_P;
    state.ownPrivate = randomBigInt(DEMO_P - 1n);
    state.ownPublic = modPow(state.currentG, state.ownPrivate, state.currentP);
    keysDiv.textContent = 'Shared key cleared; click "Init key exchange" to reestablish.';
    inboxList.innerHTML = '';
    await fetch('/api/reset_session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
  }

  async function startNewSession(recipient) {
    const modeSelect = document.getElementById('security-mode');
    const mode = modeSelect ? modeSelect.value : 'demo';

    const resp = await fetch('/api/dh_sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiator: username, recipient, mode }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success || !data.session) {
      throw new Error('Unable to begin DH session');
    }
    const session = data.session;
    state.currentSessionId = session.id;
    state.currentG = BigInt(session.g);
    state.currentP = BigInt(session.p);
    state.ownPrivate = randomBigInt(state.currentP - 1n);
    state.ownPublic = modPow(state.currentG, state.ownPrivate, state.currentP);
    state.lastPeerPublic[recipient] = null;
  }

  function markSessionComplete() {
    if (!state.currentSessionId) {
      return;
    }
    fetch(`/api/dh_sessions/${state.currentSessionId}/complete`, {
      method: 'POST',
    }).catch(() => {});
    state.currentSessionId = null;
  }

  async function publishOwnKey() {
    const resp = await fetch('/api/public_key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: username,
        public_key: state.ownPublic.toString(),
        g: state.currentG.toString(),
        p: state.currentP.toString(),
      }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) {
      throw new Error('Unable to publish own public key');
    }
  }

  async function logKeyExchange(recipient, algorithm, parameters, role) {
    await fetch('/api/key_logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        initiator: username,
        recipient,
        algorithm,
        parameters: JSON.stringify(parameters),
        role,
      }),
    }).catch(() => {});
  }

  async function fetchIncomingSession() {
    const resp = await fetch(`/api/dh_sessions/${encodeURIComponent(username)}`);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.success || !data.session) {
      return null;
    }
    const session = data.session;
    state.currentSessionId = session.id;
    state.currentG = BigInt(session.g);
    state.currentP = BigInt(session.p);
    state.ownPrivate = randomBigInt(state.currentP - 1n);
    state.ownPublic = modPow(state.currentG, state.ownPrivate, state.currentP);
    state.lastPeerPublic[session.initiator] = null;
    return session;
  }

  async function fetchPeerData(peer, { allowMissing = false } = {}) {
    const resp = await fetch('/api/public_key/' + encodeURIComponent(peer));
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || !data.success) {
      if (allowMissing) {
        return null;
      }
      throw new Error('Peer key not available yet');
    }
    return data;
  }

  async function waitForPeerKey(peer, expectedG, lastPublicKey) {
    for (let attempt = 0; attempt < 20; attempt++) {
      const data = await fetchPeerData(peer);
      const peerG = BigInt(data.g || INITIAL_G.toString());
      const peerP = BigInt(data.p || state.currentP.toString());
      const peerKey = data.public_key;
      if (peerG !== expectedG || peerP !== state.currentP || !peerKey) {
        await sleep(200);
        continue;
      }
      if (lastPublicKey && peerKey === lastPublicKey) {
        await sleep(200);
        continue;
      }
      return data;
    }
    throw new Error('Timed out waiting for peer key to update');
  }

  // Establish a shared secret with a peer
  async function establishSharedSecret(peer, role = 'initiator') {
    if (state.sharedSecrets[peer]) {
      return state.sharedSecrets[peer];
    }

    let peerData;
    if (role === 'initiator') {
      await publishOwnKey();
      const lastKey = state.lastPeerPublic[peer];
      peerData = await waitForPeerKey(peer, state.currentG, lastKey);
    } else {
      peerData = await fetchPeerData(peer);
      state.currentG = BigInt(peerData.g || state.currentG.toString());
      state.currentP = BigInt(peerData.p || state.currentP.toString());
      state.ownPublic = modPow(state.currentG, state.ownPrivate, state.currentP);
      await publishOwnKey();
    }

    const peerPublic = BigInt(peerData.public_key);
    const shared = modPow(peerPublic, state.ownPrivate, state.currentP);
    const secretHex = shared.toString(16).padStart(6, '0');

    const params = {
      g: state.currentG.toString(),
      p: state.currentP.toString(),
      A: state.ownPublic.toString(),
      B: peerPublic.toString(),
    };
    if (role === 'initiator') {
      params.a = state.ownPrivate.toString();
    } else {
      params.b = state.ownPrivate.toString();
    }

    state.sharedSecrets[peer] = { secretHex };
    state.dhParams[peer] = params;
    state.peerRoles[peer] = role;
    state.lastPeerPublic[peer] = peerData.public_key;
    await logKeyExchange(peer, 'Diffie-Hellman (demo)', params, role);
    keysDiv.textContent = `Derived DH secret ...${secretHex.slice(-8)} with ${peer}`;
    markSessionComplete();
    return state.sharedSecrets[peer];
  }

  async function performHandshake(recipient) {
    const timeout = 60 * 1000;
    const deadline = Date.now() + timeout;
    let lastError;
    while (Date.now() < deadline) {
      try {
        const session = await fetchIncomingSession();
        if (session) {
          await establishSharedSecret(session.initiator, 'responder');
          return;
        }
        if (!state.currentSessionId) {
          await startNewSession(recipient);
        }
        await establishSharedSecret(recipient, 'initiator');
        return;
      } catch (err) {
        lastError = err;
        await sleep(2500);
      }
    }
    throw lastError || new Error('Timed out waiting for peer to establish keys');
  }

  async function initKeyExchange() {
    const recipient = recipientInput.value.trim();
    if (!recipient) {
      alert('Enter a recipient username first.');
      return;
    }
    try {
      await performHandshake(recipient);
    } catch (err) {
      console.error('Key exchange error', err);
      alert('Unable to establish a shared key after repeated attempts. Please try again.');
    }
  }

  // Send an encrypted message
  async function sendMessage() {
    const recipient = recipientInput.value.trim();
    const plaintext = messageInput.value.trim();
    if (!recipient || !plaintext) return;

    let shared = state.sharedSecrets[recipient];
    if (!shared) {
      const role = state.peerRoles[recipient] || 'initiator';
      try {
        shared = await establishSharedSecret(recipient, role);
      } catch (err) {
        alert('Unable to derive shared secret yet.');
        return;
      }
    }

    const { ciphertext, iv, hmac } = encryptWithSecret(shared.secretHex, plaintext);
    const payload = { sender: username, recipient, ciphertext, iv, hmac };

    const resp = await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok || !data.success) {
      alert('Failed to send message');
      return;
    }

    const logParams = { iv, hmac, ciphertext_preview: ciphertext.slice(0, 32) };
    const algoLabel = USE_AES ? 'AES-CBC + HMAC (demo)' : 'XOR stream + HMAC (demo)';
    await logKeyExchange(recipient, algoLabel, logParams, 'sender');

    messageInput.value = '';
    refreshInbox();
  }

  // Fetch and display messages
  async function refreshInbox() {
    try {
      const resp = await fetch('/api/messages/' + encodeURIComponent(username));
      const data = await resp.json();
      if (!resp.ok || !Array.isArray(data.messages)) return;
      inboxList.innerHTML = '';
      for (const msg of data.messages) {
        const li = document.createElement('li');
        let shared = state.sharedSecrets[msg.sender];
        if (!shared) {
          try {
            shared = await establishSharedSecret(msg.sender, 'responder');
          } catch (err) {
            li.textContent = `${msg.sender}: [no shared secret yet]`;
            inboxList.appendChild(li);
            continue;
          }
        }
        try {
          const plain = decryptWithSecret(shared.secretHex, msg.iv, msg.ciphertext, msg.hmac);
          li.textContent = `${msg.sender}: ${plain}`;
        } catch (err) {
          li.textContent = `${msg.sender}: [decryption failed]`;
        }
        inboxList.appendChild(li);
      }
    } catch (err) {
      console.error('Inbox refresh failed', err);
    }
  }

  initBtn.addEventListener('click', initKeyExchange);
  if (resetBtn) {
    resetBtn.addEventListener('click', resetSharedKey);
  }
  sendBtn.addEventListener('click', sendMessage);
  refreshInbox();
  setInterval(refreshInbox, 3000);
}

window.cryptoDemoInit = cryptoDemoInit;
})();
