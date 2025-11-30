
(function() {
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function hexToBytes(hex) {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    const chunk = hex.slice(i * 2, i * 2 + 2);
    bytes[i] = parseInt(chunk || '00', 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// DH Helpers
const DEMO_P = 100003n;
const INITIAL_G = 5n;

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
  const limit = Number(max - 2n) || 1;
  const raw = Math.floor(Math.random() * limit) + 2;
  return BigInt(raw);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Web Crypto Implementation

async function deriveKeys(secretHex) {
  const secretBytes = hexToBytes(secretHex);
  const hashBuffer = await crypto.subtle.digest('SHA-256', secretBytes);
  const hashArray = new Uint8Array(hashBuffer);
  
  // Split 32 bytes into two 16-byte keys
  const encKeyBytes = hashArray.slice(0, 16);
  const authKeyBytes = hashArray.slice(16, 32);

  const encKey = await crypto.subtle.importKey(
    'raw', encKeyBytes, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']
  );

  const authKey = await crypto.subtle.importKey(
    'raw', authKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );

  return { encKey, authKey };
}

async function encryptWithSecret(secretHex, plaintext) {
  const { encKey, authKey } = await deriveKeys(secretHex);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ptBytes = encoder.encode(plaintext);

  const ctBuffer = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    encKey,
    ptBytes
  );
  const ctBytes = new Uint8Array(ctBuffer);

  // HMAC over IV + Ciphertext
  const dataToSign = new Uint8Array(iv.length + ctBytes.length);
  dataToSign.set(iv);
  dataToSign.set(ctBytes, iv.length);

  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    authKey,
    dataToSign
  );
  const sigBytes = new Uint8Array(sigBuffer);

  return {
    ciphertext: bytesToHex(ctBytes),
    iv: bytesToHex(iv),
    hmac: bytesToHex(sigBytes)
  };
}

async function decryptWithSecret(secretHex, ivHex, ciphertextHex, hmacHex) {
  const { encKey, authKey } = await deriveKeys(secretHex);
  const iv = hexToBytes(ivHex);
  const ctBytes = hexToBytes(ciphertextHex);
  const hmacBytes = hexToBytes(hmacHex);

  // Verify HMAC
  const dataToVerify = new Uint8Array(iv.length + ctBytes.length);
  dataToVerify.set(iv);
  dataToVerify.set(ctBytes, iv.length);

  const isValid = await crypto.subtle.verify(
    'HMAC',
    authKey,
    hmacBytes,
    dataToVerify
  );

  if (!isValid) {
    throw new Error('HMAC mismatch');
  }

  // Decrypt
  const ptBuffer = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    encKey,
    ctBytes
  );

  return decoder.decode(ptBuffer);
}

// Main Init Function (Async-aware)
async function webCryptoDemoInit(username) {
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
    const resp = await fetch('/api/dh_sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiator: username, recipient }),
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
    keysDiv.textContent = `Derived DH secret ${secretHex} with ${peer}`;
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

    // await encryptWithSecret
    const { ciphertext, iv, hmac } = await encryptWithSecret(shared.secretHex, plaintext);
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
    const algoLabel = 'WebCrypto AES-CBC + HMAC';
    await logKeyExchange(recipient, algoLabel, logParams, 'sender');

    messageInput.value = '';
    refreshInbox();
  }

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
          // await decryptWithSecret
          const plain = await decryptWithSecret(shared.secretHex, msg.iv, msg.ciphertext, msg.hmac);
          li.textContent = `${msg.sender}: ${plain}`;
        } catch (err) {
          console.error(err);
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

window.webCryptoDemoInit = webCryptoDemoInit;
})();
