const PUBKEY = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
const SECKEY = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';

// secp256k1 curve parameters
const CURVE = {
  P: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
  n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
  G: {
    x: BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
    y: BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')
  }
};

function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }
  return result;
}

function schnorrSign(message, privateKey) {
  const d = BigInt(`0x${privateKey}`);
  const k = BigInt(`0x${message}`) ^ d; // Simple nonce generation, not secure for production
  const R = pointMultiply(k);
  const e = BigInt(`0x${message}`) + R.x * BigInt(`0x${PUBKEY}`);
  const s = (k + e * d) % CURVE.n;
  return R.x.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0');
}

function pointMultiply(k) {
  let R = { x: CURVE.G.x, y: CURVE.G.y };
  let Q = { x: 0n, y: 0n };
  while (k > 0n) {
    if (k & 1n) {
      Q = pointAdd(Q, R);
    }
    R = pointAdd(R, R);
    k >>= 1n;
  }
  return Q;
}

function pointAdd(P, Q) {
  if (P.x === 0n && P.y === 0n) return Q;
  if (Q.x === 0n && Q.y === 0n) return P;
  const lam = ((Q.y - P.y) * modPow(Q.x - P.x, CURVE.P - 2n, CURVE.P)) % CURVE.P;
  const x = (lam * lam - P.x - Q.x) % CURVE.P;
  const y = (lam * (P.x - x) - P.y) % CURVE.P;
  return { x: (x + CURVE.P) % CURVE.P, y: (y + CURVE.P) % CURVE.P };
}

async function signEvent(event) {
  console.log('Nostr Key Signer: signEvent called with', event);
  
  try {
    if (!event) throw new Error('Event object is undefined');

    // Ensure required fields are present
    event.kind = event.kind || 1;
    event.created_at = event.created_at || Math.floor(Date.now() / 1000);
    event.tags = event.tags || [];
    event.content = event.content || '';
    event.pubkey = PUBKEY;

    // Generate the event id
    const eventData = [0, event.pubkey, event.created_at, event.kind, event.tags, event.content];
    const serializedEvent = JSON.stringify(eventData);
    const eventId = await sha256(serializedEvent);
    event.id = eventId;

    // Sign the event
    event.sig = schnorrSign(eventId, SECKEY);

    console.log('Nostr Key Signer: Event signed', event);
    return event;
  } catch (error) {
    console.error('Nostr Key Signer: Error in signEvent function', error);
    throw error;
  }
}

async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayToHex(new Uint8Array(hashBuffer));
}

function arrayToHex(array) {
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getPublicKey') {
    sendResponse(PUBKEY);
    return true;
  } else if (message.type === 'signEvent') {
    signEvent(message.event).then(signedEvent => {
      sendResponse(signedEvent);
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true;
  } else if (message.type === 'encryptMessageNip04') {
    encryptMessageNip04(message.recipientPubkey, message.content).then(encryptedMessage => {
      sendResponse(encryptedMessage);
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true;
  } else if (message.type === 'decryptMessageNip04') {
    decryptMessageNip04(message.senderPubkey, message.encryptedContent).then(decryptedMessage => {
      sendResponse(decryptedMessage);
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true;
  } else if (message.type === 'encryptMessageNip44') {
    encryptMessageNip44(message.recipientPubkey, message.content).then(encryptedMessage => {
      sendResponse(encryptedMessage);
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true;
  } else if (message.type === 'decryptMessageNip44') {
    decryptMessageNip44(message.senderPubkey, message.encryptedContent).then(decryptedMessage => {
      sendResponse(decryptedMessage);
    }).catch(error => {
      sendResponse({ error: error.message });
    });
    return true;
  }
});
