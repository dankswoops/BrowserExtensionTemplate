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

function pointAdd(P, Q) {
  if (P.x === 0n && P.y === 0n) return Q;
  if (Q.x === 0n && Q.y === 0n) return P;
  const lam = ((Q.y - P.y) * modPow(Q.x - P.x, CURVE.P - 2n, CURVE.P)) % CURVE.P;
  const x = (lam * lam - P.x - Q.x) % CURVE.P;
  const y = (lam * (P.x - x) - P.y) % CURVE.P;
  return { x: (x + CURVE.P) % CURVE.P, y: (y + CURVE.P) % CURVE.P };
}

function pointMultiply(k, P = CURVE.G) {
  let R = { x: 0n, y: 0n };
  while (k > 0n) {
    if (k & 1n) {
      R = pointAdd(R, P);
    }
    P = pointAdd(P, P);
    k >>= 1n;
  }
  return R;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function bigintToUint8Array(bigint, length = 32) {
  return hexToUint8Array(bigint.toString(16).padStart(length * 2, '0'));
}

function concatUint8Arrays(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function xor(a, b) {
  return a.map((byte, i) => byte ^ b[i]);
}

async function taggedHash(tag, ...messages) {
  const tagHash = await sha256(tag);
  return sha256(concatUint8Arrays(tagHash, tagHash, ...messages.map(m => new Uint8Array(m))));
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  return new Uint8Array(hashBuffer);
}

async function schnorrSign(message, privateKey) {
  try {
    const d = BigInt(`0x${privateKey}`);
    const P = pointMultiply(d);
    
    // BIP340-compliant nonce generation
    const aux_rand = crypto.getRandomValues(new Uint8Array(32));
    const t = xor(bigintToUint8Array(d, 32), await taggedHash('BIP0340/aux', aux_rand));
    const rand = await taggedHash('BIP0340/nonce', t, bigintToUint8Array(P.x, 32), hexToUint8Array(message));
    let k = BigInt(`0x${bufferToHex(rand)}`) % CURVE.n;
    
    const R = pointMultiply(k);
    if ((R.y & 1n) !== 0n) {
      k = CURVE.n - k;
    }
    
    const e = BigInt(`0x${bufferToHex(await taggedHash('BIP0340/challenge', bigintToUint8Array(R.x, 32), bigintToUint8Array(P.x, 32), hexToUint8Array(message)))}`) % CURVE.n;
    const s = (k + e * d) % CURVE.n;
    
    return concatUint8Arrays(bigintToUint8Array(R.x, 32), bigintToUint8Array(s, 32));
  } catch (error) {
    console.error('Error in schnorrSign:', error);
    throw error;
  }
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
    event.id = bufferToHex(eventId);

    // Sign the event
    const signatureBytes = await schnorrSign(event.id, SECKEY);
    event.sig = bufferToHex(signatureBytes);

    console.log('Nostr Key Signer: Event signed', event);
    return event;
  } catch (error) {
    console.error('Nostr Key Signer: Error in signEvent function', error);
    throw error;
  }
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
  }
  // Other message handlers...
});
