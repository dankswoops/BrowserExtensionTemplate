const PUBKEY = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
const SECKEY = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';

//////////////////////////////////////////////////////////////////////
// SCHNORR.SIGN, STILL BROKEN?
//////////////////////////////////////////////////////////////////////

const schnorr = (() => {
  const _0n = BigInt(0);
  const _1n = BigInt(1);
  const _2n = BigInt(2);
  const _3n = BigInt(3);
  const _8n = BigInt(8);
  const CURVE = {
    P: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
    n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
    G: {
      x: BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
      y: BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')
    }
  };

  const modP = (x) => ((x % CURVE.P) + CURVE.P) % CURVE.P;
  const modN = (x) => ((x % CURVE.n) + CURVE.n) % CURVE.n;

  const invert = (number, modulo) => {
    let a = modN(number);
    let b = modulo;
    let x = _0n, y = _1n, u = _1n, v = _0n;
    while (a !== _0n) {
      const q = b / a;
      const r = b % a;
      const m = x - u * q;
      const n = y - v * q;
      b = a, a = r, x = u, y = v, u = m, v = n;
    }
    const gcd = b;
    if (gcd !== _1n) throw new Error('invert: does not exist');
    return modN(x);
  };

  const sign = (msgHash, privateKey) => {
    const d = BigInt(`0x${privateKey}`);
    const k = modN(BigInt(`0x${msgHash}`) ^ d);
    const R = pointMultiply(k, CURVE.G);
    const e = modN(BigInt(`0x${msgHash}`) + BigInt(R.x) * BigInt(`0x${PUBKEY}`));
    const s = modN(k + e * d);
    return numberToHex(R.x) + numberToHex(s);
  };

  const pointMultiply = (k, { x, y }) => {
    let rx = _0n, ry = _0n, rz = _1n;
    let tx = x, ty = y, tz = _1n;
    while (k > _0n) {
      if (k & _1n) [rx, ry, rz] = pointAdd(rx, ry, rz, tx, ty, tz);
      [tx, ty, tz] = pointDouble(tx, ty, tz);
      k >>= _1n;
    }
    return { x: modP(rx * invert(rz, CURVE.P)), y: modP(ry * invert(rz, CURVE.P)) };
  };

  const pointAdd = (px, py, pz, qx, qy, qz) => {
    const u1 = modP(py * qz);
    const u2 = modP(qy * pz);
    const v1 = modP(px * qz);
    const v2 = modP(qx * pz);
    if (v1 === v2 && u1 !== u2) return [_0n, _0n, _1n];
    const u = modP(u2 - u1);
    const v = modP(v2 - v1);
    const w = modP(pz * qz);
    const a = modP(u * u * w - v * v * v - _2n * v * v * v1);
    const rx = modP(v * a);
    const ry = modP(u * (v * v * v1 - a) - v * v * v * u1);
    const rz = modP(v * v * v * w);
    return [rx, ry, rz];
  };

  const pointDouble = (px, py, pz) => {
    const w = modP(_3n * px * px);
    const s = modP(py * pz);
    const b = modP(px * py * s);
    const h = modP(w * w - _8n * b);
    const rx = modP(_2n * h * s);
    const ry = modP(w * (b - h) - _2n * py * py * s * s);
    const rz = modP(_8n * s * s * s);
    return [rx, ry, rz];
  };

  const numberToHex = (num) => num.toString(16).padStart(64, '0');

  return { sign };
})();


//////////////////////////////////////////////////////////////////////
// SIGNEVENT, I THINK ITS GOOD?
//////////////////////////////////////////////////////////////////////

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
    const eventId = await sha256((new TextEncoder()).encode(serializedEvent));
    event.id = arrayToHex(eventId);

    // Sign the event using schnorr.sign directly
    event.sig = schnorr.sign(event.id, SECKEY);

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
  return new Uint8Array(hashBuffer);
}

function arrayToHex(array) {
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

//////////////////////////////////////////////////////////////////////
// ALL WORKING BELOW
//////////////////////////////////////////////////////////////////////

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
