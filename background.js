const PUBKEY = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
const SECKEY = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';

//////////////////////////////////////////////////////////////////////
// SIGNEVENT, I THINK ITS ALL GOOD
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

    // Sign the event (this is a placeholder, replace with actual signing logic)
    event.sig = await signMessage(event.id, SECKEY);

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
// SIGNMESSAGE, WORK ON IT
//////////////////////////////////////////////////////////////////////


// Utility functions
const hexToBytes = (hex) => {
  const len = hex.length;
  if (len % 2) throw new Error('Odd length');
  const array = new Uint8Array(len / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    array[i] = parseInt(hexByte, 16);
  }
  return array;
};

const bytesToHex = (bytes) => {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

const utf8ToBytes = (str) => {
  return new TextEncoder().encode(str);
};

// Simplified modulo function for 32-bit numbers
const mod = (a, b) => ((a % b) + b) % b;

// Constants
const CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

// Simplified private key to scalar conversion
const privKeyToScalar = (privateKey) => {
  if (typeof privateKey === 'string') {
    privateKey = hexToBytes(privateKey);
  }
  let scalar = 0;
  for (let i = 0; i < privateKey.length; i++) {
    scalar = (scalar * 256 + privateKey[i]) % CURVE_ORDER;
  }
  return scalar;
};

// Main signMessage function
async function signMessage(message, privateKey) {
  if (typeof message === 'string') {
    message = utf8ToBytes(message);
  }
  
  const d = privKeyToScalar(privateKey);
  
  // Generate a random k value (this should be done more securely in practice)
  const kBytes = crypto.getRandomValues(new Uint8Array(32));
  const k = privKeyToScalar(kBytes);
  
  // Here we would normally compute R = k * G and get its x-coordinate
  // For simplicity, we'll use a placeholder
  const rx = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  
  // Compute the challenge e = H(rx || compressed(P) || m)
  // For simplicity, we'll use a basic concatenation
  const challengeInput = new Uint8Array([...hexToBytes(rx), ...hexToBytes(privateKey), ...message]);
  const eBytes = await crypto.subtle.digest('SHA-256', challengeInput);
  const e = new DataView(eBytes).getUint32(0, false); // Use only the first 4 bytes for simplicity
  
  // Compute s = k + e * d
  const s = mod(k + e * d, CURVE_ORDER);
  
  // The signature is (rx, s)
  return rx + s.toString(16).padStart(64, '0');
}

// Generate a random private key
function randomPrivateKey() {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(privateKey);
}

// Usage example:
// const privateKey = randomPrivateKey();
// const message = 'Hello, Nostr!';
// signMessage(message, privateKey).then(signature => console.log(signature));

export { signMessage, randomPrivateKey };




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
