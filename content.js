console.log('Nostr Keyring: Content script starting');

const injectScript = () => {
  const script = document.createElement('script');
  script.textContent = `
    (function() {
      console.log('Nostr Keyring: Injecting window.nostr object');
      window.nostr = {
        getPublicKey: () => {
          console.log('Nostr Keyring: getPublicKey called');
          return new Promise((resolve, reject) => {
            window.postMessage({ type: 'NOSTR_GET_PUBLIC_KEY' }, '*');
            window.addEventListener('message', function listener(event) {
              if (event.data.type === 'NOSTR_PUBLIC_KEY_RESPONSE') {
                window.removeEventListener('message', listener);
                if (event.data.error) {
                  reject(new Error(event.data.error));
                } else {
                  resolve(event.data.publicKey);
                }
              }
            });
          });
        },
        signEvent: (event) => {
          console.log('Nostr Keyring: signEvent called', event);
          return new Promise((resolve, reject) => {
            window.postMessage({ type: 'NOSTR_SIGN_EVENT', event }, '*');
            window.addEventListener('message', function listener(event) {
              if (event.data.type === 'NOSTR_SIGNED_EVENT_RESPONSE') {
                window.removeEventListener('message', listener);
                if (event.data.error) {
                  reject(new Error(event.data.error));
                } else {
                  resolve(event.data.signedEvent);
                }
              }
            });
          });
        },
        nip04: {
          encrypt: (recipientPubkey, plaintext) => {
            console.log('Nostr Keyring: nip04.encrypt called');
            return new Promise((resolve, reject) => {
              window.postMessage({ type: 'NOSTR_ENCRYPT_MESSAGE_NIP04', recipientPubkey, plaintext }, '*');
              window.addEventListener('message', function listener(event) {
                if (event.data.type === 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP04') {
                  window.removeEventListener('message', listener);
                  if (event.data.error) {
                    reject(new Error(event.data.error));
                  } else {
                    resolve(event.data.encryptedMessage);
                  }
                }
              });
            });
          },
          decrypt: (senderPubkey, ciphertext) => {
            console.log('Nostr Keyring: nip04.decrypt called');
            return new Promise((resolve, reject) => {
              window.postMessage({ type: 'NOSTR_DECRYPT_MESSAGE_NIP04', senderPubkey, ciphertext }, '*');
              window.addEventListener('message', function listener(event) {
                if (event.data.type === 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP04') {
                  window.removeEventListener('message', listener);
                  if (event.data.error) {
                    reject(new Error(event.data.error));
                  } else {
                    resolve(event.data.decryptedMessage);
                  }
                }
              });
            });
          }
        },
        nip44: {
          encrypt: (recipientPubkey, plaintext) => {
            console.log('Nostr Keyring: nip44.encrypt called');
            return new Promise((resolve, reject) => {
              window.postMessage({ type: 'NOSTR_ENCRYPT_MESSAGE_NIP44', recipientPubkey, plaintext }, '*');
              window.addEventListener('message', function listener(event) {
                if (event.data.type === 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP44') {
                  window.removeEventListener('message', listener);
                  if (event.data.error) {
                    reject(new Error(event.data.error));
                  } else {
                    resolve(event.data.encryptedMessage);
                  }
                }
              });
            });
          },
          decrypt: (senderPubkey, ciphertext) => {
            console.log('Nostr Keyring: nip44.decrypt called');
            return new Promise((resolve, reject) => {
              window.postMessage({ type: 'NOSTR_DECRYPT_MESSAGE_NIP44', senderPubkey, ciphertext }, '*');
              window.addEventListener('message', function listener(event) {
                if (event.data.type === 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP44') {
                  window.removeEventListener('message', listener);
                  if (event.data.error) {
                    reject(new Error(event.data.error));
                  } else {
                    resolve(event.data.decryptedMessage);
                  }
                }
              });
            });
          }
        }
      };
      console.log('Nostr Keyring: window.nostr object injected');
      window.dispatchEvent(new Event('nostr:ready'));
    })();
  `;
  (document.head || document.documentElement).appendChild(script);
  console.log('Nostr Keyring: Script injected into the page');
};

// Inject the script as soon as possible
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectScript);
} else {
  injectScript();
}

window.addEventListener('message', async (event) => {
  if (event.source !== window) return;

  if (event.data.type === 'NOSTR_GET_PUBLIC_KEY') {
    console.log('Nostr Keyring: Received request for public key');
    console.log('aaaaaaaa')
    try {
      console.log('bbbbbbbb')
      const response = await chrome.runtime.sendMessage({ type: 'getPublicKey' });
      console.log('Nostr Keyring: Public key received from background', response);
      window.postMessage({ type: 'NOSTR_PUBLIC_KEY_RESPONSE', publicKey: response }, '*');
    } catch (error) {
      console.log('ccccccccc')
      console.error('Nostr Keyring: Error getting public key from background', error);
      window.postMessage({ type: 'NOSTR_PUBLIC_KEY_RESPONSE', error: error.message }, '*');
    }
  } else if (event.data.type === 'NOSTR_SIGN_EVENT') {
    console.log('ddddddddd')
    console.log('Nostr Keyring: Received request to sign event', event.data.event);
    try {
      console.log('eeeeeeeee')
      const signedEvent = await chrome.runtime.sendMessage({ type: 'signEvent', event: event.data.event });
      console.log('Nostr Keyring: Event signed by background', signedEvent);
      window.postMessage({ type: 'NOSTR_SIGNED_EVENT_RESPONSE', signedEvent }, '*');
    } catch (error) {
      console.log('fffffffff')
      console.error('Nostr Keyring: Error signing event in background', error);
      window.postMessage({ type: 'NOSTR_SIGNED_EVENT_RESPONSE', error: error.message }, '*');
    }
  } else if (event.data.type === 'NOSTR_ENCRYPT_MESSAGE_NIP04') {
    console.log('Nostr Keyring: Received request to encrypt message (NIP-04)');
    try {
      const encryptedMessage = await chrome.runtime.sendMessage({ 
        type: 'encryptMessageNip04', 
        recipientPubkey: event.data.recipientPubkey, 
        content: event.data.plaintext 
      });
      console.log('Nostr Keyring: Message encrypted by background (NIP-04)', encryptedMessage);
      window.postMessage({ type: 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP04', encryptedMessage }, '*');
    } catch (error) {
      console.error('Nostr Keyring: Error encrypting message in background (NIP-04)', error);
      window.postMessage({ type: 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP04', error: error.message }, '*');
    }
  } else if (event.data.type === 'NOSTR_DECRYPT_MESSAGE_NIP04') {
    console.log('Nostr Keyring: Received request to decrypt message (NIP-04)');
    try {
      const decryptedMessage = await chrome.runtime.sendMessage({ 
        type: 'decryptMessageNip04', 
        senderPubkey: event.data.senderPubkey, 
        encryptedContent: event.data.ciphertext 
      });
      console.log('Nostr Keyring: Message decrypted by background (NIP-04)', decryptedMessage);
      window.postMessage({ type: 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP04', decryptedMessage }, '*');
    } catch (error) {
      console.error('Nostr Keyring: Error decrypting message in background (NIP-04)', error);
      window.postMessage({ type: 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP04', error: error.message }, '*');
    }
  } else if (event.data.type === 'NOSTR_ENCRYPT_MESSAGE_NIP44') {
    console.log('Nostr Keyring: Received request to encrypt message (NIP-44)');
    try {
      const encryptedMessage = await chrome.runtime.sendMessage({ 
        type: 'encryptMessageNip44', 
        recipientPubkey: event.data.recipientPubkey, 
        content: event.data.plaintext 
      });
      console.log('Nostr Keyring: Message encrypted by background (NIP-44)', encryptedMessage);
      window.postMessage({ type: 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP44', encryptedMessage }, '*');
    } catch (error) {
      console.error('Nostr Keyring: Error encrypting message in background (NIP-44)', error);
      window.postMessage({ type: 'NOSTR_ENCRYPTED_MESSAGE_RESPONSE_NIP44', error: error.message }, '*');
    }
  } else if (event.data.type === 'NOSTR_DECRYPT_MESSAGE_NIP44') {
    console.log('Nostr Keyring: Received request to decrypt message (NIP-44)');
    try {
      const decryptedMessage = await chrome.runtime.sendMessage({ 
        type: 'decryptMessageNip44', 
        senderPubkey: event.data.senderPubkey, 
        encryptedContent: event.data.ciphertext 
      });
      console.log('Nostr Keyring: Message decrypted by background (NIP-44)', decryptedMessage);
      window.postMessage({ type: 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP44', decryptedMessage }, '*');
    } catch (error) {
      console.error('Nostr Keyring: Error decrypting message in background (NIP-44)', error);
      window.postMessage({ type: 'NOSTR_DECRYPTED_MESSAGE_RESPONSE_NIP44', error: error.message }, '*');
    }
  }
});

console.log('Nostr Keyring: Content script fully loaded');
