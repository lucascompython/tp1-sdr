function generateKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

function encryptData(data, publicKey) {
  return window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    new TextEncoder().encode(data)
  );
}

function decryptData(data, privateKey) {
  return window.crypto.subtle
    .decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      data
    )
    .then((decryptedData) => new TextDecoder().decode(decryptedData));
}

function signData(data, privateKey) {
  return window.crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 20,
    },
    privateKey,
    new TextEncoder().encode(data)
  );
}

function verifySignature(data, signature, publicKey) {
  return window.crypto.subtle.verify(
    {
      name: "RSA-PSS",
      saltLength: 20,
    },
    publicKey,
    signature,
    new TextEncoder().encode(data)
  );
}
// create a key pair
const keyPair = generateKeyPair().then((keyPair) => {
  // get the public key
  const publicKey = keyPair.publicKey;

  // print the public key
  console.log(publicKey);
});

// get the public key
const publicKey = keyPair.publicKey;

// print the public key
console.log(publicKey);
