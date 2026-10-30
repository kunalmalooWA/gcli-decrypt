const crypto = require("crypto");
const fs = require("fs");

const privateKeyPem = fs.readFileSync("private_key.pem");

const base64ToArrayBuffer = (base64) => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

async function decryptResponse(data, encryptedKey) {
  const encryptedKeyForGet = Buffer.from(encryptedKey, "base64");
  const aesKeyForGet = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKeyForGet,
  );
  const iv = base64ToArrayBuffer(data.Iv);
  const ciphertext = base64ToArrayBuffer(data.EncryptedData);
  const tag = base64ToArrayBuffer(data.Tag);

  const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  combined.set(new Uint8Array(ciphertext), 0);
  combined.set(new Uint8Array(tag), ciphertext.byteLength);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    aesKeyForGet,
    {
      name: "AES-GCM",
    },
    false,
    ["decrypt"],
  );

  const decryptedData = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    cryptoKey,
    combined,
  );
  const decoded = new TextDecoder().decode(decryptedData);
  return JSON.parse(decoded);
}

const data = {
    Iv: "mujxLVaTCB7AOC0H",
    EncryptedData: "Z1kd6tPejP0d04p5YV675DpKPESlW1LnVxsFEj/jMKKSOZ4LaiWvuYiWQiI3SoVbla/mxDHF27gZ69dBdMGgYIB88P2L23GBQ6YQaAlU1gKRkDucXKGKcpN3keg5v1+vN0nV0CIGehAV0PkFkwaGLXLQi83FhHThhh9BTpKL0/IrZVbRfYIXXbyMqEgy95NeDbK96eqmiAGVM0yD/r1BC8k6CKFcbB/mWl/6aCy9jc7TX723Ya+KS5GyxaO9JZLYH9fs2o466UD3lisZ4aw3IWd1GWg=",
    Tag: "X5H9EXABiugG/lIERN5WAw=="
}

const encryptedKey =
  "o2qjOSi2Cxe7vD5jR8iP1FcaqOXjkDgUoJalgfxEbNi00gTM1oYYx3ZcP4wKJsbNuE9jufxWWZcwabLIgXhdo2jFSafWOXL3enilhLCEn0dGOp7EOTFJYdoE5IlDbdYIC1xz7WJVs7skJbHNC00FNUILx1ZP7aX1lt62RM+FfhlRF1occL0JilwpIHfc4QqkhPI/C8AhrBXz4tjBYCkLrt3yj/0KPZspfBOwc98mdu967gLucwLRI541hFKkmk2jIJLl8z2NEcpf+1rMD+em1rjMeAAZ2/eopi5N4j80+tPNT4leG9IvxqVOEc1nCUxsSoYNpiPcW87rMhvIvrsOWQ=="

const getResponse = async () => {
  try {
    const res = await decryptResponse(data, encryptedKey);
    fs.writeFileSync("./response.json", JSON.stringify(res, null, 2));
  } catch (error) {
    console.log(error);
  }
};

// {"encryptedKey":"o2qjOSi2Cxe7vD5jR8iP1FcaqOXjkDgUoJalgfxEbNi00gTM1oYYx3ZcP4wKJsbNuE9jufxWWZcwabLIgXhdo2jFSafWOXL3enilhLCEn0dGOp7EOTFJYdoE5IlDbdYIC1xz7WJVs7skJbHNC00FNUILx1ZP7aX1lt62RM+FfhlRF1occL0JilwpIHfc4QqkhPI/C8AhrBXz4tjBYCkLrt3yj/0KPZspfBOwc98mdu967gLucwLRI541hFKkmk2jIJLl8z2NEcpf+1rMD+em1rjMeAAZ2/eopi5N4j80+tPNT4leG9IvxqVOEc1nCUxsSoYNpiPcW87rMhvIvrsOWQ==","iv":"mujxLVaTCB7AOC0H","encryptedData":"Z1kd6tPejP0d04p5YV675DpKPESlW1LnVxsFEj/jMKKSOZ4LaiWvuYiWQiI3SoVbla/mxDHF27gZ69dBdMGgYIB88P2L23GBQ6YQaAlU1gKRkDucXKGKcpN3keg5v1+vN0nV0CIGehAV0PkFkwaGLXLQi83FhHThhh9BTpKL0/IrZVbRfYIXXbyMqEgy95NeDbK96eqmiAGVM0yD/r1BC8k6CKFcbB/mWl/6aCy9jc7TX723Ya+KS5GyxaO9JZLYH9fs2o466UD3lisZ4aw3IWd1GWg=","tag":"X5H9EXABiugG/lIERN5WAw=="}}

getResponse(); 