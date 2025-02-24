# crypto-security

A simple Node.js module for encrypting and decrypting data and files.

## Features
- Encrypt and decrypt text data.
- Encrypt and decrypt files.

## Usage

### Importing the Module

```js
const { data, file } = require('./crypto-security');
```

### Encrypting and Decrypting Data

```js
const password = "your-secure-password";
const plaintext = "Hello, world!";

(async () => {
    const encrypted = await data.encrypt(password, plaintext);
    console.log("Encrypted:", encrypted);

    const decrypted = await data.decrypt(password, encrypted.result.bin);
    console.log("Decrypted:", decrypted.result.bin.toString());
})();
```

### Encrypting and Decrypting Files

```js
(async () => {
    await file.encrypt(password, "This is a secret message", "secret.enc");
    console.log("File encrypted successfully");

    const decryptedText = await file.decrypt.get_text(password, "secret.enc");
    console.log("Decrypted text:", decryptedText);
})();
```

## API

### `data.encrypt(password, data, algorithm = 'aes-256-gcm')`
Encrypts text data.
- **password** _(string)_: The encryption key.
- **data** _(string)_: The plaintext data.
- **algorithm** _(string)_: The encryption algorithm (default: `aes-256-gcm`).
- **Returns**: Object with encrypted data or `false` on failure.

### `data.decrypt(password, encryptedData)`
Decrypts encrypted text data.
- **password** _(string)_: The decryption key.
- **encryptedData** _(Buffer|string)_: The encrypted data.
- **Returns**: Object with decrypted data or `false` on failure.

### `file.encrypt(password, data, file_from, algorithm)`
Encrypts and saves data to a file.
- **password** _(string)_: The encryption key.
- **data** _(string)_: The plaintext data.
- **file_from** _(string)_: The output file path.
- **algorithm** _(string)_: The encryption algorithm (default: `aes-256-gcm`).
- **Returns**: `true` on success, `false` on failure.

### `file.decrypt.to_file(password, file_from, file_to)`
Decrypts a file and saves the output.
- **password** _(string)_: The decryption key.
- **file_from** _(string)_: The input file path.
- **file_to** _(string)_: The output file path.
- **Returns**: `true` on success, `false` on failure.

### `file.decrypt.get_text(password, file_from)`
Decrypts a file and returns the decrypted text.
- **password** _(string)_: The decryption key.
- **file_from** _(string)_: The input file path.
- **Returns**: The decrypted text or `false` on failure.