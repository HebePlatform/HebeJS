# hebejs
Small collection of JavaScript functions for hebe. Allows for local signing of transactions, token creation/validation and encryption/decryption of arbitrary messages.

### Install
`npm install hebejs`

### Test
`npm test`

### Usage
##### node.js:

    var hebejs = require('hebejs');

    // Create an account
    var acc = hebejs.secretPhraseToAccountId('secret');
    console.log(acc);
    
##### Browser:

Create the bundle with browserify:

`browserify index.js -s hebejs > build/hebejs.js`

Use in HTML file:

    <script src="hebejs.js"></script>
    <script>
        var acc = hebejs.secretPhraseToAccountId('secret');
        console.log(acc);
    </script>

### Functions
#### secretPhraseToPublicKey(secretPhrase)
Returns public key of a given passphrase

#### publicKeyToAccountId(publicKey, numeric)
Returns account ID of a given public key. Set the second parameter to true to
get numeric account ID instead of RS format

#### secretPhraseToAccountId(secretPhrase, numeric)
Returns account ID of a given passphrase.  Set the second parameter to true to
get numeric account ID instead of RS format.

#### signTransactionBytes(unsignedTransactionBytes, secretPhrase)
Signs a hex string of unsigned transaction bytes (e.g. as received from NRS API)
with the provided passphrase and returns it.

#### createToken(string, secretPhrase)
Generates a hebe cryptographic token

#### parseToken(token, string)
Parses a hebe cryptographic token. Returns an object with the keys `isValid`,
`timestamp`, `publicKey` and `accountRS`.

#### encryptMessage(plainText, recipientPublicKey, senderSecretPhrase)
Returns an object with the keys `nonce` and `message`

#### decryptMessage(cipherText, nonce, senderPublicKey, recipientSecretPhrase)
Returns the deciphered text as string

#### rsConvert(address)
Converts address in numeric format to Reed-Solomon format, or vice versa. Returns an object with the keys `account` and `accountRS`



