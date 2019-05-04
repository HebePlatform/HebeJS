(function() {

  var crypto = require('crypto');
  var pako = require('pako');
  var CryptoJS = require('crypto-js');
  var c25519 = require('../util/curve25519_.js');
  var helpers = require('./helpers');


  function getPrivateKey(secretPhrase) {
    var bytes = helpers.simpleHash(
      helpers.stringToByteArray(secretPhrase)
    );
    var res = c25519.clamp(
      helpers.byteArrayToShortArray(bytes)
    );
    return helpers.shortArrayToHexString(res);
  };


  function getSharedKey(key1, key2) {
    key1 = helpers.byteArrayToShortArray(key1);
    key2 = helpers.byteArrayToShortArray(key2);
    var shared = c25519.curve25519(key1, key2, null);
    return helpers.shortArrayToByteArray(shared);
  };


  function aesDecrypt(ivCiphertext, options) {
    if (ivCiphertext.length < 16 || ivCiphertext.length % 16 !== 0) {
      return false;
    }
    var iv = helpers.byteArrayToWordArray(
      ivCiphertext.slice(0, 16)
    );
    var ciphertext = helpers.byteArrayToWordArray(
      ivCiphertext.slice(16)
    );
    for (var i = 0; i < 32; i++) {
      options.sharedKey[i] ^= options.nonce[i];
    }
    var key = CryptoJS.SHA256(
      helpers.byteArrayToWordArray(options.sharedKey)
    );
    var encrypted = CryptoJS.lib.CipherParams.create({
      ciphertext: ciphertext,
      iv: iv,
      key: key,
    });
    var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      iv: iv,
    });
    return helpers.wordArrayToByteArray(decrypted);
  };


  function aesEncrypt(plaintext, options) {
    var text = helpers.byteArrayToWordArray(plaintext);
    for (var i = 0; i < 32; i++) {
      options.sharedKey[i] ^= options.nonce[i];
    }
    var key = CryptoJS.SHA256(
      helpers.byteArrayToWordArray(options.sharedKey)
    );
    var tmp = crypto.randomBytes(16);
    var iv = helpers.byteArrayToWordArray(tmp);
    var encrypted = CryptoJS.AES.encrypt(text, key, {
      iv: iv,
    });
    var ivOut = helpers.wordArrayToByteArray(encrypted.iv);
    var ciphertextOut = helpers.wordArrayToByteArray(encrypted.ciphertext);
    return ivOut.concat(ciphertextOut);
  }


  function decryptMessage(message, nonce, publicKey, secretPhrase) {
    var options = {
      privateKey: helpers.hexStringToByteArray(
        getPrivateKey(secretPhrase)
      ),
      publicKey: helpers.hexStringToByteArray(publicKey),
      nonce: helpers.hexStringToByteArray(nonce),
    };
    options.sharedKey = getSharedKey(options.privateKey, options.publicKey);
    var messageBytes = helpers.hexStringToByteArray(message);
    var compressedPlaintext = aesDecrypt(messageBytes, options);
    if (!compressedPlaintext) {
      return false;
    }
    var binData = new Uint8Array(compressedPlaintext);
    return helpers.byteArrayToString(pako.inflate(binData));
  };


  function encryptMessage(message, publicKey, secretPhrase) {
    var options = {
      privateKey: helpers.hexStringToByteArray(
        getPrivateKey(secretPhrase)
      ),
      publicKey: helpers.hexStringToByteArray(publicKey),
      nonce: crypto.randomBytes(32),
    };
    options.sharedKey = getSharedKey(options.privateKey, options.publicKey);
    var plaintext = helpers.stringToByteArray(message);
    var compressedPlaintext = pako.gzip(
      new Uint8Array(plaintext)
    );
    var encrypted = aesEncrypt(compressedPlaintext, options);
    return {
      message: helpers.byteArrayToHexString(encrypted),
      nonce: helpers.byteArrayToHexString(options.nonce),
    };
  };


  module.exports = {
    decryptMessage: decryptMessage,
    encryptMessage: encryptMessage,
  };


})();
