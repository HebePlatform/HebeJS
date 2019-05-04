(function() {

  var Buffer = require('buffer/').Buffer;
  var crypto = require('crypto');
  var BigInteger = require('jsbn');
  var curve25519 = require('../util/curve25519.js');
  var account = require('./account');
  var helpers = require('./helpers');

  var epochNum = 1385294400;


  function createToken(websiteString, secretPhrase) {
    var data = [];
    var hexwebsite = helpers.stringToHexString(websiteString);
    var website = helpers.hexStringToByteArray(hexwebsite);

    var unix = Math.round(+new Date() / 1000);
    var timestamp = unix - epochNum;
    var timestamparray = helpers.intValToByteArray(timestamp);

    data = website.concat(
      account.secretPhraseToPublicKey(secretPhrase, true)
    );
    data = data.concat(timestamparray);

    var token = [];
    token = account.secretPhraseToPublicKey(secretPhrase, true);
    token = token.concat(timestamparray);

    var sig = account.signBytes(data, secretPhrase);
    token = token.concat(sig);

    var buf = '';
    for (var ptr = 0; ptr < 100; ptr += 5) {

      var nbr = [];
      nbr[0] = token[ptr] & 0xFF;
      nbr[1] = token[ptr + 1] & 0xFF;
      nbr[2] = token[ptr + 2] & 0xFF;
      nbr[3] = token[ptr + 3] & 0xFF;
      nbr[4] = token[ptr + 4] & 0xFF;
      var number = helpers.byteArrayToBigInteger(nbr);

      if (number < 32) {
        buf += '0000000';
      } else if (number < 1024) {
        buf += '000000';
      } else if (number < 32768) {
        buf += '00000';
      } else if (number < 1048576) {
        buf += '0000';
      } else if (number < 33554432) {
        buf += '000';
      } else if (number < 1073741824) {
        buf += '00';
      } else if (number < 34359738368) {
        buf += '0';
      }
      buf += number.toString(32);
    }

    return buf;
  };


  function parseToken(tokenString, website) {
    var websiteBytes = helpers.stringToByteArray(website);
    var tokenBytes = [];
    var i = 0;
    var j = 0;

    for (; i < tokenString.length; i += 8, j += 5) {
      var number = new BigInteger(
        tokenString.substring(i, i + 8),
        32
      );
      var part = helpers.hexStringToByteArray(number.toRadix(16));

      tokenBytes[j] = part[4];
      tokenBytes[j + 1] = part[3];
      tokenBytes[j + 2] = part[2];
      tokenBytes[j + 3] = part[1];
      tokenBytes[j + 4] = part[0];
    }

    if (i != 160) {
      return new Error('tokenString parsed to invalid size');
    }
    var publicKey = [];
    publicKey = tokenBytes.slice(0, 32);
    var timebytes = [
      tokenBytes[32],
      tokenBytes[33],
      tokenBytes[34],
      tokenBytes[35],
    ];

    var timestamp = helpers.byteArrayToIntVal(timebytes);
    var signature = tokenBytes.slice(36, 100);
    var data = websiteBytes.concat(tokenBytes.slice(0, 36));
    var isValid = verifyBytes(signature, data, publicKey);

    var ret = {};
    ret.isValid = isValid;
    ret.timestamp = timestamp;
    ret.publicKey = helpers.byteArrayToHexString(publicKey);
    ret.accountRS = account.publicKeyToAccountId(ret.publicKey);

    return ret;
  };


  function areByteArraysEqual(bytes1, bytes2) {
    if (bytes1.length !== bytes2.length) {
      return false;
    }
    for (var i = 0; i < bytes1.length; ++i) {
      if (bytes1[i] !== bytes2[i]) {
        return false;
      }
    }
    return true;
  };


  function verifyBytes(signature, message, publicKey) {
    var v = signature.slice(0, 32);
    var h = signature.slice(32);
    var y = Buffer.from(
      curve25519.verify(v, h, publicKey)
    );
    var m = Buffer.from(
      helpers.simpleHash(message)
    );
    var hash = crypto.createHash('sha256');
    hash.update(m);
    hash.update(y);
    var h2 = hash.digest();
    return areByteArraysEqual(h, h2);
  };


  module.exports = {
    createToken: createToken,
    parseToken: parseToken,
  };


})();
