const { default: axios } = require("axios");

const sha1 = (function () {
  /*
   * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
   * in FIPS 180-1
   * Version 2.2 Copyright Paul Johnston 2000 - 2009.
   * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
   * Distributed under the BSD License
   * See http://pajhome.org.uk/crypt/md5 for details.
   */

  // Convert a raw string to a hex string
  function rawToHex(raw) {
    var hex = "";
    var hexChars = "0123456789abcdef";
    for (var i = 0; i < raw.length; i++) {
      var c = raw.charCodeAt(i);
      hex += hexChars.charAt((c >>> 4) & 0x0f) + hexChars.charAt(c & 0x0f);
    }
    return hex;
  }

  // Calculate the SHA1 of a raw string
  function sha1Raw(raw) {
    return binaryToRaw(sha1Binary(rawToBinary(raw), raw.length * 8));
  }

  /*
   * Convert an array of big-endian words to a string
   */
  function binaryToRaw(bin) {
    var raw = "";
    for (var i = 0, il = bin.length * 32; i < il; i += 8) {
      raw += String.fromCharCode((bin[i >> 5] >>> (24 - (i % 32))) & 0xff);
    }
    return raw;
  }

  /*
   * Calculate the SHA-1 of an array of big-endian words, and a bit length
   */
  function sha1Binary(bin, len) {
    // append padding
    bin[len >> 5] |= 0x80 << (24 - (len % 32));
    bin[(((len + 64) >> 9) << 4) + 15] = len;

    var w = new Array(80);
    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;
    var e = -1009589776;

    for (var i = 0, il = bin.length; i < il; i += 16) {
      var _a = a;
      var _b = b;
      var _c = c;
      var _d = d;
      var _e = e;

      for (var j = 0; j < 80; j++) {
        if (j < 16) {
          w[j] = bin[i + j];
        } else {
          w[j] = _rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        }
        var t = _add(
          _add(_rotateLeft(a, 5), _ft(j, b, c, d)),
          _add(_add(e, w[j]), _kt(j))
        );
        e = d;
        d = c;
        c = _rotateLeft(b, 30);
        b = a;
        a = t;
      }

      a = _add(a, _a);
      b = _add(b, _b);
      c = _add(c, _c);
      d = _add(d, _d);
      e = _add(e, _e);
    }
    return [a, b, c, d, e];
  }

  // Add integers, wrapping at 2^32. This uses 16-bit operations internally
  // to work around bugs in some JS interpreters.
  function _add(x, y) {
    var lsw = (x & 0xffff) + (y & 0xffff);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }

  /*
   * Bitwise rotate a 32-bit number to the left.
   */
  function _rotateLeft(n, count) {
    return (n << count) | (n >>> (32 - count));
  }

  /*
   * Perform the appropriate triplet combination function for the current
   * iteration
   */
  function _ft(t, b, c, d) {
    if (t < 20) {
      return (b & c) | (~b & d);
    } else if (t < 40) {
      return b ^ c ^ d;
    } else if (t < 60) {
      return (b & c) | (b & d) | (c & d);
    } else {
      return b ^ c ^ d;
    }
  }

  /*
   * DeterMine the appropriate additive constant for the current iteration
   */
  function _kt(t) {
    if (t < 20) {
      return 1518500249;
    } else if (t < 40) {
      return 1859775393;
    } else if (t < 60) {
      return -1894007588;
    } else {
      return -899497514;
    }
  }

  // Convert a raw string to an array of big-endian words.
  // Characters >255 have their high-byte silently ignored.
  function rawToBinary(raw) {
    var binary = new Array(raw.length >> 2);
    for (var i = 0, il = binary.length; i < il; i++) {
      binary[i] = 0;
    }
    for (i = 0, il = raw.length * 8; i < il; i += 8) {
      binary[i >> 5] |= (raw.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
    }
    return binary;
  }

  // Encode a string as UTF-8.
  // For efficiency, this assumes the input is valid UTF-16.
  function stringToRaw(string) {
    var raw = "",
      x,
      y;
    var i = -1;
    var il = string.length;
    while (++i < il) {
      // decode UTF-16 surrogate pairs
      x = string.charCodeAt(i);
      y = i + 1 < il ? string.charCodeAt(i + 1) : 0;
      if (0xd800 <= x && x <= 0xdbff && 0xdc00 <= y && y <= 0xdfff) {
        x = 0x10000 + ((x & 0x03ff) << 10) + (y & 0x03ff);
        ++i;
      }
      // encode output as UTF-8
      if (x <= 0x7f) {
        raw += String.fromCharCode(x);
      } else if (x <= 0x7ff) {
        raw += String.fromCharCode(
          0xc0 | ((x >>> 6) & 0x1f),
          0x80 | (x & 0x3f)
        );
      } else if (x <= 0xffff) {
        raw += String.fromCharCode(
          0xe0 | ((x >>> 12) & 0x0f),
          0x80 | ((x >>> 6) & 0x3f),
          0x80 | (x & 0x3f)
        );
      } else if (x <= 0x1fffff) {
        raw += String.fromCharCode(
          0xf0 | ((x >>> 18) & 0x07),
          0x80 | ((x >>> 12) & 0x3f),
          0x80 | ((x >>> 6) & 0x3f),
          0x80 | (x & 0x3f)
        );
      }
    }
    return raw;
  }

  // Calculate the HMAC-SHA1 of a key and some data (raw strings)
  function hmacRaw(key, data) {
    var binaryKey = rawToBinary(key);
    if (binaryKey.length > 16) {
      binaryKey = sha1Binary(binaryKey, key.length * 8);
    }
    var ipad = new Array(16);
    var opad = new Array(16);
    for (var i = 0; i < 16; i++) {
      ipad[i] = binaryKey[i] ^ 0x36363636;
      opad[i] = binaryKey[i] ^ 0x5c5c5c5c;
    }
    var hash = sha1Binary(
      ipad.concat(rawToBinary(data)),
      512 + data.length * 8
    );
    return binaryToRaw(sha1Binary(opad.concat(hash), 512 + 160));
  }

  return {
    sha1: function (s) {
      return rawToHex(sha1Raw(stringToRaw(s)));
    },

    sha1Hex: function (value) {
      return rawToHex(sha1Raw(this.hexToString(value)));
    },

    hmac: function (k, d) {
      return rawToHex(hmacRaw(stringToRaw(k), stringToRaw(d)));
    },

    hexToString: function (hex) {
      var str = "";
      for (var i = 0, il = hex.length; i < il; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
      }
      return str;
    }
  };
})();

async function httpGet(theUrl) {
  const result = await axios.get(theUrl);
  return result.data;
}

async function httpPost(theUrl) {
  const result = await axios.post(theUrl);
  return result.data;
}

// function getRandomInt(min, max) {
//   min = Math.ceil(min);
//   max = Math.floor(max);
//   return Math.floor(Math.random() * (max - min)) + min;
// }

function roundTo(precision, value) {
  const power_of_ten = 10 * (precision * precision);
  return Math.round(value * power_of_ten) / power_of_ten;
}

// function getPrefix(value) {
//   value = parseFloat(value);
//   if (value / 1000000 > 0.5) value = roundTo(4, value / 1000000) + " M";
//   else if (value / 1000 > 0.5) value = roundTo(3, value / 1000) + " k";
//   else value = roundTo(2, value) + " ";
//   return value;
// }

let accepted = 0;
let rejected = 0;

async function Mine() {
  const username = "frenow";
  const key = "None";
  const base_url = "http://51.15.127.80";
  const diff = 100;

  try {
    const job = await httpGet(
      base_url +
        "/legacy_job?u=" +
        username +
        "&i=" +
        "NetFront 3.4" +
        "&nocache=" +
        new Date().getTime()
    );

    console.log(job);

    const last_block_hash = job.split(",")[0];
    const expected_hash = job.split(",")[1];
    const difficulty = job.split(",")[2];

    const timeStart = new Date().getTime();
    for (var result = 0; result < difficulty * diff; result++) {
      const current_hash = sha1.sha1(last_block_hash + result);
      if (current_hash === expected_hash) {
        break;
      }
    }
    const timeStop = new Date().getTime();

    const timeDiff = (timeStop - timeStart) / 1000;
    const sharetime = roundTo(2, timeDiff);
    const hashrate = result / timeDiff;

    const feedback = await httpPost(
      base_url +
        "/legacy_job?u=" +
        username +
        "&r=" +
        result +
        "&k=" +
        key +
        "&s=Official Mini Miner 3.2" +
        "&j=" +
        expected_hash +
        "&i=" +
        "NetFront 3.4" +
        "&h=" +
        hashrate +
        "&b=" +
        sharetime +
        "&nocache=" +
        new Date().getTime()
    );

    if (feedback === "GOOD") {
      accepted++;
    } else {
      rejected++;
    }
    console.log(`${feedback} (+${accepted}) (-${rejected}) ${new Date()}`);

    Mine(username);
  } catch (err) {
    console.log(err);
  }
}

function startMining() {
  setTimeout(function () {
    console.log("Mining started");
  }, 10 * 60 * 1000);
  Mine();
}

console.log("Starting mining by nodejs");

setTimeout(function () {
    startMining();
}, 1000);
