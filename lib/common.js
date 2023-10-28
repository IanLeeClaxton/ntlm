/*
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright (C) 2012  Joshua M. Clulow <josh@sysmgr.org>
 */

var { DES } = require('des.js');
var md4 = require('js-md4');

function zeroextend(str, len)
{
  while (str.length < len)
    str = '0' + str;
  return (str);
}

/*
 * Fix (odd) parity bits in a 64-bit DES key.
 */
function oddpar(buf)
{
  for (var j = 0; j < buf.length; j++) {
    var par = 1;
    for (var i = 1; i < 8; i++) {
      par = (par + ((buf[j] >> i) & 1)) % 2;
    }
    buf[j] |= par & 1;
  }
  return buf;
}

/*
 * Expand a 56-bit key buffer to the full 64-bits for DES.
 *
 * Based on code sample in:
 *    http://www.innovation.ch/personal/ronald/ntlm.html
 */
function expandkey(key56)
{
  var key64 = Buffer.alloc(8);

  key64[0] = key56[0] & 0xFE;
  key64[1] = ((key56[0] << 7) & 0xFF) | (key56[1] >> 1);
  key64[2] = ((key56[1] << 6) & 0xFF) | (key56[2] >> 2);
  key64[3] = ((key56[2] << 5) & 0xFF) | (key56[3] >> 3);
  key64[4] = ((key56[3] << 4) & 0xFF) | (key56[4] >> 4);
  key64[5] = ((key56[4] << 3) & 0xFF) | (key56[5] >> 5);
  key64[6] = ((key56[5] << 2) & 0xFF) | (key56[6] >> 6);
  key64[7] =  (key56[6] << 1) & 0xFF;

  return key64;
}

/*
 * Convert a binary string to a hex string
 */
function bintohex(bin)
{
  var buf = (Buffer.isBuffer(buf) ? buf : Buffer.from(bin, 'binary'));
  var str = buf.toString('hex').toUpperCase();
  return zeroextend(str, 32);
}

function calculateDES(key, message) {
  var desKey = new Buffer.alloc(8);
  desKey[0] = key[0] & 0xFE;
  desKey[1] = ((key[0] << 7) & 0xFF) | (key[1] >> 1);
  desKey[2] = ((key[1] << 6) & 0xFF) | (key[2] >> 2);
  desKey[3] = ((key[2] << 5) & 0xFF) | (key[3] >> 3);
  desKey[4] = ((key[3] << 4) & 0xFF) | (key[4] >> 4);
  desKey[5] = ((key[4] << 3) & 0xFF) | (key[5] >> 5);
  desKey[6] = ((key[5] << 2) & 0xFF) | (key[6] >> 6);
  desKey[7] = (key[6] << 1) & 0xFF;
  for (var i = 0; i < 8; i++) {
      var parity = 0;
      for (var j = 1; j < 8; j++) {
          parity += (desKey[i] >> j) % 2;
      }
      desKey[i] |= (parity % 2) === 0 ? 1 : 0;
  }
  var des = DES.create({ type: 'encrypt', key: desKey});
  return Buffer.from(des.update(message));
}

function calculateMD4(message) {
  var md4sum = md4.create();
  md4sum.update(new Buffer.from(message, 'ucs2'));
  return Buffer.from(md4sum.buffer());
}

module.exports.zeroextend = zeroextend;
module.exports.oddpar = oddpar;
module.exports.expandkey = expandkey;
module.exports.bintohex = bintohex;
module.exports.calculateDES = calculateDES;
module.exports.calculateMD4 = calculateMD4;
