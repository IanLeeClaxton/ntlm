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

var $ = require('./common');
var { lmhashbuf, nthashbuf } = require('./smbhash');
var { URL } = require('url');

function encodeType1(hostname, ntdomain) {
  hostname = hostname.toUpperCase();
  ntdomain = ntdomain.toUpperCase();
  var hostnamelen = Buffer.byteLength(hostname, 'ascii');
  var ntdomainlen = Buffer.byteLength(ntdomain, 'ascii');

  var pos = 0;
  var buf = Buffer.alloc(32 + hostnamelen + ntdomainlen);

  buf.write('NTLMSSP', pos, 7, 'ascii'); // byte protocol[8];
  pos += 7;
  buf.writeUInt8(0, pos);
  pos++;

  buf.writeUInt8(0x01, pos); // byte type;
  pos++;

  buf.fill(0x00, pos, pos + 3); // byte zero[3];
  pos += 3;

  buf.writeUInt16LE(0xb203, pos); // short flags;
  pos += 2;

  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(ntdomainlen, pos); // short dom_len;
  pos += 2;
  buf.writeUInt16LE(ntdomainlen, pos); // short dom_len;
  pos += 2;

  var ntdomainoff = 0x20 + hostnamelen;
  buf.writeUInt16LE(ntdomainoff, pos); // short dom_off;
  pos += 2;

  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(hostnamelen, pos); // short host_len;
  pos += 2;
  buf.writeUInt16LE(hostnamelen, pos); // short host_len;
  pos += 2;

  buf.writeUInt16LE(0x20, pos); // short host_off;
  pos += 2;

  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.write(hostname, 0x20, hostnamelen, 'ascii');
  buf.write(ntdomain, ntdomainoff, ntdomainlen, 'ascii');

  return buf;
}

/*
 * 
 */
function decodeType2(buf)
{
  var proto = buf.toString('ascii', 0, 7);
  if (buf[7] !== 0x00 || proto !== 'NTLMSSP')
    throw new Error('magic was not NTLMSSP');

  var type = buf.readUInt8(8);
  if (type !== 0x02)
    throw new Error('message was not NTLMSSP type 0x02');

  //var msg_len = buf.readUInt16LE(16);

  //var flags = buf.readUInt16LE(20);

  var nonce = buf.slice(24, 32);
  return nonce;
}

function encodeType3(username, hostname, ntdomain, nonce, password) {
  hostname = hostname.toUpperCase();
  ntdomain = ntdomain.toUpperCase();

  const challenge = new Buffer.from(nonce, 'ascii')

  var lmr = makeResponse(lmhashbuf(password), challenge);
  var ntr = makeResponse(nthashbuf(password), challenge);

  var usernamelen = Buffer.byteLength(username, 'ucs2');
  var hostnamelen = Buffer.byteLength(hostname, 'ucs2');
  var ntdomainlen = Buffer.byteLength(ntdomain, 'ucs2');
  var lmrlen = 0x18;
  var ntrlen = 0x18;

  var ntdomainoff = 0x40;
  var usernameoff = ntdomainoff + ntdomainlen;
  var hostnameoff = usernameoff + usernamelen;
  var lmroff = hostnameoff + hostnamelen;
  var ntroff = lmroff + lmrlen;

  var pos = 0;
  var msg_len = 64 + ntdomainlen + usernamelen + hostnamelen + lmrlen + ntrlen;
  var buf = Buffer.alloc(msg_len);

  buf.write('NTLMSSP', pos, 7, 'ascii'); // byte protocol[8];
  pos += 7;
  buf.writeUInt8(0, pos);
  pos++;

  buf.writeUInt8(0x03, pos); // byte type;
  pos++;

  buf.fill(0x00, pos, pos + 3); // byte zero[3];
  pos += 3;

  buf.writeUInt16LE(lmrlen, pos); // short lm_resp_len;
  pos += 2;
  buf.writeUInt16LE(lmrlen, pos); // short lm_resp_len;
  pos += 2;
  buf.writeUInt16LE(lmroff, pos); // short lm_resp_off;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(ntrlen, pos); // short nt_resp_len;
  pos += 2;
  buf.writeUInt16LE(ntrlen, pos); // short nt_resp_len;
  pos += 2;
  buf.writeUInt16LE(ntroff, pos); // short nt_resp_off;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(ntdomainlen, pos); // short dom_len;
  pos += 2;
  buf.writeUInt16LE(ntdomainlen, pos); // short dom_len;
  pos += 2;
  buf.writeUInt16LE(ntdomainoff, pos); // short dom_off;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(usernamelen, pos); // short user_len;
  pos += 2;
  buf.writeUInt16LE(usernamelen, pos); // short user_len;
  pos += 2;
  buf.writeUInt16LE(usernameoff, pos); // short user_off;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(hostnamelen, pos); // short host_len;
  pos += 2;
  buf.writeUInt16LE(hostnamelen, pos); // short host_len;
  pos += 2;
  buf.writeUInt16LE(hostnameoff, pos); // short host_off;
  pos += 2;
  buf.fill(0x00, pos, pos + 6); // byte zero[6];
  pos += 6;

  buf.writeUInt16LE(msg_len, pos); // short msg_len;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.writeUInt16LE(0x8201, pos); // short flags;
  pos += 2;
  buf.fill(0x00, pos, pos + 2); // byte zero[2];
  pos += 2;

  buf.write(ntdomain, ntdomainoff, ntdomainlen, 'ucs2');
  buf.write(username, usernameoff, usernamelen, 'ucs2');
  buf.write(hostname, hostnameoff, hostnamelen, 'ucs2');
  lmr.copy(buf, lmroff, 0, lmrlen);
  ntr.copy(buf, ntroff, 0, ntrlen);

  return buf;
}

function makeResponse(lmhash, challenge)
{
  let buf = new Buffer.alloc(24), 
    pwBuffer = new Buffer.alloc(21).fill(0);

  lmhash.copy(pwBuffer);

  $.calculateDES(pwBuffer.slice(0, 7), challenge).copy(buf);
  $.calculateDES(pwBuffer.slice(7, 14), challenge).copy(buf, 8);
  $.calculateDES(pwBuffer.slice(14), challenge).copy(buf, 16);

  return buf;
}

exports.encodeType1 = encodeType1;
exports.decodeType2 = decodeType2;
exports.encodeType3 = encodeType3;

// Convenience methods.

exports.challengeHeader = function (hostname, domain) {
  return 'NTLM ' + exports.encodeType1(hostname, domain).toString('base64');
};

exports.responseHeader = function (res, url, domain, username, password) {
  const serverNonce = Buffer.from((res.headers['www-authenticate'].match(/^NTLM\s+(.+?)(,|\s+|$)/) || [])[1], 'base64');
  const hostname = new URL(url).hostname;
  return 'NTLM ' + exports.encodeType3(username, hostname, domain, exports.decodeType2(serverNonce), password).toString('base64');
};

// Import smbhash module.

exports.smbhash = require('./smbhash');
