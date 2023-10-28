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
 * Copyright (C) 2011-2012  Joshua M. Clulow <josh@sysmgr.org>
 */

var $ = require('./common');

/*
 * Generate the LM Hash
 */
function lmhashbuf(inputstr)
{
  let pwBuffer = new Buffer.alloc(14),
    magicKey = new Buffer.from('KGS!@#$%', 'ascii');

  if (inputstr.length > 14) {
    inputstr = inputstr.slice(0, 14);
  }

  pwBuffer.fill(0);
  pwBuffer.write(inputstr.toUpperCase(), 0, 'ascii');

  return Buffer.from([...$.calculateDES(pwBuffer.slice(0, 7), magicKey), ...$.calculateDES(pwBuffer.slice(7), magicKey)]);
}

function nthashbuf(inputstr)
{
  return $.calculateMD4(inputstr)
}

function lmhash(is)
{
  return $.bintohex(lmhashbuf(is));
}

function nthash(is)
{
  return $.bintohex(nthashbuf(is));
}

module.exports.nthashbuf = nthashbuf;
module.exports.lmhashbuf = lmhashbuf;

module.exports.nthash = nthash;
module.exports.lmhash = lmhash;
