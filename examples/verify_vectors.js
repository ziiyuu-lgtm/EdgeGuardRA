/* Test vectors for flat EdgeGuardRA messages. Public fixture keys only.
 * This is an interoperability example, not a general canonical JSON standard.
 * Requires Node.js. The Python toolkit itself does not require Node.js.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const input = JSON.parse(fs.readFileSync(path.join(__dirname, 'signature_vectors.json'), 'utf8'));
function canonicalFlat(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('expected object');
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    const v = value[key];
    if (!(typeof v === 'string' || (typeof v === 'number' && Number.isSafeInteger(v)))) {
      throw new Error('only string and safe integer fields are supported');
    }
    sorted[key] = v;
  }
  // Match Python ensure_ascii=True, including both UTF-16 surrogate code units.
  return JSON.stringify(sorted).replace(/[\u007f-\uffff]/g,
    ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
}
for (const v of input.vectors) {
  const canonical = canonicalFlat(v.payload);
  const mac = crypto.createHmac('sha256', Buffer.from(v.key_hex, 'hex')).update(canonical, 'ascii').digest('hex');
  if (canonical !== v.canonical_ascii || mac !== v.hmac_sha256_hex) throw new Error('Mismatch: ' + v.name);
  process.stdout.write(v.name + ': OK\n');
}
