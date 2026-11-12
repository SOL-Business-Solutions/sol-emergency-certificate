// Builds data.json from the Google Form responses CSV.
//
//   node tools/build-data.mjs private/responses.csv [private/overrides.json]
//
// No phone number or name is written in clear. Each record is stored under an id
// derived from the phone number with PBKDF2, and the name is AES-GCM encrypted
// with a key derived from the same number, so a certificate opens only for the
// number it was registered with. The format must match assets/app.js.
//
// overrides.json (optional, keep it in private/): { "05XXXXXXXX": "الاسم الصحيح" }
// Set a number to null to leave it out.

import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const ITERATIONS = 300_000;
const [csvPath, overridesPath] = process.argv.slice(2);
if (!csvPath) {
  console.error('usage: node tools/build-data.mjs <responses.csv> [overrides.json]');
  process.exit(1);
}

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(f => f.trim()));
}

// Same rules as normalizePhone() in assets/app.js.
function normalizePhone(raw) {
  let d = String(raw)
    .replace(/[٠-٩]/g, c => String(c.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, c => String(c.charCodeAt(0) - 0x06f0))
    .replace(/\D/g, '');
  if (d.startsWith('00966')) d = d.slice(5);
  else if (d.startsWith('966')) d = d.slice(3);
  if (d.length === 9 && d.startsWith('5')) d = '0' + d;
  return /^05\d{8}$/.test(d) ? d : null;
}

const cleanName = s => s.replace(/\s+/g, ' ').trim();

const rows = parseCsv(readFileSync(csvPath, 'utf8').replace(/^﻿/, ''));
const header = rows.shift();
const nameCol = header.findIndex(h => h.trim() === 'الاسم');
const phoneCol = header.findIndex(h => h.trim() === 'رقم الجوال');
if (nameCol < 0 || phoneCol < 0) throw new Error(`unexpected header: ${header.join(' | ')}`);

const byPhone = new Map();   // later submissions replace earlier ones
const invalid = [];
const conflicts = new Map();
for (const r of rows) {
  const name = cleanName(r[nameCol] ?? '');
  const phone = normalizePhone(r[phoneCol] ?? '');
  if (!phone) { invalid.push(`${r[phoneCol]} | ${name}`); continue; }
  if (!name) continue;
  const prev = byPhone.get(phone);
  if (prev && prev !== name) conflicts.set(phone, new Set([...(conflicts.get(phone) ?? [prev]), name]));
  byPhone.set(phone, name);
}

if (overridesPath) {
  const overrides = JSON.parse(readFileSync(overridesPath, 'utf8'));
  for (const [raw, name] of Object.entries(overrides)) {
    const phone = normalizePhone(raw);
    if (!phone) throw new Error(`override has an invalid phone: ${raw}`);
    if (name === null) byPhone.delete(phone);
    else byPhone.set(phone, cleanName(name));
    conflicts.delete(phone);
  }
}

const enc = new TextEncoder();
const b64 = buf => Buffer.from(buf).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16));

async function deriveRecordKey(phone) {
  const base = await crypto.subtle.importKey('raw', enc.encode(phone), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, 384));
  const id = Buffer.from(bits.slice(0, 16)).toString('hex');
  const key = await crypto.subtle.importKey('raw', bits.slice(16, 48), 'AES-GCM', false, ['encrypt']);
  return { id, key };
}

const records = {};
for (const [phone, name] of byPhone) {
  const { id, key } = await deriveRecordKey(phone);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // Pad to a fixed size so the ciphertext length says nothing about the name length.
  const plain = new Uint8Array(256).fill(0x20);
  const json = enc.encode(JSON.stringify({ n: name }));
  if (json.length > plain.length) throw new Error(`name too long: ${name}`);
  plain.set(json);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv); blob.set(ct, iv.length);
  records[id] = b64(blob);
}

// Shuffle so the file order says nothing about submission order.
const entries = Object.entries(records);
for (let i = entries.length - 1; i > 0; i--) {
  const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
  [entries[i], entries[j]] = [entries[j], entries[i]];
}
const shuffled = Object.fromEntries(entries);
writeFileSync(new URL('../data.json', import.meta.url),
  JSON.stringify({ v: 1, iterations: ITERATIONS, salt: b64(salt), records: shuffled }) + '\n');

console.log(`wrote data.json: ${Object.keys(records).length} certificates from ${rows.length} responses`);
if (invalid.length) console.log(`\nskipped, phone is not 05XXXXXXXX:\n  ${invalid.join('\n  ')}`);
if (conflicts.size) {
  console.log('\nsame phone, different names (latest submission used; fix in overrides.json):');
  for (const [p, names] of conflicts) console.log(`  ${p}: ${[...names].join('  ←→  ')}`);
}
const latin = [...byPhone.values()].filter(n => /[A-Za-z]/.test(n));
if (latin.length) console.log(`\nnames written in Latin letters:\n  ${latin.join('\n  ')}`);
