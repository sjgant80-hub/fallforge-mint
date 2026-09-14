#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
const kernel = readFileSync(new URL('./kernel.mjs', import.meta.url), 'utf8')
  .replace(/^export /gm, '').replace(/\r\n/g, '\n').trimEnd();
const page = readFileSync(new URL('./index.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const BEGIN = '// ⟦KERNEL-BEGIN⟧ generated from kernel.mjs by make-page.mjs — do not edit here';
const END = '// ⟦KERNEL-END⟧';
const a = page.indexOf(BEGIN), b = page.indexOf(END);
if (a === -1 || b === -1 || b < a) { console.error('markers missing'); process.exit(1); }
writeFileSync(new URL('./index.html', import.meta.url), page.slice(0, a + BEGIN.length) + '\n' + kernel + '\n' + page.slice(b));
console.log('kernel injected: ' + kernel.length + ' chars');
