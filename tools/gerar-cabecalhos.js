// Gera site/vercel.json com os cabeçalhos de segurança do site.
// Rode depois de qualquer mudança nos <script> internos do index.html: node tools/gerar-cabecalhos.js
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const site = path.join(__dirname, '..', 'site');
const html = fs.readFileSync(path.join(site, 'index.html'), 'utf8');
const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`);
const SB = 'yhekjbxrsxvmqiloxxzx.supabase.co';
const csp = [
  "default-src 'self'",
  `script-src 'self' https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.49.4/ https://cdn.jsdelivr.net/npm/exceljs@4.4.0/ ${hashes.join(' ')}`,
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  `img-src 'self' data: blob: https://${SB}`,
  `connect-src 'self' https://${SB} wss://${SB}`,
  "manifest-src 'self'", "worker-src 'self' blob:", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'", 'upgrade-insecure-requests',
].join('; ');
const cfg = {
  buildCommand: 'sh build.sh', outputDirectory: 'public', installCommand: '',
  headers: [{source: '/(.*)', headers: [
    {key: 'Content-Security-Policy', value: csp},
    {key: 'X-Content-Type-Options', value: 'nosniff'},
    {key: 'X-Frame-Options', value: 'DENY'},
    {key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin'},
    {key: 'Permissions-Policy', value: 'camera=(self), microphone=(), geolocation=(), payment=(), usb=()'},
    {key: 'Cross-Origin-Opener-Policy', value: 'same-origin'},
  ]}],
};
fs.writeFileSync(path.join(site, 'vercel.json'), JSON.stringify(cfg, null, 2) + '\n');
console.log(`site/vercel.json gerado: ${hashes.length} scripts internos autorizados`);
