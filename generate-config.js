#!/usr/bin/env node
/* ==========================================================================
   generate-config.js — baca .env lalu hasilkan config.js untuk browser.
   (Site ini statis tanpa build server, jadi browser tidak bisa membaca .env;
   skrip ini menyuntik nilai ke window.MISIPULSA_CONFIG sebelum sistem.js.)

   Cara pakai:
     1. Isi .env  (lihat .env.example)
     2. node generate-config.js
     3. config.js hasil generate JANGAN dicommit (sudah di .gitignore);
        jalankan ulang skrip setiap kali .env berubah, termasuk sebelum deploy.
   ========================================================================== */
'use strict';
const fs = require('fs');
const path = require('path');

function parseEnv(file) {
    const out = {};
    if (!fs.existsSync(file)) return out;
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq === -1) continue;
        const key = line.slice(0, eq).trim();
        let val = line.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
        } else {
            const hash = val.indexOf(' #');
            if (hash !== -1) val = val.slice(0, hash).trim();
        }
        out[key] = val;
    }
    return out;
}

const env = parseEnv(path.join(__dirname, '.env'));
const supabaseUrl = (env.SUPABASE_URL || '').trim();
const supabaseAnonKey = (env.SUPABASE_ANON_KEY || '').trim();

const content = `/* DIBUAT OTOMATIS oleh generate-config.js — jangan edit manual.
   Sumber: .env (jangan dicommit). Jalankan ulang: node generate-config.js */
window.MISIPULSA_CONFIG = {
    supabaseUrl: ${JSON.stringify(supabaseUrl)},
    supabaseAnonKey: ${JSON.stringify(supabaseAnonKey)}
};
`;

fs.writeFileSync(path.join(__dirname, 'config.js'), content);

if (supabaseUrl && supabaseAnonKey) {
    console.log('config.js dibuat — kredensial Supabase TERISI (mode server).');
} else {
    console.log('config.js dibuat — kredensial masih kosong (app tetap mode demo). Isi .env lalu jalankan ulang.');
}
