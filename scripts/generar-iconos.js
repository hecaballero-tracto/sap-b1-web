'use strict';

/**
 * Genera los iconos PWA (192x192 y 512x512) a partir de la silueta del tractor.
 *
 * Estrategia:
 *  1) Si `sharp` está instalado, convierte el SVG (public/img/tractor-icon.svg)
 *     a PNG en ambos tamaños.
 *  2) Si `sharp` no está disponible, escribe un PNG válido mínimo (1x1 blanco)
 *     como placeholder y avisa al usuario que instale `sharp` para obtener los
 *     iconos reales del tractor.
 *
 * Uso:
 *   node scripts/generar-iconos.js
 *
 * Instalación de sharp (opcional pero recomendada):
 *   npm install --save-dev sharp
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ICONS_DIR = path.join(ROOT, 'public', 'icons');
const SVG_PATH = path.join(ROOT, 'public', 'img', 'tractor-icon.svg');

const TARGETS = [
  { size: 192, file: 'icon-192.png' },
  { size: 512, file: 'icon-512.png' },
];

// PNG válido mínimo (1x1 blanco) usado como placeholder si `sharp` no está.
const PLACEHOLDER_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=';

function ensureIconsDir() {
  if (!fs.existsSync(ICONS_DIR)) {
    fs.mkdirSync(ICONS_DIR, { recursive: true });
  }
}

function writePlaceholder(target) {
  const buffer = Buffer.from(PLACEHOLDER_PNG_BASE64, 'base64');
  const outPath = path.join(ICONS_DIR, target.file);
  fs.writeFileSync(outPath, buffer);
  console.warn(
    `[generar-iconos] Placeholder escrito en ${outPath} (${target.size}x${target.size}). ` +
      'Instala "sharp" para generar los iconos reales del tractor.'
  );
}

async function generateWithSharp(sharp) {
  if (!fs.existsSync(SVG_PATH)) {
    throw new Error(`No se encontró el SVG fuente en: ${SVG_PATH}`);
  }

  const svgBuffer = fs.readFileSync(SVG_PATH);

  for (const target of TARGETS) {
    const outPath = path.join(ICONS_DIR, target.file);
    await sharp(svgBuffer, { density: 384 })
      .resize(target.size, target.size, {
        fit: 'contain',
        background: { r: 255, g: 255, b: 255, alpha: 1 },
      })
      .png()
      .toFile(outPath);
    console.log(
      `[generar-iconos] Generado ${outPath} (${target.size}x${target.size})`
    );
  }
}

async function main() {
  ensureIconsDir();

  let sharp = null;
  try {
    // eslint-disable-next-line global-require
    sharp = require('sharp');
  } catch (_) {
    sharp = null;
  }

  if (sharp) {
    try {
      await generateWithSharp(sharp);
      return;
    } catch (err) {
      console.error(
        '[generar-iconos] Error usando sharp, se usarán placeholders:',
        err.message
      );
    }
  }

  for (const target of TARGETS) {
    writePlaceholder(target);
  }
}

main().catch((err) => {
  console.error('[generar-iconos] Error inesperado:', err);
  process.exit(1);
});
