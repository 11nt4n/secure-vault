/* Small self-contained QR encoder for offline TOTP provisioning.
 * QR Code Version 10, error correction L. No provisioning secret leaves the browser.
 */
const VERSION = 10;
const SIZE = VERSION * 4 + 17;
const DATA_CODEWORDS = 274;
const BLOCKS = [68, 68, 69, 69];
const ECC_PER_BLOCK = 18;

function gfMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}
function rsGenerator(degree) {
  let result = [1];
  let root = 1;
  for (let i = 0; i < degree; i++) {
    const next = new Array(result.length + 1).fill(0);
    for (let j = 0; j < result.length; j++) {
      next[j] ^= result[j];
      next[j + 1] ^= gfMultiply(result[j], root);
    }
    result = next;
    root = gfMultiply(root, 2);
  }
  return result;
}
function rsRemainder(data, degree) {
  const gen = rsGenerator(degree);
  const work = [...data, ...new Array(degree).fill(0)];
  for (let i = 0; i < data.length; i++) {
    const factor = work[i];
    if (!factor) continue;
    for (let j = 0; j < gen.length; j++) work[i + j] ^= gfMultiply(gen[j], factor);
  }
  return work.slice(data.length);
}
function appendBits(target, value, length) {
  for (let i = length - 1; i >= 0; i--) target.push((value >>> i) & 1);
}
function createCodewords(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const capacity = DATA_CODEWORDS * 8;
  const bits = [];
  appendBits(bits, 0b0100, 4); // Byte mode
  appendBits(bits, bytes.length, 16); // Byte count for versions 10-40
  for (const byte of bytes) appendBits(bits, byte, 8);
  if (bits.length > capacity) throw new Error('Data OTP terlalu panjang untuk dibuat QR. Gunakan secret manual di bawah.');
  appendBits(bits, 0, Math.min(4, capacity - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j];
    data.push(value);
  }
  let pad = 0;
  while (data.length < DATA_CODEWORDS) data.push((pad++ % 2) ? 0x11 : 0xec);

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (const length of BLOCKS) {
    const block = data.slice(offset, offset + length);
    offset += length;
    dataBlocks.push(block);
    ecBlocks.push(rsRemainder(block, ECC_PER_BLOCK));
  }
  const result = [];
  for (let i = 0; i < Math.max(...BLOCKS); i++) {
    for (const block of dataBlocks) if (i < block.length) result.push(block[i]);
  }
  for (let i = 0; i < ECC_PER_BLOCK; i++) for (const block of ecBlocks) result.push(block[i]);
  return result;
}
function bchRemainder(value, polynomial) {
  let degree = 31 - Math.clz32(polynomial);
  let v = value;
  while (31 - Math.clz32(v) >= degree) v ^= polynomial << ((31 - Math.clz32(v)) - degree);
  return v;
}
function blankMatrix() { return Array.from({ length: SIZE }, () => new Array(SIZE).fill(null)); }
function setFinder(matrix, row, col) {
  for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
    const y = row + r, x = col + c;
    if (y < 0 || x < 0 || y >= SIZE || x >= SIZE) continue;
    matrix[y][x] = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
      (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
      (r >= 2 && r <= 4 && c >= 2 && c <= 4);
  }
}
function setAlignment(matrix, row, col) {
  for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) {
    matrix[row + r][col + c] = Math.max(Math.abs(r), Math.abs(c)) !== 1;
  }
}
function setupFunctions(matrix) {
  setFinder(matrix, 0, 0);
  setFinder(matrix, SIZE - 7, 0);
  setFinder(matrix, 0, SIZE - 7);
  const positions = [6, 28, 50];
  for (const row of positions) for (const col of positions) {
    if (matrix[row][col] === null) setAlignment(matrix, row, col);
  }
  for (let i = 8; i < SIZE - 8; i++) {
    if (matrix[6][i] === null) matrix[6][i] = i % 2 === 0;
    if (matrix[i][6] === null) matrix[i][6] = i % 2 === 0;
  }
  // Version information (version 10), BCH polynomial 0x1f25.
  const versionBits = (VERSION << 12) | bchRemainder(VERSION << 12, 0x1f25);
  for (let i = 0; i < 18; i++) {
    const bit = ((versionBits >>> i) & 1) !== 0;
    matrix[Math.floor(i / 3)][i % 3 + SIZE - 11] = bit;
    matrix[i % 3 + SIZE - 11][Math.floor(i / 3)] = bit;
  }
}
function formatBits(mask) {
  const data = (0b01 << 3) | mask; // Error correction level L.
  return ((data << 10) | bchRemainder(data << 10, 0x537)) ^ 0x5412;
}
function placeFormat(matrix, mask) {
  const bits = formatBits(mask);
  for (let i = 0; i < 15; i++) {
    const bit = ((bits >>> i) & 1) !== 0;
    if (i < 6) matrix[i][8] = bit;
    else if (i < 8) matrix[i + 1][8] = bit;
    else matrix[SIZE - 15 + i][8] = bit;

    if (i < 8) matrix[8][SIZE - i - 1] = bit;
    else if (i < 9) matrix[8][15 - i] = bit;
    else matrix[8][15 - i - 1] = bit;
  }
  matrix[SIZE - 8][8] = true;
}
const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
];
function mapData(matrix, codewords, mask) {
  let row = SIZE - 1, direction = -1, bitIndex = 7, byteIndex = 0;
  const maskFn = MASKS[mask];
  for (let col = SIZE - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    while (true) {
      for (let offset = 0; offset < 2; offset++) {
        const x = col - offset;
        if (matrix[row][x] !== null) continue;
        let dark = false;
        if (byteIndex < codewords.length) dark = ((codewords[byteIndex] >>> bitIndex) & 1) !== 0;
        if (maskFn(row, x)) dark = !dark;
        matrix[row][x] = dark;
        bitIndex--;
        if (bitIndex < 0) { byteIndex++; bitIndex = 7; }
      }
      row += direction;
      if (row < 0 || row >= SIZE) { row -= direction; direction = -direction; break; }
    }
  }
}
function penalty(matrix) {
  let score = 0;
  const scan = line => {
    let runColor = line[0], runLength = 1;
    for (let i = 1; i < line.length; i++) {
      if (line[i] === runColor) { runLength++; if (runLength === 5) score += 3; else if (runLength > 5) score++; }
      else { runColor = line[i]; runLength = 1; }
    }
    const s = line.map(v => v ? '1' : '0').join('');
    for (let i = 0; i <= s.length - 11; i++) {
      const p = s.slice(i, i + 11);
      if (p === '10111010000' || p === '00001011101') score += 40;
    }
  };
  for (let r = 0; r < SIZE; r++) scan(matrix[r]);
  for (let c = 0; c < SIZE; c++) scan(matrix.map(row => row[c]));
  for (let r = 0; r < SIZE - 1; r++) for (let c = 0; c < SIZE - 1; c++) {
    const v = matrix[r][c];
    if (matrix[r][c + 1] === v && matrix[r + 1][c] === v && matrix[r + 1][c + 1] === v) score += 3;
  }
  const dark = matrix.reduce((sum, row) => sum + row.filter(Boolean).length, 0);
  score += Math.floor(Math.abs((dark * 100 / (SIZE * SIZE)) - 50) / 5) * 10;
  return score;
}
export function createQrMatrix(text) {
  const codewords = createCodewords(String(text));
  const base = blankMatrix();
  setupFunctions(base);
  let best = null, bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const candidate = base.map(row => row.slice());
    placeFormat(candidate, mask);
    mapData(candidate, codewords, mask);
    const p = penalty(candidate);
    if (p < bestPenalty) { bestPenalty = p; best = candidate; }
  }
  return best;
}
export function createQrSvg(text, cellSize = 4, margin = 4) {
  const matrix = createQrMatrix(text);
  const dimension = (SIZE + margin * 2) * cellSize;
  let path = '';
  for (let r = 0; r < SIZE; r++) for (let c = 0; c < SIZE; c++) {
    if (matrix[r][c]) path += `M${(c + margin) * cellSize},${(r + margin) * cellSize}h${cellSize}v${cellSize}h-${cellSize}z`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${dimension}" height="${dimension}" viewBox="0 0 ${dimension} ${dimension}" role="img" aria-label="QR code aktivasi OTP"><rect width="100%" height="100%" fill="#fff"/><path d="${path}" fill="#07101f"/></svg>`;
}
