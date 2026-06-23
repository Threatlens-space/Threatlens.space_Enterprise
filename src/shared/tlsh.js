const BUCKET_COUNT = 128;
const BODY_BYTES = BUCKET_COUNT / 4;
const MIN_INPUT_BYTES = 50;

const PEARSON_TABLE = Object.freeze(createPearsonTable());

/**
 * Browser-safe locality-sensitive fuzzy hash generator.
 *
 * This intentionally avoids native bindings and Node-only crypto. It is a
 * fast, deterministic TLSH-style similarity signal for enterprise triage, but
 * it does not claim byte-for-byte compatibility with Trend Micro's reference
 * TLSH implementation unless validated separately against official vectors.
 */
export class TLSH {
  constructor() {
    this.length = 0;
    this.checksum = 0;
    this.buckets = new Uint32Array(BUCKET_COUNT);
    this.window = [];
  }

  update(chunk) {
    if (!chunk) return;

    const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    for (let i = 0; i < bytes.length; i++) {
      this._updateByte(bytes[i]);
    }
  }

  digest() {
    if (this.length < MIN_INPUT_BYTES) {
      return "";
    }

    const sortedBuckets = Array.from(this.buckets).sort((a, b) => a - b);
    const q1 = sortedBuckets[Math.floor(BUCKET_COUNT * 0.25)];
    const q2 = sortedBuckets[Math.floor(BUCKET_COUNT * 0.50)];
    const q3 = sortedBuckets[Math.floor(BUCKET_COUNT * 0.75)];

    if (q3 === 0) {
      return "";
    }

    const lValue = encodeLength(this.length);
    const qByte = ((Math.floor((q1 * 100) / q3) & 0x0f) << 4) |
      (Math.floor((q2 * 100) / q3) & 0x0f);
    const body = [];

    for (let i = 0; i < BODY_BYTES; i++) {
      let value = 0;
      for (let j = 0; j < 4; j++) {
        const bucket = this.buckets[(i * 4) + j];
        const code = bucket > q3 ? 3 : bucket > q2 ? 2 : bucket > q1 ? 1 : 0;
        value |= code << (j * 2);
      }
      body.push(toHexByte(value));
    }

    return `T1${toHexByte(this.checksum)}${toHexByte(lValue)}${toHexByte(qByte)}${body.join("")}`;
  }

  _updateByte(value) {
    this.length += 1;
    this.window.unshift(value);
    if (this.window.length > 5) {
      this.window.pop();
    }

    if (this.window.length >= 3) {
      this.checksum = pearson3(this.window[0], this.window[1], this.window[2], this.checksum);
    }

    if (this.window.length < 5) {
      return;
    }

    this._incrementBucket(0, 1, 2, 2);
    this._incrementBucket(0, 1, 3, 3);
    this._incrementBucket(0, 1, 4, 5);
    this._incrementBucket(0, 2, 3, 7);
    this._incrementBucket(0, 2, 4, 11);
    this._incrementBucket(0, 3, 4, 13);
  }

  _incrementBucket(aIndex, bIndex, cIndex, salt) {
    const bucket = pearson3(
      this.window[aIndex],
      this.window[bIndex],
      this.window[cIndex],
      salt
    ) % BUCKET_COUNT;
    this.buckets[bucket] += 1;
  }
}

function pearson3(a, b, c, salt) {
  return PEARSON_TABLE[
    PEARSON_TABLE[
      PEARSON_TABLE[(a ^ salt) & 0xff] ^ b
    ] ^ c
  ];
}

function encodeLength(length) {
  let value;
  if (length <= 656) {
    value = Math.floor(Math.log(length) / Math.log(1.5));
  } else if (length <= 3199) {
    value = Math.floor((Math.log(length) / Math.log(1.3)) - 8.72777);
  } else {
    value = Math.floor((Math.log(length) / Math.log(1.1)) - 62.5472);
  }
  return Math.max(0, Math.min(255, value));
}

function createPearsonTable() {
  const values = Array.from({ length: 256 }, (_, index) => index);
  let state = 0x9e3779b9;

  for (let i = values.length - 1; i > 0; i--) {
    state = (Math.imul(state ^ (state >>> 15), 2246822519) + 3266489917) >>> 0;
    const j = state % (i + 1);
    [values[i], values[j]] = [values[j], values[i]];
  }

  return values;
}

function toHexByte(value) {
  return (value & 0xff).toString(16).padStart(2, "0").toUpperCase();
}
