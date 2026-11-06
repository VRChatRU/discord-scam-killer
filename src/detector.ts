import { join } from "node:path";
import sharp from "sharp";
import type { Sensitivity } from "./config.ts";
import { logger } from "./logger.ts";

export interface RgbColor {
  red: number;
  green: number;
  blue: number;
}

export interface ImageFingerprint {
  color: RgbColor;
  pHash: bigint;
}

export interface ReferenceProfile extends ImageFingerprint {
  sourcePath: string;
}

export interface DetectionResult {
  suspicious: boolean;
  confidence: number;
  imageCountPoints: number;
  colorPoints: number;
  pHashPoints: number;
  averageReferenceDistance: number;
  averagePHashDistance: number;
  pHashMatches: number;
  colors: RgbColor[];
}

interface NearestDistances {
  color: number;
  pHash: number;
}

export const MINIMUM_IMAGE_COUNT = 1;
export const MAXIMUM_IMAGE_COUNT = 8;
export const MAXIMUM_IMAGE_BYTES = 12 * 1024 * 1024;

const DEFAULT_SAMPLES_DIRECTORY = join(import.meta.dir, "..", "samples");
const SAMPLE_EXTENSION = /\.(?:avif|gif|jpe?g|png|tiff?|webp)$/i;
const SAMPLE_LOAD_CONCURRENCY = 4;

const NORMALIZED_IMAGE_SIZE = 64;
const NORMALIZED_PIXEL_COUNT = NORMALIZED_IMAGE_SIZE ** 2;
const PHASH_IMAGE_SIZE = 32;
const PHASH_FREQUENCY_SIZE = 8;
const COLOR_DISTANCE_RANGE = 70;
const PHASH_DISTANCE_RANGE = 16;
const PHASH_MATCH_DISTANCE = 8;
const COLOR_MAX_POINTS = 25;
const PHASH_MAX_POINTS = 45;

const CONFIDENCE_THRESHOLDS: Record<Sensitivity, number> = {
  strict: 90,
  balanced: 75,
  aggressive: 62,
};

// DCT lookup tables are identical for every image, so build them once.
const DCT_COSINES = Array.from(
  { length: PHASH_FREQUENCY_SIZE },
  (_, frequency) =>
    Float64Array.from({ length: PHASH_IMAGE_SIZE }, (_, position) =>
      Math.cos(
        ((2 * position + 1) * frequency * Math.PI) / (2 * PHASH_IMAGE_SIZE),
      ),
    ),
);
const DCT_FACTORS = Float64Array.from(
  { length: PHASH_FREQUENCY_SIZE },
  (_, frequency) =>
    frequency === 0
      ? Math.sqrt(1 / PHASH_IMAGE_SIZE)
      : Math.sqrt(2 / PHASH_IMAGE_SIZE),
);

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function pHashFromGrayscale(pixels: Float64Array): bigint {
  const coefficients = new Float64Array(
    PHASH_FREQUENCY_SIZE * PHASH_FREQUENCY_SIZE,
  );

  for (
    let verticalFrequency = 0;
    verticalFrequency < PHASH_FREQUENCY_SIZE;
    verticalFrequency += 1
  ) {
    const verticalCosines = DCT_COSINES[verticalFrequency];
    const verticalFactor = DCT_FACTORS[verticalFrequency];
    if (!verticalCosines || verticalFactor === undefined) {
      throw new Error("Invalid DCT lookup table");
    }

    for (
      let horizontalFrequency = 0;
      horizontalFrequency < PHASH_FREQUENCY_SIZE;
      horizontalFrequency += 1
    ) {
      const horizontalCosines = DCT_COSINES[horizontalFrequency];
      const horizontalFactor = DCT_FACTORS[horizontalFrequency];
      if (!horizontalCosines || horizontalFactor === undefined) {
        throw new Error("Invalid DCT lookup table");
      }

      let sum = 0;
      for (let y = 0; y < PHASH_IMAGE_SIZE; y += 1) {
        const verticalCosine = verticalCosines[y];
        if (verticalCosine === undefined) {
          continue;
        }

        for (let x = 0; x < PHASH_IMAGE_SIZE; x += 1) {
          const pixel = pixels[y * PHASH_IMAGE_SIZE + x];
          const horizontalCosine = horizontalCosines[x];
          if (pixel !== undefined && horizontalCosine !== undefined) {
            sum += pixel * horizontalCosine * verticalCosine;
          }
        }
      }

      coefficients[
        verticalFrequency * PHASH_FREQUENCY_SIZE + horizontalFrequency
      ] = verticalFactor * horizontalFactor * sum;
    }
  }

  // DC represents overall brightness. Excluding it makes pHash resilient to
  // global brightness changes.
  const comparableCoefficients = Array.from(coefficients.slice(1)).sort(
    (left, right) => left - right,
  );
  const median =
    comparableCoefficients[Math.floor(comparableCoefficients.length / 2)];
  if (median === undefined) {
    throw new Error("Could not calculate the pHash median");
  }

  let hash = 0n;
  for (let index = 1; index < coefficients.length; index += 1) {
    const coefficient = coefficients[index];
    if (coefficient !== undefined && coefficient > median) {
      hash |= 1n << BigInt(index);
    }
  }
  return hash;
}

export function hammingDistance(left: bigint, right: bigint): number {
  let difference = left ^ right;
  let distance = 0;
  while (difference !== 0n) {
    difference &= difference - 1n;
    distance += 1;
  }
  return distance;
}

export async function fingerprintImage(
  input: Uint8Array,
): Promise<ImageFingerprint> {
  // One sharp decode/resize supplies both average color and pHash.
  const { data, info } = await sharp(Buffer.from(input), {
    failOn: "error",
    limitInputPixels: 40_000_000,
  })
    .rotate()
    .resize(NORMALIZED_IMAGE_SIZE, NORMALIZED_IMAGE_SIZE, { fit: "fill" })
    .flatten({ background: "#ffffff" })
    .removeAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  if (
    info.width !== NORMALIZED_IMAGE_SIZE ||
    info.height !== NORMALIZED_IMAGE_SIZE ||
    info.channels !== 3
  ) {
    throw new Error("Could not normalize the RGB image");
  }

  let redSum = 0;
  let greenSum = 0;
  let blueSum = 0;
  const grayscale = new Float64Array(PHASH_IMAGE_SIZE ** 2);

  // Each pHash pixel is a 2x2 average from the single 64x64 RGB buffer.
  for (let y = 0; y < PHASH_IMAGE_SIZE; y += 1) {
    for (let x = 0; x < PHASH_IMAGE_SIZE; x += 1) {
      let luminanceSum = 0;

      for (let offsetY = 0; offsetY < 2; offsetY += 1) {
        for (let offsetX = 0; offsetX < 2; offsetX += 1) {
          const sourceX = x * 2 + offsetX;
          const sourceY = y * 2 + offsetY;
          const index =
            (sourceY * NORMALIZED_IMAGE_SIZE + sourceX) * info.channels;
          const red = data[index];
          const green = data[index + 1];
          const blue = data[index + 2];
          if (red === undefined || green === undefined || blue === undefined) {
            throw new Error("Incomplete RGB image buffer");
          }

          redSum += red;
          greenSum += green;
          blueSum += blue;
          luminanceSum += 0.2126 * red + 0.7152 * green + 0.0722 * blue;
        }
      }

      grayscale[y * PHASH_IMAGE_SIZE + x] = luminanceSum / 4;
    }
  }

  return {
    color: {
      red: redSum / NORMALIZED_PIXEL_COUNT,
      green: greenSum / NORMALIZED_PIXEL_COUNT,
      blue: blueSum / NORMALIZED_PIXEL_COUNT,
    },
    pHash: pHashFromGrayscale(grayscale),
  };
}

async function loadReferenceProfile(
  path: string,
): Promise<ReferenceProfile | null> {
  try {
    const file = Bun.file(path);
    if (file.size > MAXIMUM_IMAGE_BYTES) {
      logger.warn("Skipping oversized sample", { path, bytes: file.size });
      return null;
    }

    return {
      ...(await fingerprintImage(await file.bytes())),
      sourcePath: path,
    };
  } catch (error) {
    logger.warn("Could not load sample", { path, error });
    return null;
  }
}

export async function loadReferenceProfiles(
  samplesDirectory = DEFAULT_SAMPLES_DIRECTORY,
): Promise<ReferenceProfile[]> {
  const paths: string[] = [];
  try {
    for await (const relativePath of new Bun.Glob("**/*").scan({
      cwd: samplesDirectory,
      onlyFiles: true,
    })) {
      if (SAMPLE_EXTENSION.test(relativePath)) {
        paths.push(join(samplesDirectory, relativePath));
      }
    }
  } catch (error) {
    if (!(
      error instanceof Error &&
      "code" in error &&
      error.code === "ENOENT"
    )) {
      throw error;
    }
  }
  paths.sort((left, right) => left.localeCompare(right));

  const loaded = new Array<ReferenceProfile | null>(paths.length).fill(null);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(SAMPLE_LOAD_CONCURRENCY, paths.length) },
    async () => {
      while (nextIndex < paths.length) {
        const index = nextIndex;
        nextIndex += 1;
        const path = paths[index];
        if (path) {
          loaded[index] = await loadReferenceProfile(path);
        }
      }
    },
  );
  await Promise.all(workers);

  const referenceProfiles = loaded.filter(
    (profile): profile is ReferenceProfile => profile !== null,
  );
  if (referenceProfiles.length === 0) {
    throw new Error(
      `No usable reference images were found in ${samplesDirectory}`,
    );
  }
  return referenceProfiles;
}

function nearestDistances(
  fingerprint: ImageFingerprint,
  references: readonly ReferenceProfile[],
): NearestDistances {
  let nearestColorSquared = Number.POSITIVE_INFINITY;
  let nearestPHash = Number.POSITIVE_INFINITY;

  // One pass finds both the nearest average color and nearest pHash.
  for (const reference of references) {
    const red = fingerprint.color.red - reference.color.red;
    const green = fingerprint.color.green - reference.color.green;
    const blue = fingerprint.color.blue - reference.color.blue;
    nearestColorSquared = Math.min(
      nearestColorSquared,
      red * red + green * green + blue * blue,
    );
    nearestPHash = Math.min(
      nearestPHash,
      hammingDistance(fingerprint.pHash, reference.pHash),
    );
  }

  return {
    color: Math.sqrt(nearestColorSquared),
    pHash: nearestPHash,
  };
}

export function evaluateFingerprints(
  fingerprints: readonly ImageFingerprint[],
  sensitivity: Sensitivity,
  references: readonly ReferenceProfile[],
): DetectionResult {
  if (references.length === 0) {
    throw new Error("The detector received no reference profiles");
  }

  if (fingerprints.length === 0) {
    return {
      suspicious: false,
      confidence: 0,
      imageCountPoints: 0,
      colorPoints: 0,
      pHashPoints: 0,
      averageReferenceDistance: Number.POSITIVE_INFINITY,
      averagePHashDistance: Number.POSITIVE_INFINITY,
      pHashMatches: 0,
      colors: [],
    };
  }

  let colorSimilaritySum = 0;
  let pHashSimilaritySum = 0;
  let colorDistanceSum = 0;
  let pHashDistanceSum = 0;
  let pHashMatches = 0;

  for (const fingerprint of fingerprints) {
    const distance = nearestDistances(fingerprint, references);
    colorDistanceSum += distance.color;
    pHashDistanceSum += distance.pHash;
    colorSimilaritySum += clamp(
      1 - distance.color / COLOR_DISTANCE_RANGE,
      0,
      1,
    );
    pHashSimilaritySum += clamp(
      1 - distance.pHash / PHASH_DISTANCE_RANGE,
      0,
      1,
    );
    if (distance.pHash <= PHASH_MATCH_DISTANCE) {
      pHashMatches += 1;
    }
  }

  const imageCountPoints = Math.min(fingerprints.length, 4) * 10;
  const colorPoints =
    (colorSimilaritySum / fingerprints.length) * COLOR_MAX_POINTS;
  const pHashPoints =
    (pHashSimilaritySum / fingerprints.length) * PHASH_MAX_POINTS;
  const confidence = clamp(
    imageCountPoints + colorPoints + pHashPoints,
    0,
    100,
  );

  return {
    suspicious:
      pHashMatches > 0 && confidence >= CONFIDENCE_THRESHOLDS[sensitivity],
    confidence: Math.round(confidence),
    imageCountPoints: Math.round(imageCountPoints),
    colorPoints: Math.round(colorPoints),
    pHashPoints: Math.round(pHashPoints),
    averageReferenceDistance:
      Math.round((colorDistanceSum / fingerprints.length) * 10) / 10,
    averagePHashDistance:
      Math.round((pHashDistanceSum / fingerprints.length) * 10) / 10,
    pHashMatches,
    colors: fingerprints.map((fingerprint) => fingerprint.color),
  };
}

export async function createEvidenceImage(input: Uint8Array): Promise<Buffer> {
  return sharp(Buffer.from(input), {
    failOn: "error",
    limitInputPixels: 40_000_000,
  })
    .rotate()
    .resize({
      width: 256,
      height: 256,
      fit: "inside",
      withoutEnlargement: true,
    })
    .flatten({ background: "#ffffff" })
    .jpeg({ quality: 80, progressive: true, mozjpeg: true })
    .toBuffer();
}
