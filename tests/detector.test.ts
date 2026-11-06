import { describe, expect, test } from "bun:test";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import {
  createEvidenceImage,
  evaluateFingerprints,
  fingerprintImage,
  hammingDistance,
  loadReferenceProfiles,
  type ImageFingerprint,
  type ReferenceProfile,
  type RgbColor,
} from "../src/detector.ts";

const SAMPLE_DIRECTORY = new URL("../samples/", import.meta.url);

describe("MrBeast scam detector", () => {
  test("recognizes the supplied sample palette", async () => {
    const names = [
      "photo_2026-07-15_03-20-32.jpg",
      "photo_2026-07-15_03-20-35.jpg",
      "photo_2026-07-15_03-20-36.jpg",
    ];
    const fingerprints = await Promise.all(
      names.map(async (name) => {
        const bytes = await Bun.file(new URL(name, SAMPLE_DIRECTORY)).bytes();
        return fingerprintImage(bytes);
      }),
    );

    const references = await loadReferenceProfiles();
    const detection = evaluateFingerprints(
      fingerprints,
      "balanced",
      references,
    );
    expect(detection.suspicious).toBeTrue();
    expect(detection.confidence).toBe(100);
    expect(detection.imageCountPoints).toBe(30);
    expect(detection.colorPoints).toBe(25);
    expect(detection.pHashMatches).toBe(3);
    expect(detection.pHashPoints).toBe(45);
  });

  test("creates a durable JPEG copy for the moderation report", async () => {
    const source = await Bun.file(
      new URL("photo_2026-07-15_03-20-32.jpg", SAMPLE_DIRECTORY),
    ).bytes();
    const evidence = await createEvidenceImage(source);

    expect(evidence.byteLength).toBeGreaterThan(0);
    expect(evidence[0]).toBe(0xff);
    expect(evidence[1]).toBe(0xd8);
    const metadata = await sharp(evidence).metadata();
    expect(metadata.width).toBeLessThanOrEqual(256);
    expect(metadata.height).toBeLessThanOrEqual(256);
  });

  test("picks up added samples on the next load", async () => {
    const temporaryDirectory = await mkdtemp(join(tmpdir(), "beastkiller-"));

    try {
      await copyFile(
        new URL("photo_2026-07-15_03-20-32.jpg", SAMPLE_DIRECTORY),
        join(temporaryDirectory, "first.JPG"),
      );
      expect(await loadReferenceProfiles(temporaryDirectory)).toHaveLength(1);

      const nestedDirectory = join(temporaryDirectory, "new");
      await mkdir(nestedDirectory);
      await copyFile(
        new URL("photo_2026-07-15_03-20-35.jpg", SAMPLE_DIRECTORY),
        join(nestedDirectory, "second.jpeg"),
      );
      expect(await loadReferenceProfiles(temporaryDirectory)).toHaveLength(2);
    } finally {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });

  test("detects one exact known scam image in balanced mode", () => {
    const reference: ReferenceProfile = {
      color: { red: 20, green: 25, blue: 35 },
      pHash: 0x1234_5678_9abc_def0n,
      sourcePath: "known-scam.jpg",
    };
    const detection = evaluateFingerprints([reference], "balanced", [
      reference,
    ]);

    expect(detection.confidence).toBe(80);
    expect(detection.imageCountPoints).toBe(10);
    expect(detection.colorPoints).toBe(25);
    expect(detection.pHashPoints).toBe(45);
    expect(detection.suspicious).toBeTrue();
  });

  test("does not flag one image from average color alone", () => {
    const reference: ReferenceProfile = {
      color: { red: 20, green: 25, blue: 35 },
      pHash: (1n << 63n) - 1n,
      sourcePath: "known-scam.jpg",
    };
    const detection = evaluateFingerprints(
      [{ color: reference.color, pHash: 0n }],
      "aggressive",
      [reference],
    );

    expect(detection.confidence).toBe(35);
    expect(detection.suspicious).toBeFalse();
  });

  test("does not flag four unrelated bright images", () => {
    const brightColors: RgbColor[] = [
      { red: 245, green: 230, blue: 220 },
      { red: 210, green: 240, blue: 230 },
      { red: 220, green: 220, blue: 250 },
      { red: 250, green: 250, blue: 250 },
    ];

    const brightFingerprints: ImageFingerprint[] = brightColors.map(
      (color) => ({ color, pHash: 0n }),
    );
    const references: ReferenceProfile[] = [
      {
        color: { red: 20, green: 25, blue: 35 },
        pHash: (1n << 63n) - 1n,
        sourcePath: "dark-sample.jpg",
      },
    ];
    const detection = evaluateFingerprints(
      brightFingerprints,
      "aggressive",
      references,
    );
    expect(detection.suspicious).toBeFalse();
    expect(detection.imageCountPoints).toBe(40);
    expect(detection.colorPoints).toBe(0);
  });

  test("keeps fingerprints close on a 256px optimized preview", async () => {
    const source = await Bun.file(
      new URL("photo_2026-07-15_03-20-32.jpg", SAMPLE_DIRECTORY),
    ).bytes();
    const optimizedPreview = await sharp(source)
      .resize({ width: 256, height: 256, fit: "inside" })
      .webp({ quality: 70 })
      .toBuffer();
    const [original, changed] = await Promise.all([
      fingerprintImage(source),
      fingerprintImage(optimizedPreview),
    ]);

    expect(hammingDistance(original.pHash, changed.pHash)).toBeLessThanOrEqual(
      8,
    );
    expect(
      Math.hypot(
        original.color.red - changed.color.red,
        original.color.green - changed.color.green,
        original.color.blue - changed.color.blue,
      ),
    ).toBeLessThan(3);
  });

  test("uses a close pHash as an additional detection signal", () => {
    const pHash = 0x1234_5678_9abc_def0n;
    const references: ReferenceProfile[] = [
      {
        color: { red: 20, green: 20, blue: 20 },
        pHash,
        sourcePath: "sample.jpg",
      },
    ];
    const baseFingerprints: ImageFingerprint[] = Array.from(
      { length: 3 },
      () => ({
        color: { red: 35, green: 35, blue: 35 },
        pHash,
      }),
    );

    const withPHash = evaluateFingerprints(
      baseFingerprints,
      "balanced",
      references,
    );
    const withoutPHash = evaluateFingerprints(
      baseFingerprints.map((fingerprint) => ({
        ...fingerprint,
        pHash: fingerprint.pHash ^ ((1n << 64n) - 1n),
      })),
      "balanced",
      references,
    );

    expect(withPHash.pHashPoints).toBe(45);
    expect(withPHash.suspicious).toBeTrue();
    expect(withoutPHash.pHashPoints).toBe(0);
    expect(withoutPHash.suspicious).toBeFalse();
  });

  test.each([
    [8, true],
    [9, false],
    [63, false],
  ] as const)(
    "requires a close pHash even above the aggressive threshold (distance %i)",
    (distance, suspicious) => {
      const reference: ReferenceProfile = {
        color: { red: 20, green: 25, blue: 35 },
        pHash: 0n,
        sourcePath: "sample.jpg",
      };
      const fingerprints: ImageFingerprint[] = Array.from(
        { length: 4 },
        (_, index) => ({
          color: reference.color,
          pHash: (1n << BigInt(index === 0 ? distance : 63)) - 1n,
        }),
      );

      const result = evaluateFingerprints(fingerprints, "aggressive", [
        reference,
      ]);

      expect(result.confidence).toBeGreaterThanOrEqual(65);
      expect(result.pHashMatches).toBe(suspicious ? 1 : 0);
      expect(result.suspicious).toBe(suspicious);
    },
  );
});
