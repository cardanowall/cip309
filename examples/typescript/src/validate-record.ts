// Label 309 structural validator — surface demo + conformance replay.
//
// The structural validator is a pure function over record-body bytes: no
// I/O, no signature crypto, no decryption. It returns a discriminated
// result — `valid: true` with the decoded record (plus any warning- and
// info-severity issues), or `valid: false` with the typed error-severity
// issue list. Every issue carries a path from the record root, a
// SCREAMING_SNAKE code from the error-code registry, a severity, and a
// human-readable message.
//
// After a short tour of that surface, the example replays the conformance
// corpus shipped next to the specification (`../conformance/validator/`):
// byte-pinned record bodies, each with the exact set of error-severity
// codes a conformant validator emits. The corpus is the cross-language
// oracle — any implementation must agree with it code-for-code.
//
// Run: `node src/validate-record.ts` (exits non-zero on any disagreement).

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { validatePoeRecord, type ValidatorOptions } from '@cardanowall/poe-standard';

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === '' ? '' : ` — ${detail}`}`);
  if (!ok) failures += 1;
}

// ── Surface tour ─────────────────────────────────────────────────────────────

function surfaceTour(): void {
  // The smallest conformant record: v plus one item with one registered
  // content hash. (a2 = map(2); "v" → 1; "items" → [ { "hashes": { "sha2-256":
  // h'11…11' } } ].)
  const minimal = hexToBytes(
    'a2617601656974656d7381a166686173686573a168736861322d3235365820' + '11'.repeat(32),
  );
  const ok = validatePoeRecord(minimal);
  check('minimal hash-only record validates', ok.valid);

  // An unknown field inside a closed map is a structural rejection with a
  // precise path. (Same record with "bogus": 1 inside the item map.)
  const unknownField = hexToBytes(
    'a2617601656974656d7381a265626f67757301' +
      '66686173686573a168736861322d3235365820' +
      '11'.repeat(32),
  );
  const bad = validatePoeRecord(unknownField);
  check('unknown field is rejected', !bad.valid);
  if (!bad.valid) {
    const issue = bad.issues[0];
    console.log(
      `issue               : code=${issue?.code} severity=${issue?.severity} path=[${issue?.path.join(', ')}]`,
    );
    console.log(`                      ${issue?.message}`);
    check(
      'issue is SCHEMA_UNKNOWN_FIELD at items[0]',
      issue?.code === 'SCHEMA_UNKNOWN_FIELD' && issue.path[0] === 'items' && issue.path[1] === 0,
    );
  }
}

// ── Conformance replay ───────────────────────────────────────────────────────

interface CorpusVector {
  readonly name: string;
  readonly cbor_hex: string;
  readonly expected_error_codes: ReadonlyArray<string>;
  readonly expected_info_codes?: ReadonlyArray<string>;
  readonly validator_options?: {
    readonly supportedCriticalExtensions?: ReadonlyArray<string>;
    readonly maxSlots?: number;
    readonly maxEncEnvelopeBytes?: number;
    readonly passphraseParamsCeiling?: { m: number; t: number; p: number } | null;
  };
}

function loadCorpus(file: string): CorpusVector[] {
  const url = new URL(`../../../conformance/validator/${file}`, import.meta.url);
  const parsed = JSON.parse(fs.readFileSync(fileURLToPath(url), 'utf8')) as {
    vectors: CorpusVector[];
  };
  return parsed.vectors;
}

function toOptions(v: CorpusVector): ValidatorOptions | undefined {
  const fixture = v.validator_options;
  if (fixture === undefined) return undefined;
  return {
    ...(fixture.supportedCriticalExtensions !== undefined
      ? { supportedCriticalExtensions: new Set(fixture.supportedCriticalExtensions) }
      : {}),
    ...(fixture.maxSlots !== undefined ? { maxSlots: fixture.maxSlots } : {}),
    ...(fixture.maxEncEnvelopeBytes !== undefined
      ? { maxEncEnvelopeBytes: fixture.maxEncEnvelopeBytes }
      : {}),
    ...(fixture.passphraseParamsCeiling !== undefined
      ? { passphraseParamsCeiling: fixture.passphraseParamsCeiling }
      : {}),
  };
}

function replay(file: string): void {
  let pass = 0;
  const corpus = loadCorpus(file);
  for (const vector of corpus) {
    const result = validatePoeRecord(hexToBytes(vector.cbor_hex), toOptions(vector));
    const expected = [...vector.expected_error_codes].sort();
    const actual = result.valid
      ? []
      : [...new Set(result.issues.filter((i) => i.severity === 'error').map((i) => i.code))].sort();
    const codesAgree = JSON.stringify(actual) === JSON.stringify(expected);
    // Positive vectors may additionally pin info-severity tags that MUST be
    // surfaced without failing the record.
    const expectedInfo = [...(vector.expected_info_codes ?? [])].sort();
    const actualInfo = result.valid
      ? [...new Set((result.info ?? []).map((i) => i.code))].sort()
      : [];
    const infoAgrees =
      vector.expected_info_codes === undefined ||
      JSON.stringify(actualInfo) === JSON.stringify(expectedInfo);
    if (codesAgree && infoAgrees) {
      pass += 1;
    } else {
      check(
        `${file} :: ${vector.name}`,
        false,
        `expected [${expected.join(',')}] got [${actual.join(',')}]`,
      );
    }
  }
  check(`${file}: ${pass}/${corpus.length} vectors agree`, pass === corpus.length);
}

function main(): void {
  surfaceTour();
  console.log('\n--- conformance replay ---');
  replay('validator-positive.json');
  replay('validator-negative.json');
  replay('validator-bounds-negative.json');

  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nALL validator checks PASSED');
}

main();
