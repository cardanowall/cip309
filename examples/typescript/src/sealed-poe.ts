// Label 309 sealed PoE — the multi-recipient encryption construction.
//
// A sealed PoE publishes a public, timestamped commitment to a plaintext
// digest while keeping the plaintext readable only by intended recipients:
// the on-chain record carries the plaintext hashes plus an `enc` envelope
// (the key-delivery material), and the ciphertext lives off-chain at a
// content-addressed URI. This example tours the construction through the
// SDK surface:
//
//   * wrap/unwrap under both registered KEMs — classical `x25519` and the
//     post-quantum hybrid `mlkem768x25519` (X-Wing), the recommended default;
//   * the envelope shape: `kem_ct` is a single 1120-byte byte string, the
//     content format is the segmented STREAM `chacha20-poly1305-stream64k`;
//   * the hash-claim binding: the envelope's slot-set MAC commits to the
//     item's `hashes` map, so an envelope spliced onto a different hash
//     claim fails before any content work;
//   * trial-decrypt: recipient public keys are never on the wire — a
//     recipient discovers their slot by attempting to open it;
//   * the decryption outcomes: a non-throwing result whose internal reason
//     codes (WRONG_RECIPIENT_KEY / TAMPERED_HEADER / TAMPERED_CIPHERTEXT)
//     are diagnostics for a trusted local caller — an untrusted caller MUST
//     see one indistinguishable generic failure;
//   * the published age-style recipient encodings (`age1…` / `age1pqc…`).
//
// Run: `node src/sealed-poe.ts` (exits non-zero on any failed check).

import {
  deriveMlKem768X25519KeypairFromSeed,
  deriveX25519KeypairFromSeed,
  eciesSealedPoeUnwrap,
  eciesSealedPoeWrap,
  encodeAgeX25519Recipient,
  encodeAgeXWingRecipient,
  hash,
  recipientKeyBundleFromSeed,
} from '@cardanowall/sdk-ts';

const enc = new TextEncoder();

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === '' ? '' : ` — ${detail}`}`);
  if (!ok) failures += 1;
}

function main(): void {
  const plaintext = enc.encode('sealed-poe example plaintext');
  // The item's hashes map MUST always commit to the PLAINTEXT, even when the
  // content ships encrypted — that commitment is what makes the time claim
  // meaningful, and it is the map the envelope is cryptographically bound to.
  const hashes = {
    'sha2-256': hash.sha2256(plaintext),
    'blake2b-256': hash.blake2b256(plaintext),
  };

  // Three recipients with independent keys; seed-derived here so the example
  // is deterministic apart from the envelope's fresh CEK/nonce/ephemerals.
  const seeds = [1, 2, 3].map((b) => new Uint8Array(32).fill(b));
  const x25519Pubs = seeds.map((s) => deriveX25519KeypairFromSeed(s).publicKey);

  // ── Classical x25519 path ─────────────────────────────────────────────────
  const classical = eciesSealedPoeWrap({
    plaintext,
    hashes,
    recipientPublicKeys: x25519Pubs,
    kem: 'x25519',
  });
  const env = classical.envelope;
  console.log(
    `x25519 envelope     : scheme ${env.scheme}, aead ${env.aead}, ${env.slots.length} slot(s), nonce ${env.nonce.length}B, slots_mac ${env.slots_mac.length}B`,
  );
  check('aead is the segmented STREAM format', env.aead === 'chacha20-poly1305-stream64k');
  check(
    'every classical slot is { epk: 32B, wrap: 48B }',
    env.kem === 'x25519' && env.slots.every((s) => s.epk.length === 32 && s.wrap.length === 48),
  );
  // Every sealed chunk carries a 16-byte tag; this short payload is a single
  // final chunk, so ciphertext = plaintext + 16.
  check(
    'STREAM ciphertext = plaintext + 16-byte tag',
    classical.ciphertext.length === plaintext.length + 16,
  );

  // Recipient 2 unwraps with their key bundle. The slot order on the wire is
  // CSPRNG-shuffled at sealing time, so position reveals nothing; the
  // trial-decrypt loop visits every slot regardless of where the match sits.
  const opened = eciesSealedPoeUnwrap({
    envelope: classical.envelope,
    ciphertext: classical.ciphertext,
    hashes,
    recipientKeyBundle: recipientKeyBundleFromSeed(seeds[1]!),
  });
  check('recipient 2 unwraps', opened.matched);
  if (opened.matched) {
    check('plaintext round-trips', bytesEqual(opened.plaintext, plaintext));
    // The application-layer recheck: recompute the committed digests over the
    // recovered plaintext before acting on it.
    check(
      'plaintext-hash recheck passes',
      bytesEqual(hash.sha2256(opened.plaintext), hashes['sha2-256']),
    );
  }

  // A non-recipient gets a clean no-match. The typed reason is an internal
  // diagnostic; an untrusted caller must receive one generic failure shape
  // regardless of WHY decryption failed.
  const stranger = eciesSealedPoeUnwrap({
    envelope: classical.envelope,
    ciphertext: classical.ciphertext,
    hashes,
    recipientKeyBundle: recipientKeyBundleFromSeed(new Uint8Array(32).fill(99)),
  });
  check(
    'non-recipient → WRONG_RECIPIENT_KEY',
    !stranger.matched && stranger.reason === 'WRONG_RECIPIENT_KEY',
  );

  // The hash-claim binding: the slots transcript digests this item's `hashes`
  // map, so presenting the same envelope under a different hashes map fails
  // the slot-set MAC — before any ciphertext work.
  const spliced = eciesSealedPoeUnwrap({
    envelope: classical.envelope,
    ciphertext: classical.ciphertext,
    hashes: { 'sha2-256': hash.sha2256(enc.encode('a different claim')) },
    recipientKeyBundle: recipientKeyBundleFromSeed(seeds[1]!),
  });
  check(
    'envelope spliced onto another hash claim → TAMPERED_HEADER',
    !spliced.matched && spliced.reason === 'TAMPERED_HEADER',
  );

  // Ciphertext tamper: a flipped byte fails the chunk's Poly1305 tag.
  const tampered = new Uint8Array(classical.ciphertext);
  tampered[4] = (tampered[4]! + 1) & 0xff;
  const torn = eciesSealedPoeUnwrap({
    envelope: classical.envelope,
    ciphertext: tampered,
    hashes,
    recipientKeyBundle: recipientKeyBundleFromSeed(seeds[1]!),
  });
  check(
    'tampered ciphertext → TAMPERED_CIPHERTEXT',
    !torn.matched && torn.reason === 'TAMPERED_CIPHERTEXT',
  );

  // ── Hybrid mlkem768x25519 (X-Wing) path — the recommended default ─────────
  // Secure against classical adversaries and harvest-now-decrypt-later
  // quantum adversaries, with X25519's classical security as the floor.
  const hybridPub = deriveMlKem768X25519KeypairFromSeed(seeds[0]!).publicKey;
  check('X-Wing recipient public key is 1216 bytes', hybridPub.length === 1216);
  const hybrid = eciesSealedPoeWrap({
    plaintext,
    hashes,
    recipientPublicKeys: [hybridPub],
    kem: 'mlkem768x25519',
  });
  check(
    'hybrid slot carries kem_ct as a single 1120-byte byte string',
    hybrid.envelope.kem === 'mlkem768x25519' &&
      hybrid.envelope.slots.length === 1 &&
      hybrid.envelope.slots[0]?.kem_ct.length === 1120 &&
      hybrid.envelope.slots[0]?.wrap.length === 48,
  );
  const hybridOpened = eciesSealedPoeUnwrap({
    envelope: hybrid.envelope,
    ciphertext: hybrid.ciphertext,
    hashes,
    // The bundle form carries both KEMs' secret lists; the unwrap dispatch
    // selects the right one from `envelope.kem`.
    recipientKeyBundle: recipientKeyBundleFromSeed(seeds[0]!),
  });
  check(
    'hybrid unwrap round-trips',
    hybridOpened.matched && bytesEqual(hybridOpened.plaintext, plaintext),
  );

  // ── Published recipient encodings ─────────────────────────────────────────
  // Out-of-band key distribution uses age-style Bech32 strings: `age1…` for
  // X25519 recipients, `age1pqc…` for X-Wing recipients (a Label 309
  // encoding — deliberately distinct from age's own `age1pq`).
  const ageClassical = encodeAgeX25519Recipient(x25519Pubs[0]!);
  const ageHybrid = encodeAgeXWingRecipient(hybridPub);
  console.log(`x25519 recipient    : ${ageClassical}`);
  console.log(`X-Wing recipient    : ${ageHybrid.slice(0, 40)}… (${ageHybrid.length} chars)`);
  check('classical recipient encodes as age1…', ageClassical.startsWith('age1'));
  check('hybrid recipient encodes as age1pqc…', ageHybrid.startsWith('age1pqc'));

  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nALL sealed-PoE checks PASSED');
}

main();
