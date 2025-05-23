/**
 * @param {string} str
 */
export function fromBase64(str) {
  str = atob(str);
  let arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return arr;
}

/**
 * @param {BufferSource} buf
 */
export function toBase64(buf) {
  if (ArrayBuffer.isView(buf)) buf = buf.buffer;
  let s = String.fromCharCode(...new Uint8Array(buf));
  return btoa(s);
}

/**
 * @param {Object} opts
 * @param {PublicKeyCredentialRpEntity} opts.rp
 * @param {PublicKeyCredentialUserEntity} opts.user
 */
export async function createCredential({ rp, user } = {}) {
  user ??= {
    displayName: "User",
    name: "user",
    id: new TextEncoder().encode("user"),
  };

  await navigator.credentials.create({
    publicKey: {
      rp,
      user,
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "discouraged",
      },
      challenge: new Uint8Array(),
      extensions: {
        prf: { eval: { first: new Uint8Array(32) } },
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -8 /* Ed25519 */ },
        { type: "public-key", alg: -7 /* ES256 */ },
        { type: "public-key", alg: -257 /* RS256 */ },
      ],
    },
  });
}

/**
 * @param {Object} opts
 * @param {string?} opts.rpId
 * @param {BufferSource} opts.salt 64 bytes
 * @param {BufferSource} opts.info
 * @param {AesDerivedKeyParams} opts.keyType
 * @param {boolean?} opts.extractable
 * @param {Iterable<KeyUsage>} opts.usage
 */
export async function deriveKey({
  rpId,
  salt,
  info,
  keyType,
  extractable,
  usage,
}) {
  salt ??= new Uint8Array(64);
  extractable ??= false;

  if (ArrayBuffer.isView(salt)) salt = salt.buffer;

  let prfSalt = new Uint8Array(32);
  prfSalt.set(new Uint8Array(salt, 0, 32));

  let hkdfSalt = new Uint8Array(32);
  hkdfSalt.set(new Uint8Array(salt, 32, 32));

  let cred = await navigator.credentials.get({
    publicKey: {
      rpId,
      challenge: new Uint8Array(),
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
      userVerification: "discouraged",
    },
  });

  let extensions = cred.getClientExtensionResults();
  if (!extensions.prf) throw new Error("PRF is not supported");

  let material = await crypto.subtle.importKey(
    "raw",
    extensions.prf.results.first,
    "HKDF",
    /* extractable */ false,
    ["deriveKey"]
  );

  return await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info },
    material,
    keyType,
    extractable,
    usage
  );
}
