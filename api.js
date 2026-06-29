let native = null;
let nativeLoadError = null;

try {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  native = require('./native.cjs');
} catch (err) {
  nativeLoadError = err;
}

const TPM_UNAVAILABLE = {
  code: 'TPM_UNAVAILABLE',
  suggestion: 'Run npm run build, or install a published platform package.',
};

function parseNativeError(err) {
  const msg = err?.message ?? String(err);
  if (msg.startsWith('__tpm2__')) {
    const rest = msg.slice('__tpm2__'.length);
    const parts = rest.split('|');
    const [code, message, suggestion, tpmRcStr, hresultStr] = parts;
    const tpmRc = tpmRcStr ? Number.parseInt(tpmRcStr, 10) : undefined;
    const hresult = hresultStr ? Number.parseInt(hresultStr, 10) : undefined;
    return new TpmError(
      code,
      message,
      suggestion || undefined,
      Number.isFinite(tpmRc) ? tpmRc : undefined,
      Number.isFinite(hresult) ? hresult : undefined,
    );
  }
  return err;
}

function wrapNative(fn) {
  return async (...args) => {
    try {
      return await fn(...args);
    } catch (err) {
      throw parseNativeError(err);
    }
  };
}

function requireNative(method) {
  if (!native?.[method]) {
    throw new TpmError(
      TPM_UNAVAILABLE.code,
      nativeLoadError
        ? `Native backend not loaded: ${nativeLoadError.message}`
        : 'Native backend not built for this platform.',
      TPM_UNAVAILABLE.suggestion,
    );
  }
}

export class TpmError extends Error {
  constructor(code, message, suggestion, tpmRc, hresult) {
    super(message);
    this.name = 'TpmError';
    this.code = code;
    this.suggestion = suggestion;
    this.tpmRc = tpmRc;
    this.hresult = hresult;
  }
}

function parseTpmHandle(handle) {
  if (typeof handle === 'number') {
    return `0x${handle.toString(16).padStart(8, '0')}`;
  }
  return handle;
}

function createKeyHandle(publicKeyDer, keyBlob) {
  return {
    export() {
      return {
        public: Buffer.from(keyBlob.public),
        private: Buffer.from(keyBlob.private),
      };
    },

    get publicKeyDer() {
      return Buffer.from(publicKeyDer);
    },

    sign: wrapNative(async (digest) => {
      requireNative('signKeyBlob');
      const sig = await native.signKeyBlob({
        keyBlob,
        digest,
      });
      return Buffer.from(sig);
    }),

    decrypt: wrapNative(async (cipher) => {
      requireNative('decryptKeyBlob');
      const plain = await native.decryptKeyBlob({
        keyBlob,
        cipher,
      });
      return Buffer.from(plain);
    }),
  };
}

function createAkHandle(akPublicDer, akBlob) {
  return {
    /** Wrapped TPM2B_PUBLIC + TPM2B_PRIVATE for persistence (no persistent TPM handle). */
    export() {
      return {
        public: Buffer.from(akBlob.public),
        private: Buffer.from(akBlob.private),
      };
    },

    /** SPKI DER for the AK public area (from provisioning). */
    get publicKeyDer() {
      return Buffer.from(akPublicDer);
    },

    quote: wrapNative(async (opts) => {
      requireNative('quote');
      return native.quote({
        akBlob,
        pcrSelection: opts.pcrSelection,
        qualifyingData: opts.qualifyingData,
        bank: opts.bank,
      });
    }),

    activateCredential: wrapNative(async (opts) => {
      requireNative('activateCredential');
      return native.activateCredential({
        akBlob,
        credentialBlob: opts.credentialBlob,
        secret: opts.secret,
      });
    }),
  };
}

function createTpmHandle() {
  return {
    async info() {
      return Tpm.getFixedProperties();
    },

    pcr: {
      /** Read SHA-256 PCR digests for the given indices. */
      read: wrapNative(async (selection, bank = 'sha256') => {
        requireNative('pcrRead');
        return native.pcrRead(selection, bank);
      }),

      /** Extend a PCR digest in the SHA-256 bank. */
      extend: wrapNative(async (index, digest) => {
        requireNative('pcrExtend');
        await native.pcrExtend(index, digest);
      }),
    },

    random: {
      /** Read `count` bytes from the TPM RNG (GetRandom). */
      bytes: wrapNative(async (count) => {
        requireNative('randomBytes');
        const buf = await native.randomBytes(count);
        return Buffer.from(buf);
      }),
    },

    nv: {
      readPublic: wrapNative(async (handle) => {
        requireNative('nvReadPublic');
        return native.nvReadPublic(parseTpmHandle(handle));
      }),

      read: wrapNative(async (handle, offset, size, auth, ownerAuth) => {
        requireNative('nvRead');
        const buf = await native.nvRead(
          parseTpmHandle(handle),
          offset ?? undefined,
          size ?? undefined,
          auth ?? undefined,
          ownerAuth ?? undefined,
        );
        return Buffer.from(buf);
      }),

      write: wrapNative(async (handle, data, offset, auth, ownerAuth) => {
        requireNative('nvWrite');
        await native.nvWrite({
          handle: parseTpmHandle(handle),
          data,
          offset: offset ?? undefined,
          auth: auth ?? undefined,
          ownerAuth: ownerAuth ?? undefined,
        });
      }),

      define: wrapNative(async (opts) => {
        requireNative('nvDefine');
        await native.nvDefine({
          handle: parseTpmHandle(opts.handle),
          size: opts.size,
          auth: opts.auth ?? undefined,
          ownerAuth: opts.ownerAuth ?? undefined,
        });
      }),

      undefine: wrapNative(async (handle, ownerAuth) => {
        requireNative('nvUndefine');
        await native.nvUndefine({
          handle: parseTpmHandle(handle),
          ownerAuth: ownerAuth ?? undefined,
        });
      }),
    },

    keys: {
      create: wrapNative(async (opts) => {
        requireNative('createKey');
        const result = await native.createKey({
          keyType: opts?.type,
          sign: opts?.sign,
          decrypt: opts?.decrypt,
        });
        return createKeyHandle(result.publicKeyDer, result.keyBlob);
      }),

      load: wrapNative(async (blob) => {
        requireNative('keyBlobPublicDer');
        const publicKeyDer = await native.keyBlobPublicDer(blob);
        return createKeyHandle(publicKeyDer, blob);
      }),
    },

    seal: {
      seal: wrapNative(async (opts) => {
        requireNative('seal');
        const buf = await native.seal({
          data: opts.data,
          pcrSelection: opts.pcrSelection,
        });
        return Buffer.from(buf);
      }),

      unseal: wrapNative(async (blob) => {
        requireNative('unseal');
        const plain = await native.unseal(blob);
        return Buffer.from(plain);
      }),
    },

    attest: {
      /** EK certificate from NV index, or null if not provisioned. */
      ekCertificate: wrapNative(async () => {
        requireNative('readEkCertificate');
        return native.readEkCertificate();
      }),

      /** Provision a transient AK; returns a handle with export/quote/activateCredential. */
      provisionAk: wrapNative(async (opts) => {
        requireNative('provisionAk');
        const result = await native.provisionAk({
          keyName: opts?.keyName,
          scope: opts?.scope,
          overwrite: opts?.overwrite,
        });
        return createAkHandle(result.akPublicDer, result.akBlob);
      }),

      /** Produce a quote from a wrapped AK blob (transient load, no persistent handle). */
      quote: wrapNative(async (opts) => {
        requireNative('quote');
        return native.quote({
          akBlob: opts.akBlob,
          pcrSelection: opts.pcrSelection,
          qualifyingData: opts.qualifyingData,
          bank: opts.bank,
        });
      }),
    },

    /** Read a TPM object's public area as SPKI DER + name. */
    readPublic: wrapNative(async (handle) => {
      requireNative('readPublic');
      return native.readPublic(handle);
    }),

    async [Symbol.asyncDispose]() {
      // Transient handles are flushed inside each native operation.
    },
  };
}

export const Tpm = {
  /** Probe for an accessible TPM. False on darwin / no TPM / no access. */
  async isAvailable() {
    if (!native?.isAvailable) {
      return false;
    }
    try {
      return await native.isAvailable();
    } catch {
      return false;
    }
  },

  /** Open a TPM handle. Auto-detects transport (TBS / /dev/tpmrm0). */
  async open() {
    requireNative('isAvailable');
    const available = await this.isAvailable();
    if (!available) {
      throw new TpmError(
        'TPM_UNAVAILABLE',
        'No accessible TPM on this platform.',
        'On Linux, ensure /dev/tpmrm0 is readable; on Windows, ensure the TPM is present.',
      );
    }
    return createTpmHandle();
  },

  /** Manufacturer, firmware, and virtual-TPM hint from GetCapability. */
  getFixedProperties: wrapNative(async () => {
    requireNative('getFixedProperties');
    const props = await native.getFixedProperties();
    return {
      manufacturer: props.manufacturer,
      firmwareVersion: props.firmwareVersion,
      isVirtual: props.isVirtual,
      spec: props.spec,
    };
  }),

  /** Alias for getFixedProperties. */
  async info() {
    return this.getFixedProperties();
  },

  /** Flat: TPM RNG bytes (GetRandom). Prefer `tpm.random.bytes` on an open handle. */
  randomBytes: wrapNative(async (count) => {
    requireNative('randomBytes');
    const buf = await native.randomBytes(count);
    return Buffer.from(buf);
  }),

  /** Flat native binding: PCR read. Prefer `tpm.pcr.read` on an open handle. */
  pcrRead: wrapNative(async (selection, bank) => {
    requireNative('pcrRead');
    return native.pcrRead(selection, bank);
  }),

  /** Flat native binding: PCR extend. Prefer `tpm.pcr.extend` on an open handle. */
  pcrExtend: wrapNative(async (index, digest) => {
    requireNative('pcrExtend');
    await native.pcrExtend(index, digest);
  }),

  /** Flat native binding: ReadPublic. */
  readPublic: wrapNative(async (handle) => {
    requireNative('readPublic');
    return native.readPublic(handle);
  }),

  /** Flat native binding: EK certificate NV read. */
  readEkCertificate: wrapNative(async () => {
    requireNative('readEkCertificate');
    return native.readEkCertificate();
  }),

  /** Flat native binding: quote with wrapped AK blob. */
  quote: wrapNative(async (opts) => {
    requireNative('quote');
    return native.quote(opts);
  }),

  /** Flat native binding: provision AK (returns akPublicDer + akBlob). */
  provisionAk: wrapNative(async (opts) => {
    requireNative('provisionAk');
    const result = await native.provisionAk({
      keyName: opts?.keyName,
      scope: opts?.scope,
      overwrite: opts?.overwrite,
    });
    return {
      akPublicDer: result.akPublicDer,
      akBlob: result.akBlob,
    };
  }),

  /** Flat native binding: activate credential with wrapped AK blob. */
  activateCredential: wrapNative(async (opts) => {
    requireNative('activateCredential');
    return native.activateCredential(opts);
  }),

  createKey: wrapNative(async (opts) => {
    requireNative('createKey');
    const result = await native.createKey({
      keyType: opts?.type,
      sign: opts?.sign,
      decrypt: opts?.decrypt,
    });
    return {
      publicKeyDer: result.publicKeyDer,
      keyBlob: result.keyBlob,
    };
  }),

  signKeyBlob: wrapNative(async (opts) => {
    requireNative('signKeyBlob');
    const sig = await native.signKeyBlob(opts);
    return Buffer.from(sig);
  }),

  decryptKeyBlob: wrapNative(async (opts) => {
    requireNative('decryptKeyBlob');
    const plain = await native.decryptKeyBlob(opts);
    return Buffer.from(plain);
  }),

  nvRead: wrapNative(async (handle, offset, size, auth, ownerAuth) => {
    requireNative('nvRead');
    const buf = await native.nvRead(
      parseTpmHandle(handle),
      offset ?? undefined,
      size ?? undefined,
      auth ?? undefined,
      ownerAuth ?? undefined,
    );
    return Buffer.from(buf);
  }),

  nvWrite: wrapNative(async (handle, data, offset, auth, ownerAuth) => {
    requireNative('nvWrite');
    await native.nvWrite({
      handle: parseTpmHandle(handle),
      data,
      offset: offset ?? undefined,
      auth: auth ?? undefined,
      ownerAuth: ownerAuth ?? undefined,
    });
  }),

  nvReadPublic: wrapNative(async (handle) => {
    requireNative('nvReadPublic');
    return native.nvReadPublic(parseTpmHandle(handle));
  }),

  nvDefine: wrapNative(async (opts) => {
    requireNative('nvDefine');
    await native.nvDefine({
      handle: parseTpmHandle(opts.handle),
      size: opts.size,
      auth: opts.auth ?? undefined,
      ownerAuth: opts.ownerAuth ?? undefined,
    });
  }),

  nvUndefine: wrapNative(async (handle, ownerAuth) => {
    requireNative('nvUndefine');
    await native.nvUndefine({
      handle: parseTpmHandle(handle),
      ownerAuth: ownerAuth ?? undefined,
    });
  }),

  seal: wrapNative(async (opts) => {
    requireNative('seal');
    const buf = await native.seal({
      data: opts.data,
      pcrSelection: opts.pcrSelection,
    });
    return Buffer.from(buf);
  }),

  unseal: wrapNative(async (blob) => {
    requireNative('unseal');
    const plain = await native.unseal(blob);
    return Buffer.from(plain);
  }),
};
