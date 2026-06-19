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
    const [code, message, suggestion, tpmRcStr] = parts;
    const tpmRc = tpmRcStr ? Number.parseInt(tpmRcStr, 10) : undefined;
    return new TpmError(
      code,
      message,
      suggestion || undefined,
      Number.isFinite(tpmRc) ? tpmRc : undefined,
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
  constructor(code, message, suggestion, tpmRc) {
    super(message);
    this.name = 'TpmError';
    this.code = code;
    this.suggestion = suggestion;
    this.tpmRc = tpmRc;
  }
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
    },

    attest: {
      /** EK certificate from NV index, or null if not provisioned. */
      ekCertificate: wrapNative(async () => {
        requireNative('readEkCertificate');
        return native.readEkCertificate();
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

  /** Flat native binding: PCR read. Prefer `tpm.pcr.read` on an open handle. */
  pcrRead: wrapNative(async (selection, bank) => {
    requireNative('pcrRead');
    return native.pcrRead(selection, bank);
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
};
