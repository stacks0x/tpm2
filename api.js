let native = null;
let nativeLoadError = null;

try {
  native = await import('./native.js');
} catch (err) {
  nativeLoadError = err;
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

  /** Open a TPM handle. Not implemented until post-spike releases. */
  async open() {
    if (!native?.isAvailable) {
      throw new TpmError(
        'TPM_UNAVAILABLE',
        nativeLoadError
          ? `Native backend not loaded: ${nativeLoadError.message}`
          : 'Native backend not built for this platform.',
        'Run npm run build, or install a published platform package.',
      );
    }
    throw new TpmError(
      'NOT_IMPLEMENTED',
      'Tpm.open() is not implemented yet; spike phase exposes isAvailable/getFixedProperties only.',
      'Follow https://github.com/stacks0x/tpm2 for progress.',
    );
  },

  /** Low-level probe used during development. */
  async getFixedProperties() {
    if (!native?.getFixedProperties) {
      throw new TpmError(
        'TPM_UNAVAILABLE',
        'Native backend not loaded.',
        'Run npm run build, or install a published platform package.',
      );
    }
    return native.getFixedProperties();
  },
};
