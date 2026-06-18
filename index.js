export class TpmError extends Error {
  constructor(code, message, suggestion) {
    super(message);
    this.name = 'TpmError';
    this.code = code;
    this.suggestion = suggestion;
  }
}

export const Tpm = {
  /** Probe for an accessible TPM. Always false in this pre-release placeholder. */
  async isAvailable() {
    return false;
  },
  /** Open a TPM handle. Not implemented yet in this pre-release. */
  async open() {
    throw new TpmError(
      'NOT_IMPLEMENTED',
      'node-tpm2 is a pre-release placeholder; the native backend is not published yet.',
      'Follow https://github.com/stacks0x/tpm2 for the first working release.',
    );
  },
};
