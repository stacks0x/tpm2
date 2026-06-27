export declare class TpmError extends Error {
  code: TpmErrorCode;
  suggestion?: string;
  tpmRc?: number;
  hresult?: number;
  constructor(
    code: TpmErrorCode,
    message: string,
    suggestion?: string,
    tpmRc?: number,
    hresult?: number,
  );
}

/** Stable error codes — match Rust `src/tbs/codes.rs`. Semver after `latest`. */
export declare type TpmErrorCode =
  | 'TPM_UNAVAILABLE'
  | 'ACCESS_DENIED'
  | 'COMMAND_BLOCKED'
  | 'REQUIRES_ELEVATION'
  | 'NOT_SUPPORTED'
  | 'INVALID_ARGUMENT'
  | 'KEY_NOT_FOUND'
  | 'ALREADY_EXISTS'
  | 'MARSHALLING_ERROR'
  | 'TRANSPORT_ERROR'
  | 'AUTH_FAILED'
  | 'TPM_RC';

export declare type AkBlob = {
  public: Buffer;
  private: Buffer;
};

/** General key blob (same wire shape as AkBlob; distinct type for clarity). */
export declare type KeyBlob = AkBlob;

export declare type QuoteOptions = {
  akBlob: AkBlob;
  pcrSelection: number[];
  qualifyingData: Buffer;
  bank?: 'sha256';
};

export declare type QuoteResult = {
  message: Buffer;
  signature: Buffer;
};

export declare type ReadPublicResult = {
  publicKeyDer: Buffer;
  name: Buffer;
};

export declare type ProvisionAkOptions = {
  /** Persisted PCP key name on Windows. Omitted = random dev name. */
  keyName?: string;
  /** Windows only: `user` (default) or `machine` (fleet enrollment). */
  scope?: 'user' | 'machine';
  /** Windows only: replace existing persisted key of the same name. */
  overwrite?: boolean;
  /** @deprecated Linux-only hint; Windows PCP always uses RSA identity AK. */
  algorithm?: 'ecc' | 'rsa';
};

export declare type ProvisionAkResult = {
  akPublicDer: Buffer;
  akBlob: AkBlob;
};

export declare type ActivateCredentialOptions = {
  credentialBlob: Buffer;
  secret: Buffer;
};

export declare type ActivateCredentialFlatOptions = ActivateCredentialOptions & {
  akBlob: AkBlob;
};

/** @throws {TpmError} NOT_SUPPORTED until Phase 2 */
export declare type KeyCreateOptions = {
  type: 'ecc' | 'rsa';
  sign?: boolean;
  decrypt?: boolean;
};

/** @throws {TpmError} NOT_SUPPORTED until Phase 5 */
export declare type SealOptions = {
  data: Buffer;
  pcrSelection?: number[];
};

export declare interface AkHandle {
  export(): AkBlob;
  readonly publicKeyDer: Buffer;
  quote(opts: Omit<QuoteOptions, 'akBlob'>): Promise<QuoteResult>;
  activateCredential(opts: ActivateCredentialOptions): Promise<Buffer>;
}

/** @throws {TpmError} NOT_SUPPORTED until Phase 2 */
export declare interface KeyHandle {
  export(): KeyBlob;
  sign(digest: Buffer): Promise<Buffer>;
  decrypt(cipher: Buffer): Promise<Buffer>;
}

export declare type TpmInfo = {
  manufacturer: string;
  firmwareVersion: string;
  isVirtual: boolean;
  spec: string;
};

export declare interface TpmHandle {
  info(): Promise<TpmInfo>;
  pcr: {
    read(selection: number[], bank?: 'sha256'): Promise<Record<number, string>>;
    /** @throws {TpmError} NOT_SUPPORTED until Phase 3 */
    extend(index: number, digest: Buffer): Promise<void>;
  };
  random: {
    bytes(count: number): Promise<Buffer>;
  };
  nv: {
    /** @throws {TpmError} NOT_SUPPORTED until Phase 4 */
    read(handle: string, offset?: number, size?: number): Promise<Buffer>;
    /** @throws {TpmError} NOT_SUPPORTED until Phase 4 */
    write(handle: string, data: Buffer, offset?: number): Promise<void>;
  };
  keys: {
    /** @throws {TpmError} NOT_SUPPORTED until Phase 2 */
    create(opts: KeyCreateOptions): Promise<KeyHandle>;
    /** @throws {TpmError} NOT_SUPPORTED until Phase 2 */
    load(blob: KeyBlob): Promise<KeyHandle>;
  };
  seal: {
    /** @throws {TpmError} NOT_SUPPORTED until Phase 5 */
    seal(opts: SealOptions): Promise<Buffer>;
    /** @throws {TpmError} NOT_SUPPORTED until Phase 5 */
    unseal(blob: Buffer): Promise<Buffer>;
  };
  attest: {
    ekCertificate(): Promise<Buffer | null>;
    provisionAk(opts?: ProvisionAkOptions): Promise<AkHandle>;
    quote(opts: QuoteOptions): Promise<QuoteResult>;
  };
  readPublic(handle: string): Promise<ReadPublicResult>;
  [Symbol.asyncDispose](): Promise<void>;
}

export declare const Tpm: {
  isAvailable(): Promise<boolean>;
  open(): Promise<TpmHandle>;
  getFixedProperties(): Promise<TpmInfo>;
  info(): Promise<TpmInfo>;
  randomBytes(count: number): Promise<Buffer>;
  pcrRead(selection: number[], bank?: 'sha256'): Promise<Record<number, string>>;
  readPublic(handle: string): Promise<ReadPublicResult>;
  readEkCertificate(): Promise<Buffer | null>;
  quote(opts: QuoteOptions): Promise<QuoteResult>;
  provisionAk(opts?: ProvisionAkOptions): Promise<ProvisionAkResult>;
  activateCredential(opts: ActivateCredentialFlatOptions): Promise<Buffer>;
};
