export declare class TpmError extends Error {
  code: string;
  suggestion?: string;
  tpmRc?: number;
  constructor(code: string, message: string, suggestion?: string, tpmRc?: number);
}

export declare type AkBlob = {
  public: Buffer;
  private: Buffer;
};

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
  };
  attest: {
    ekCertificate(): Promise<Buffer | null>;
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
  pcrRead(selection: number[], bank?: 'sha256'): Promise<Record<number, string>>;
  readPublic(handle: string): Promise<ReadPublicResult>;
  readEkCertificate(): Promise<Buffer | null>;
  quote(opts: QuoteOptions): Promise<QuoteResult>;
};

export declare function pcrRead(
  selection: number[],
  bank?: 'sha256',
): Promise<Record<number, string>>;

export declare function readPublic(handle: string): Promise<ReadPublicResult>;

export declare function readEkCertificate(): Promise<Buffer | null>;

export declare function quote(opts: QuoteOptions): Promise<QuoteResult>;

export declare function getFixedProperties(): Promise<TpmInfo>;

export declare function isAvailable(): Promise<boolean>;
