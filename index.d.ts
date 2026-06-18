export declare class TpmError extends Error {
  code: string;
  suggestion?: string;
  tpmRc?: number;
  constructor(code: string, message: string, suggestion?: string, tpmRc?: number);
}

export declare const Tpm: {
  isAvailable(): Promise<boolean>;
  open(): Promise<never>;
  getFixedProperties(): Promise<{
    manufacturer: string;
    firmwareVersion: string;
    isVirtual: boolean;
    spec: string;
  }>;
  info(): Promise<{
    manufacturer: string;
    firmwareVersion: string;
    isVirtual: boolean;
    spec: string;
  }>;
};
