export declare class TpmError extends Error {
  code: string;
  suggestion?: string;
}

export declare const Tpm: {
  isAvailable(): Promise<boolean>;
  open(): Promise<never>;
};
