export type DKIMSelector = string;

export type DKIMRecord = {
  version: string;
  keyType: string;
  publicKey: string;
  notes?: string;
  serviceType?: string;
  granularity?: string;
  hashAlgorithms?: string[];
  flags?: string[];
};

export type DKIMValidationResult = {
  isValid: boolean;
  score: number;
  record: string;
  issues: DKIMIssue[];
  recommendations: string[];
  details: {
    hasVersion: boolean;
    hasValidKeyType: boolean;
    hasValidPublicKey: boolean;
    hasValidHashAlgorithms: boolean;
    keyLength: number;
    finalDomain: string;
  };
};

export type DKIMIssue = {
  type: 'error' | 'warning' | 'info';
  message: string;
  recommendation?: string;
};

export type DKIMScoreBreakdown = {
  recordPresent: number;
  validVersion: number;
  validKeyType: number;
  validPublicKey: number;
  validHashAlgorithms: number;
  total: number;
}; 