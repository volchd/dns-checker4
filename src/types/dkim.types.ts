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
  records: DKIMRecordData[];
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

export type DKIMRecordData = {
  raw: string;
  parsed: DKIMRecord;
  selector?: string;
};

export type DKIMIssue = {
  type: 'error' | 'warning' | 'info';
  message: string;
  recommendation?: string;
};

export type DKIMScoreBreakdown = {
  dkimImplemented: number;      // 10 points (all or nothing)
  keyLength: number;            // Up to 5 points (2048+ = 5, 1024+ = 3, <1024 = 0)
  multipleSelectors: number;    // 3 points (if ≥2 selectors; 0 if only one)
  noTestMode: number;           // 2 points (if no test flags; 0 if any present)
  total: number;                // Total score (max 20)
}; 