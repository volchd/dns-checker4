export type SPFQualifier = '+' | '-' | '~' | '?';

export type SPFMechanism = {
  type: string;
  value?: string;
  qualifier: SPFQualifier;
};

export type SPFRedirect = {
  from: string;
  to: string;
  record: string;
};

export type SPFValidationResult = {
  isValid: boolean;
  score: number;
  record: string;
  redirectRecord: string;
  issues: SPFIssue[];
  recommendations: string[];
  mechanisms: SPFMechanism[];
  lookupCount: number;
  redirects: SPFRedirect[];
  details: {
    hasVersion: boolean;
    hasAllMechanism: boolean;
    allMechanismQualifier?: SPFQualifier;
    hasMultipleRecords: boolean;
    hasDeprecatedMechanisms: boolean;
    exceedsLookupLimit: boolean;
    hasPassAll: boolean;
    finalDomain: string;
  };
};

export type SPFIssue = {
  type: 'error' | 'warning' | 'info';
  message: string;
  recommendation?: string;
};

export type SPFScoreBreakdown = {
  recordPresent: number;
  singleRecord: number;
  syntaxValid: number;
  lookupLimit: number;
  noPassAll: number;
  allMechanismPolicy: number;
  noDeprecatedMechanisms: number;
  total: number;
}; 