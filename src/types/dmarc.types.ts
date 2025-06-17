export type DMARCPolicy = 'none' | 'quarantine' | 'reject';

export type DMARCSubdomainPolicy = 'none' | 'quarantine' | 'reject';

export type DMARCReportFormat = 'afrf' | 'iodef';

export type DMARCReport = {
  type: DMARCReportFormat;
  uri: string;
  maxSize?: number;
};

export type DMARCRecord = {
  version: string;
  policy: DMARCPolicy;
  subdomainPolicy?: DMARCSubdomainPolicy;
  percentage?: number;
  reports?: DMARCReport[];
  failureOptions?: string[];
  adkim?: 'r' | 's';
  aspf?: 'r' | 's';
  notes?: string;
};

export type DMARCValidationResult = {
  isValid: boolean;
  score: number;
  record: string;
  issues: DMARCIssue[];
  recommendations: string[];
  details: {
    hasVersion: boolean;
    hasValidPolicy: boolean;
    hasSubdomainPolicy: boolean;
    hasPercentage: boolean;
    hasReports: boolean;
    hasFailureOptions: boolean;
    hasAdkim: boolean;
    hasAspf: boolean;
    finalDomain: string;
  };
};

export type DMARCIssue = {
  type: 'error' | 'warning' | 'info';
  message: string;
  recommendation?: string;
};

export type DMARCScoreBreakdown = {
  dmarcImplemented: number;     // 10 points (all or nothing)
  validPolicy: number;          // 5 points (reject = 5, quarantine = 3, none = 1)
  subdomainPolicy: number;      // 3 points (if present and valid)
  percentage: number;           // 2 points (if 100%; 1 point if <100%)
  reports: number;              // 2 points (if present)
  total: number;                // Total score (max 22)
}; 