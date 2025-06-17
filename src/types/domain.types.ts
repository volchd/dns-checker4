import { SPFValidationResult } from './spf.types';
import { DKIMValidationResult } from './dkim.types';
import { DMARCValidationResult } from './dmarc.types';

export type DomainValidationResult = {
  total_score: number;
  total_max_score: number;
  spf_result: SPFValidationResult;
  kdim_result: DKIMValidationResult;
  dmarc_result: DMARCValidationResult;
};

export type DomainValidationError = {
  error: string;
  domain?: string;
  details?: string;
  timestamp?: string;
};

export type DomainValidationResponse = DomainValidationResult | DomainValidationError; 