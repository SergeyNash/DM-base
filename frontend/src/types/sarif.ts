export type NormalizedSeverity =
  | "error"
  | "warning"
  | "note"
  | "none"
  | "pass"
  | "open"
  | "review"
  | "informational"
  | "unknown";

export interface NormalizedFindingLocation {
  file?: string;
  uriBaseId?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
}

export interface NormalizedFinding {
  id: string;
  ruleId: string;
  ruleName?: string;
  ruleDescription?: string;
  severity: NormalizedSeverity;
  message: string;
  tool: {
    name: string;
    version?: string;
    informationUri?: string;
  };
  location?: NormalizedFindingLocation;
  remediation?: string;
  helpUrl?: string;
  tags: string[];
  fingerprints: Record<string, string>;
  properties: Record<string, unknown>;
}

export interface NormalizedSarif {
  metadata: {
    sarifVersion: string;
    toolNames: string[];
    uploadedAt: string;
    fileName?: string;
  };
  stats: {
    totalFindings: number;
    bySeverity: Record<NormalizedSeverity, number>;
  };
  findings: NormalizedFinding[];
}

export interface SarifReport {
  id: string;
  sessionId: string;
  fileName: string;
  createdAt: string;
  normalized: NormalizedSarif;
}



