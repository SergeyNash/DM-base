import { createHash } from "crypto";
import { z } from "zod";

const MessageSchema = z
  .object({
    text: z.string().optional(),
    markdown: z.string().optional(),
  })
  .partial();

const SnippetSchema = z
  .object({
    text: z.string().optional(),
  })
  .partial();

const RegionSchema = z
  .object({
    startLine: z.number().optional(),
    startColumn: z.number().optional(),
    endLine: z.number().optional(),
    endColumn: z.number().optional(),
    snippet: SnippetSchema.optional(),
  })
  .partial();

const ArtifactLocationSchema = z
  .object({
    uri: z.string().optional(),
    uriBaseId: z.string().optional(),
  })
  .partial();

const PhysicalLocationSchema = z
  .object({
    artifactLocation: ArtifactLocationSchema.optional(),
    region: RegionSchema.optional(),
  })
  .partial();

const LocationSchema = z
  .object({
    physicalLocation: PhysicalLocationSchema.optional(),
    message: MessageSchema.optional(),
  })
  .partial();

const FixSchema = z
  .object({
    description: MessageSchema.optional(),
  })
  .partial();

const RuleSchema = z
  .object({
    id: z.string(),
    name: z.string().optional(),
    shortDescription: MessageSchema.optional(),
    fullDescription: MessageSchema.optional(),
    help: MessageSchema.optional(),
    helpUri: z.string().optional(),
    properties: z.record(z.any()).optional(),
    defaultConfiguration: z
      .object({
        level: z.string().optional(),
        severity: z.string().optional(),
      })
      .partial()
      .optional(),
  })
  .passthrough();

const ResultSchema = z
  .object({
    ruleId: z.string().optional(),
    ruleIndex: z.number().optional(),
    message: MessageSchema,
    level: z.string().optional(),
    kind: z.string().optional(),
    baselineState: z.string().optional(),
    locations: z.array(LocationSchema).optional(),
    relatedLocations: z.array(LocationSchema).optional(),
    fixes: z.array(FixSchema).optional(),
    fingerprints: z.record(z.string()).optional(),
    partialFingerprints: z.record(z.string()).optional(),
    properties: z.record(z.any()).optional(),
    id: z.string().optional(),
    guid: z.string().optional(),
  })
  .passthrough();

const DriverSchema = z
  .object({
    name: z.string(),
    fullName: z.string().optional(),
    semanticVersion: z.string().optional(),
    version: z.string().optional(),
    organization: z.string().optional(),
    informationUri: z.string().optional(),
    rules: z.array(RuleSchema).optional(),
  })
  .passthrough();

const ToolSchema = z
  .object({
    driver: DriverSchema,
  })
  .passthrough();

const RunSchema = z
  .object({
    tool: ToolSchema,
    automationDetails: z
      .object({
        id: z.string().optional(),
        guid: z.string().optional(),
      })
      .partial()
      .optional(),
    results: z.array(ResultSchema).default([]),
  })
  .passthrough();

export const SarifSchema = z.object({
  version: z.string(),
  runs: z.array(RunSchema),
});

export type SarifLog = z.infer<typeof SarifSchema>;
export type SarifRun = z.infer<typeof RunSchema>;
export type SarifResult = z.infer<typeof ResultSchema>;

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
  partialFingerprints: Record<string, string>;
  fingerprints: Record<string, string>;
  properties: Record<string, unknown>;
  dedupeKey: string;
  rawResult: SarifResult;
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

export interface NormalizeSarifOptions {
  fileName?: string;
}

export function parseSarif(input: unknown): SarifLog {
  if (input == null) {
    throw new Error("SARIF payload отсутствует");
  }

  let payload: unknown = input;
  if (typeof payload === "string") {
    payload = JSON.parse(payload);
  }

  const result = SarifSchema.safeParse(payload);
  if (!result.success) {
    throw new Error(
      `SARIF формат невалиден: ${result.error.issues
        .map((issue) => `${issue.path.join(".") || "<root>"} ${issue.message}`)
        .join(", ")}`
    );
  }

  return result.data;
}

export function normalizeSarif(
  input: unknown,
  options: NormalizeSarifOptions = {}
): NormalizedSarif {
  const sarifLog = parseSarif(input);
  const findings: NormalizedFinding[] = [];
  const toolNames = new Set<string>();
  const severityStats: Record<NormalizedSeverity, number> = {
    error: 0,
    warning: 0,
    note: 0,
    none: 0,
    pass: 0,
    open: 0,
    review: 0,
    informational: 0,
    unknown: 0,
  };

  sarifLog.runs.forEach((run, runIndex) => {
    const driver = run.tool?.driver;
    if (driver?.name) {
      toolNames.add(driver.name);
    }

    const ruleMap = buildRuleMap(driver?.rules ?? []);

    run.results?.forEach((result, resultIndex) => {
      const rule = findRuleForResult(result, ruleMap);
      const severity = normalizeSeverity(
        result.level ??
          rule?.defaultConfiguration?.level ??
          rule?.defaultConfiguration?.severity ??
          "unknown"
      );
      severityStats[severity] += 1;

      const message = pickMessage(result.message);
      const location = pickLocation(result);
      const remediation = pickRemediation(result, rule);
      const tags = Array.from(
        new Set([
          ...extractTags(result.properties?.tags),
          ...extractTags(rule?.properties?.tags),
        ])
      );
      const partialFingerprints = result.partialFingerprints ?? {};
      const dedupeKey = buildDedupeKey({
        result,
        message,
        location,
        severity,
        partialFingerprints,
      });

      findings.push({
        id:
          result.id ??
          result.guid ??
          `${runIndex}-${resultIndex}-${result.ruleId ?? "unknown"}`,
        ruleId: rule?.id ?? result.ruleId ?? "unknown",
        ruleName: rule?.name,
        ruleDescription:
          rule?.shortDescription?.text ??
          rule?.shortDescription?.markdown ??
          rule?.fullDescription?.text ??
          rule?.fullDescription?.markdown,
        severity,
        message,
        tool: {
          name: driver?.name ?? "unknown",
          version: driver?.semanticVersion ?? driver?.version,
          informationUri: driver?.informationUri,
        },
        location,
        remediation,
        helpUrl: rule?.helpUri,
        tags,
        partialFingerprints,
        fingerprints: result.fingerprints ?? {},
        properties: result.properties ?? {},
        dedupeKey,
        rawResult: result,
      });
    });
  });

  return {
    metadata: {
      sarifVersion: sarifLog.version,
      toolNames: Array.from(toolNames),
      uploadedAt: new Date().toISOString(),
      fileName: options.fileName,
    },
    stats: {
      totalFindings: findings.length,
      bySeverity: severityStats,
    },
    findings,
  };
}

function buildRuleMap(
  rules: SarifRun["tool"]["driver"]["rules"] | undefined
): Map<string, z.infer<typeof RuleSchema>> {
  const map = new Map<string, z.infer<typeof RuleSchema>>();
  rules?.forEach((rule) => {
    if (rule?.id) {
      map.set(rule.id, rule);
    }
  });
  return map;
}

function findRuleForResult(
  result: SarifResult,
  ruleMap: Map<string, z.infer<typeof RuleSchema>>
) {
  if (result.ruleId && ruleMap.has(result.ruleId)) {
    return ruleMap.get(result.ruleId);
  }

  if (
    typeof result.ruleIndex === "number" &&
    result.ruleIndex >= 0 &&
    result.ruleIndex < ruleMap.size
  ) {
    const rules = Array.from(ruleMap.values());
    return rules[result.ruleIndex];
  }

  return undefined;
}

function normalizeSeverity(level: string | undefined): NormalizedSeverity {
  const normalized = (level ?? "unknown").toLowerCase();
  const allowed: NormalizedSeverity[] = [
    "error",
    "warning",
    "note",
    "none",
    "pass",
    "open",
    "review",
    "informational",
    "unknown",
  ];

  return (allowed.includes(normalized as NormalizedSeverity)
    ? normalized
    : "unknown") as NormalizedSeverity;
}

function pickMessage(message: z.infer<typeof MessageSchema> | undefined) {
  if (!message) {
    return "";
  }
  return message.text ?? message.markdown ?? "";
}

function pickLocation(result: SarifResult): NormalizedFindingLocation | undefined {
  const location = result.locations?.[0]?.physicalLocation;
  if (!location) {
    return undefined;
  }

  const region = location.region;
  return {
    file: location.artifactLocation?.uri,
    uriBaseId: location.artifactLocation?.uriBaseId,
    startLine: region?.startLine,
    startColumn: region?.startColumn,
    endLine: region?.endLine,
    endColumn: region?.endColumn,
    snippet: region?.snippet?.text,
  };
}

function pickRemediation(
  result: SarifResult,
  rule?: z.infer<typeof RuleSchema>
): string | undefined {
  const fix = result.fixes?.[0];
  const fromFix = pickMessage(fix?.description);
  if (fromFix) {
    return fromFix;
  }

  const fromRule = pickMessage(rule?.help);
  if (fromRule) {
    return fromRule;
  }

  return undefined;
}

function extractTags(source: unknown): string[] {
  if (Array.isArray(source)) {
    return source.filter((tag): tag is string => typeof tag === "string");
  }
  if (typeof source === "string") {
    return [source];
  }
  return [];
}

function buildDedupeKey(input: {
  result: SarifResult;
  message: string;
  location?: NormalizedFindingLocation;
  severity: NormalizedSeverity;
  partialFingerprints: Record<string, string>;
}) {
  const candidateFingerprints = [
    input.partialFingerprints?.primaryLocationFingerprint,
    input.partialFingerprints?.["primaryLocationFingerprint/v2"],
    input.result.fingerprints?.primaryLocationFingerprint,
    input.result.fingerprints?.["primaryLocationFingerprint/v2"],
  ].filter(Boolean);

  const fingerprintPayload = JSON.stringify(candidateFingerprints);

  const parts = [
    input.result.ruleId ?? "unknown",
    input.severity,
    input.message,
    input.location?.file ?? "",
    String(input.location?.startLine ?? ""),
    String(input.location?.startColumn ?? ""),
    fingerprintPayload,
  ];

  return createHash("sha256").update(parts.join("::")).digest("hex");
}

