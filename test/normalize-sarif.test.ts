import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { normalizeSarif, parseSarif } from "../src/lib/normalize-sarif";

const fixture = (name: string) =>
  readFileSync(join(process.cwd(), name), "utf-8");

describe("normalizeSarif", () => {
  it("парсит и нормализует реальный SARIF отчёт", () => {
    const sarifText = fixture("bbs2_ru.sarif");
    const normalized = normalizeSarif(sarifText, {
      fileName: "bbs2_ru.sarif",
    });

    expect(normalized.metadata.fileName).toBe("bbs2_ru.sarif");
    expect(normalized.metadata.sarifVersion).toMatch(/^2\./);
    expect(normalized.findings.length).toBeGreaterThan(0);
    expect(normalized.stats.totalFindings).toBe(normalized.findings.length);

    const severitySum = Object.values(normalized.stats.bySeverity).reduce(
      (acc, value) => acc + value,
      0
    );
    expect(severitySum).toBe(normalized.findings.length);
  });

  it("кидает понятную ошибку для невалидного JSON", () => {
    expect(() => parseSarif("{not-valid-json")).toThrow(
      /SARIF формат невалиден|Unexpected token/
    );
  });
});

