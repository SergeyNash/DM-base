import { useEffect, useMemo, useState } from "react";

import { fetchReports, uploadSarifFile } from "./api";
import { getOrCreateSessionId } from "./session";
import type {
  NormalizedFinding,
  NormalizedSarif,
  NormalizedSeverity,
  SarifReport,
} from "./types/sarif";

type SeverityFilter = NormalizedSeverity | "all";

interface FiltersState {
  severity: SeverityFilter;
  tool: string | "all";
  search: string;
}

const initialFilters: FiltersState = {
  severity: "all",
  tool: "all",
  search: "",
};

const MAX_REPORTS = 10;

export default function App() {
  const [sessionId] = useState(() => getOrCreateSessionId());
  const [reports, setReports] = useState<SarifReport[]>([]);
  const [activeReportId, setActiveReportId] = useState<string | null>(null);
  const [report, setReport] = useState<NormalizedSarif | null>(null);
  const [filters, setFilters] = useState<FiltersState>(initialFilters);
  const [selectedFinding, setSelectedFinding] =
    useState<NormalizedFinding | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    if (!sessionId) {
      setIsLoading(false);
      return;
    }
    fetchReports(sessionId)
      .then((data) => {
        if (!mounted) return;
        setReports(data);
        const latest = data[0] ?? null;
        setActiveReportId(latest?.id ?? null);
        setReport(latest?.normalized ?? null);
        setSelectedFinding(latest?.normalized.findings[0] ?? null);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(
          err instanceof Error
            ? err.message
            : "Не удалось загрузить сохранённые отчёты"
        );
      })
      .finally(() => {
        if (mounted) {
          setIsLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, [sessionId]);

  useEffect(() => {
    if (!activeReportId) {
      setReport(null);
      setSelectedFinding(null);
      return;
    }
    const current = reports.find((item) => item.id === activeReportId);
    if (current) {
      setReport(current.normalized);
      setSelectedFinding(current.normalized.findings[0] ?? null);
      setFilters(initialFilters);
    }
  }, [activeReportId, reports]);

  const selectedReport = useMemo(
    () => reports.find((item) => item.id === activeReportId) ?? null,
    [activeReportId, reports]
  );

  const filteredFindings = useMemo(() => {
    if (!report) {
      return [];
    }
    return report.findings.filter((finding) => {
      const severityOk =
        filters.severity === "all" || finding.severity === filters.severity;
      const toolOk =
        filters.tool === "all" || finding.tool.name === filters.tool;
      const search = filters.search.trim().toLowerCase();
      const searchOk =
        !search ||
        [finding.message, finding.ruleId, finding.location?.file]
          .filter(Boolean)
          .some((value) => value!.toLowerCase().includes(search));
      return severityOk && toolOk && searchOk;
    });
  }, [filters, report]);

  const severityOptions = useMemo(() => {
    if (!report) {
      return ["all"] as SeverityFilter[];
    }
    const available = Object.entries(report.stats.bySeverity)
      .filter(([, count]) => count > 0)
      .map(([severity]) => severity as NormalizedSeverity);
    return ["all", ...available];
  }, [report]);

  const toolOptions = useMemo(() => {
    if (!report) {
      return ["all"];
    }
    const names = new Set(report.findings.map((finding) => finding.tool.name));
    return ["all", ...Array.from(names)];
  }, [report]);

  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const files = Array.from(event.target.files ?? []);
    event.target.value = "";
    if (files.length === 0) {
      return;
    }
    if (reports.length + files.length > MAX_REPORTS) {
      setError(
        `Можно хранить не более ${MAX_REPORTS} отчетов. Удалите старые или выберите меньше файлов.`
      );
      return;
    }

    for (const file of files) {
      await processFile(file);
    }
  };

  const processFile = async (file: File) => {
    setIsUploading(true);
    setError(null);
    try {
      const saved = await uploadSarifFile(file, sessionId);
      setReports((prev) => [saved, ...prev]);
      setActiveReportId(saved.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Неизвестная ошибка");
    } finally {
      setIsUploading(false);
    }
  };

  const handleFindingSelect = (finding: NormalizedFinding) => {
    setSelectedFinding(finding);
  };

  return (
    <div className="app">
      <header className="app__header">
        <div>
          <p className="eyebrow">AppSec workspace</p>
          <h1>SARIF Viewer</h1>
          <p className="subtitle">
            Загрузите отчет SAST/DAST в формате SARIF и получите удобный список
            находок с фильтрами.
          </p>
        </div>
        <div className="upload-controls">
          <label className="file-input">
          <input
            type="file"
            accept=".sarif,application/json"
            multiple
            onChange={handleFileChange}
            disabled={isUploading}
          />
          {isUploading ? "Загрузка..." : "Выбрать SARIF"}
          </label>
          <p className="upload-hint">
            Доступно слотов: {Math.max(0, MAX_REPORTS - reports.length)} /{" "}
            {MAX_REPORTS}
          </p>
        </div>
      </header>

      {error && <div className="banner banner--error">{error}</div>}

      {report ? (
        <main className="layout">
          <section className="panel panel--reports">
            <div className="reports-header">
              <div>
                <p className="eyebrow">Загруженные отчёты ({reports.length})</p>
                <h2>
                  {selectedReport?.fileName ?? "—"}
                  {selectedReport?.createdAt && (
                    <span className="muted small">
                      {" "}
                      ·{" "}
                      {new Date(selectedReport.createdAt).toLocaleString("ru-RU")}
                    </span>
                  )}
                </h2>
              </div>
              <div className="pill-group wrap">
                {reports.map((item) => (
                  <button
                    key={item.id}
                    className={`pill pill--outline ${
                      item.id === activeReportId ? "is-active" : ""
                    }`}
                    onClick={() => setActiveReportId(item.id)}
                  >
                    {item.fileName}
                  </button>
                ))}
              </div>
            </div>
          </section>
          <section className="panel panel--summary">
            <div>
              <p className="eyebrow">
                {report.metadata.fileName ?? "Неизвестный файл"}
              </p>
              <h2>{report.stats.totalFindings} находок</h2>
              <p className="subtitle">
                Инструменты: {report.metadata.toolNames.join(", ")}
              </p>
            </div>
            <div className="pill-group">
              {Object.entries(report.stats.bySeverity)
                .filter(([, count]) => count > 0)
                .map(([severity, count]) => (
                  <span key={severity} className={`pill pill--${severity}`}>
                    {severity}: {count}
                  </span>
                ))}
            </div>
          </section>

          <section className="panel panel--filters">
            <div className="filter-group">
              <label>
                Severity
                <select
                  value={filters.severity}
                  onChange={(event) =>
                    setFilters((prev) => ({
                      ...prev,
                      severity: event.target.value as SeverityFilter,
                    }))
                  }
                >
                  {severityOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Tool
                <select
                  value={filters.tool}
                  onChange={(event) =>
                    setFilters((prev) => ({
                      ...prev,
                      tool: event.target.value,
                    }))
                  }
                >
                  {toolOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
              <label className="search-field">
                Поиск
                <input
                  type="search"
                  placeholder="rule/file/message"
                  value={filters.search}
                  onChange={(event) =>
                    setFilters((prev) => ({
                      ...prev,
                      search: event.target.value,
                    }))
                  }
                />
              </label>
            </div>
          </section>

          <section className="panel panel--content">
            <div className="list">
              {filteredFindings.length === 0 ? (
                <p className="muted">
                  Нет находок, удовлетворяющих фильтрам.
                </p>
              ) : (
                filteredFindings.map((finding) => (
                  <button
                    key={finding.id}
                    onClick={() => handleFindingSelect(finding)}
                    className={`list-item ${
                      selectedFinding?.id === finding.id ? "is-active" : ""
                    }`}
                  >
                    <div className="list-item__header">
                      <span className={`pill pill--${finding.severity}`}>
                        {finding.severity}
                      </span>
                      <span className="list-item__rule">
                        {finding.ruleId}
                        {finding.ruleName ? ` · ${finding.ruleName}` : ""}
                      </span>
                    </div>
                    <p className="list-item__message">{finding.message}</p>
                    <p className="list-item__meta">
                      {finding.tool.name}
                      {finding.location?.file
                        ? ` · ${finding.location.file}${
                            finding.location.startLine
                              ? `:${finding.location.startLine}`
                              : ""
                          }`
                        : ""}
                    </p>
                  </button>
                ))
              )}
            </div>

            <aside className="details">
              {selectedFinding ? (
                <FindingDetails finding={selectedFinding} />
              ) : (
                <p className="muted">Выберите находку слева, чтобы увидеть детали.</p>
              )}
            </aside>
          </section>
        </main>
      ) : isLoading ? (
        <div className="placeholder">
          <p>Загружаем отчёты...</p>
        </div>
      ) : (
        <div className="placeholder">
          <h2>Нет данных</h2>
          <p>Загрузите SARIF файл, чтобы начать работу.</p>
        </div>
      )}
    </div>
  );
}

function FindingDetails({ finding }: { finding: NormalizedFinding }) {
  return (
    <div className="details__content">
      <h3>{finding.ruleId}</h3>
      {finding.ruleName && <p className="muted">{finding.ruleName}</p>}
      <p>{finding.message}</p>

      {finding.location?.file && (
        <div className="details__section">
          <h4>Локация</h4>
          <p>
            {finding.location.file}
            {finding.location.startLine
              ? `:${finding.location.startLine}`
              : ""}
          </p>
          {finding.location.snippet && (
            <pre className="code-snippet">{finding.location.snippet}</pre>
          )}
        </div>
      )}

      {finding.remediation && (
        <div className="details__section">
          <h4>Рекомендации</h4>
          <p>{finding.remediation}</p>
        </div>
      )}

      {finding.tags.length > 0 && (
        <div className="details__section">
          <h4>Теги</h4>
          <div className="pill-group">
            {finding.tags.map((tag) => (
              <span key={tag} className="pill">
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {finding.helpUrl && (
        <div className="details__section">
          <h4>Документация</h4>
          <a href={finding.helpUrl} target="_blank" rel="noreferrer">
            {finding.helpUrl}
          </a>
        </div>
      )}
    </div>
  );
}


