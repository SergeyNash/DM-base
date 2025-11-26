import { useEffect, useMemo, useState } from "react";

import { fetchReports, uploadSarifFile } from "./api";
import { getOrCreateSessionId } from "./session";
import type {
  NormalizedFinding,
  NormalizedSeverity,
  SarifReport,
} from "./types/sarif";

type SeverityFilter = NormalizedSeverity | "all";

interface FiltersState {
  severity: SeverityFilter;
  tool: string | "all";
  reportId: string | "all";
  search: string;
}

const initialFilters: FiltersState = {
  severity: "all",
  tool: "all",
  reportId: "all",
  search: "",
};

const MAX_REPORTS = 10;

interface FindingView {
  uid: string;
  reportId: string;
  reportFileName: string;
  createdAt: string;
  finding: NormalizedFinding;
}

export default function App() {
  const [sessionId] = useState(() => getOrCreateSessionId());
  const [reports, setReports] = useState<SarifReport[]>([]);
  const [filters, setFilters] = useState<FiltersState>(initialFilters);
  const [selectedFinding, setSelectedFinding] =
    useState<FindingView | null>(null);
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
        setFilters(initialFilters);
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

  const findingsView = useMemo(() => {
    return reports.flatMap((report) =>
      report.normalized.findings.map((finding, index) => ({
        uid: `${report.id}::${index}`,
        reportId: report.id,
        reportFileName: report.fileName,
        createdAt: report.createdAt,
        finding,
      }))
    );
  }, [reports]);

  useEffect(() => {
    if (findingsView.length === 0) {
      setSelectedFinding(null);
      return;
    }
    setSelectedFinding((prev) => {
      if (!prev) {
        return findingsView[0];
      }
      const stillExists = findingsView.find((item) => item.uid === prev.uid);
      return stillExists ?? findingsView[0];
    });
  }, [findingsView]);

  const aggregatedStats = useMemo(() => {
    const severityTemplate: Record<NormalizedSeverity, number> = {
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
    const toolNames = new Set<string>();
    findingsView.forEach(({ finding }) => {
      severityTemplate[finding.severity] =
        (severityTemplate[finding.severity] ?? 0) + 1;
      toolNames.add(finding.tool.name);
    });
    return {
      total: findingsView.length,
      bySeverity: severityTemplate,
      toolNames,
    };
  }, [findingsView]);

  const severityOptions = useMemo(() => {
    const active = Object.entries(aggregatedStats.bySeverity)
      .filter(([, count]) => count > 0)
      .map(([severity]) => severity as NormalizedSeverity);
    return ["all", ...active];
  }, [aggregatedStats]);

  const toolOptions = useMemo(() => {
    const names = new Set(findingsView.map((entry) => entry.finding.tool.name));
    return ["all", ...Array.from(names)];
  }, [findingsView]);

  const filteredFindings = useMemo(() => {
    const search = filters.search.trim().toLowerCase();
    return findingsView.filter((entry) => {
      const severityOk =
        filters.severity === "all" ||
        entry.finding.severity === filters.severity;
      const toolOk =
        filters.tool === "all" || entry.finding.tool.name === filters.tool;
      const reportOk =
        filters.reportId === "all" || entry.reportId === filters.reportId;
      const searchOk =
        !search ||
        [
          entry.finding.message,
          entry.finding.ruleId,
          entry.finding.location?.file,
          entry.reportFileName,
        ]
          .filter(Boolean)
          .some((value) => value!.toLowerCase().includes(search));
      return severityOk && toolOk && reportOk && searchOk;
    });
  }, [findingsView, filters]);

  const activeReportLabel =
    filters.reportId === "all"
      ? "Все отчёты"
      : reports.find((item) => item.id === filters.reportId)?.fileName ??
        "Отчёт";

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
      setFilters(initialFilters);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Неизвестная ошибка");
    } finally {
      setIsUploading(false);
    }
  };

  const handleFindingSelect = (entry: FindingView) => {
    setSelectedFinding(entry);
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

      {findingsView.length > 0 ? (
        <main className="layout">
          <section className="panel panel--reports">
            <div className="reports-header">
              <div>
                <p className="eyebrow">Загруженные отчёты ({reports.length})</p>
                <h2>Сводная таблица</h2>
                <p className="subtitle">
                  Инструменты:{" "}
                  {aggregatedStats.toolNames.size > 0
                    ? Array.from(aggregatedStats.toolNames).join(", ")
                    : "—"}
                </p>
                <p className="muted small">
                  Шаг фильтрации: {activeReportLabel}
                </p>
              </div>
              <div className="pill-group wrap">
                <button
                  className={`pill pill--outline ${
                    filters.reportId === "all" ? "is-active" : ""
                  }`}
                  onClick={() =>
                    setFilters((prev) => ({ ...prev, reportId: "all" }))
                  }
                >
                  Все отчёты
                </button>
                {reports.map((item) => (
                  <button
                    key={item.id}
                    className={`pill pill--outline ${
                      filters.reportId === item.id ? "is-active" : ""
                    }`}
                    onClick={() =>
                      setFilters((prev) => ({
                        ...prev,
                        reportId:
                          prev.reportId === item.id ? "all" : item.id,
                      }))
                    }
                  >
                    {item.fileName}
                  </button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel panel--summary">
            <div>
              <p className="eyebrow">Сводка по severity</p>
              <h2>{aggregatedStats.total} находок</h2>
              <p className="subtitle">Фильтр отчёта: {activeReportLabel}</p>
            </div>
            <div className="pill-group">
              {Object.entries(aggregatedStats.bySeverity)
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
              <label>
                Отчёт
                <select
                  value={filters.reportId}
                  onChange={(event) =>
                    setFilters((prev) => ({
                      ...prev,
                      reportId: event.target.value as FiltersState["reportId"],
                    }))
                  }
                >
                  <option value="all">Все отчёты</option>
                  {reports.map((report) => (
                    <option key={report.id} value={report.id}>
                      {report.fileName}
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
                filteredFindings.map((entry) => (
                  <button
                    key={entry.uid}
                    onClick={() => handleFindingSelect(entry)}
                    className={`list-item ${
                      selectedFinding?.uid === entry.uid ? "is-active" : ""
                    }`}
                  >
                    <div className="list-item__header">
                      <span
                        className={`pill pill--${entry.finding.severity}`}
                      >
                        {entry.finding.severity}
                      </span>
                      <span className="list-item__rule">
                        {entry.finding.ruleId}
                        {entry.finding.ruleName
                          ? ` · ${entry.finding.ruleName}`
                          : ""}
                      </span>
                    </div>
                    <p className="list-item__message">
                      {entry.finding.message}
                    </p>
                    <p className="list-item__meta">
                      {entry.finding.tool.name}
                      {entry.finding.location?.file
                        ? ` · ${entry.finding.location.file}${
                            entry.finding.location.startLine
                              ? `:${entry.finding.location.startLine}`
                              : ""
                          }`
                        : ""}
                      {" · "}
                      {entry.reportFileName}
                    </p>
                  </button>
                ))
              )}
            </div>

            <aside className="details">
              {selectedFinding ? (
                <FindingDetails entry={selectedFinding} />
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

function FindingDetails({ entry }: { entry: FindingView }) {
  const finding = entry.finding;
  return (
    <div className="details__content">
      <h3>{finding.ruleId}</h3>
      {finding.ruleName && <p className="muted">{finding.ruleName}</p>}
      <p className="muted small">
        Отчёт: {entry.reportFileName} ·{" "}
        {new Date(entry.createdAt).toLocaleString("ru-RU")}
      </p>
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


