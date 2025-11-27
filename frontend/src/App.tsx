import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { fetchReports, uploadSarifFile } from "./api";
import { getOrCreateSessionId } from "./session";
import type {
  NormalizedFinding,
  NormalizedSeverity,
  SarifReport,
} from "./types/sarif";

type SeverityFilter = NormalizedSeverity | "all";
type PriorityLevel = "critical" | "high" | "medium" | "low";
type StatusValue = "new" | "confirmed" | "in_progress" | "resolved";
type GroupingMode = "vulnType" | "ownerTeam" | "source";
type AttackVector = "network" | "local" | "physical" | "unknown";
type TrendState = "up" | "flat" | "down";
type ColumnId =
  | "priority"
  | "cvss"
  | "severity"
  | "type"
  | "vector"
  | "businessComponent"
  | "ownerTeam"
  | "occurrences"
  | "status"
  | "age"
  | "source"
  | "trend"
  | "slsa"
  | "riskFactors"
  | "group";

interface FiltersState {
  severity: SeverityFilter;
  tool: string | "all";
  reportId: string | "all";
  search: string;
  priority: PriorityLevel[];
  status: StatusValue[];
  groupBy: GroupingMode;
}

const defaultPriorityFilter: PriorityLevel[] = ["critical", "high"];
const defaultStatusFilter: StatusValue[] = ["new", "confirmed"];

const initialFilters: FiltersState = {
  severity: "all",
  tool: "all",
  reportId: "all",
  search: "",
  priority: defaultPriorityFilter,
  status: defaultStatusFilter,
  groupBy: "vulnType",
};

const MAX_REPORTS = 10;
const TEAM_OPTIONS = [
  "Identity Platform",
  "Payments & Billing",
  "Digital Experience",
  "Cloud SecOps",
  "Data Platform",
  "AppSec Platform",
];
const DEFAULT_VISIBLE_COLUMNS: ColumnId[] = [
  "priority",
  "cvss",
  "severity",
  "type",
  "vector",
  "businessComponent",
  "ownerTeam",
  "occurrences",
  "status",
  "age",
  "source",
  "trend",
  "slsa",
  "riskFactors",
  "group",
];
const COLUMN_CONFIG: ColumnConfig[] = [
  {
    id: "priority",
    label: "Приоритет",
    render: (row) => (
      <span className={`priority-pill priority-pill--${row.priority}`}>
        {PRIORITY_LABELS[row.priority]} · {row.priorityScore.toFixed(1)}
      </span>
    ),
  },
  {
    id: "cvss",
    label: "CVSS",
    render: (row) => row.cvssScore.toFixed(1),
  },
  {
    id: "severity",
    label: "Серьёзность",
    render: (row) => (
      <span className={`pill pill--${row.finding.severity}`}>
        {row.finding.severity}
      </span>
    ),
  },
  {
    id: "type",
    label: "Тип уязвимости",
    render: (row) => row.vulnerabilityType,
  },
  {
    id: "vector",
    label: "Вектор атаки",
    render: (row) => (
      <span className={`attack attack--${row.attackVector}`}>
        {ATTACK_VECTOR_LABELS[row.attackVector]}
      </span>
    ),
  },
  {
    id: "businessComponent",
    label: "Бизнес-компонент",
    render: (row) => row.businessComponent,
  },
  {
    id: "ownerTeam",
    label: "Проект / команда",
    render: (row) => row.ownerTeam,
  },
  {
    id: "occurrences",
    label: "Кол-во вхождений",
    render: (row) => row.occurrences,
  },
  {
    id: "status",
    label: "Статус",
    render: (row) => (
      <span className={`status-pill status-pill--${row.status}`}>
        {STATUS_LABELS[row.status]}
      </span>
    ),
  },
  {
    id: "age",
    label: "Возраст",
    render: (row) => `${row.ageDays} дн.`,
  },
  {
    id: "source",
    label: "Источник",
    render: (row) => row.source,
  },
  {
    id: "trend",
    label: "Тренд",
    render: (row) => (
      <span className={`trend trend--${row.trend}`}>
        {TREND_ICONS[row.trend]} {TREND_LABELS[row.trend]}
      </span>
    ),
  },
  {
    id: "slsa",
    label: "SLSA",
    render: (row) => row.slsaLevel,
  },
  {
    id: "riskFactors",
    label: "Риск-факторы",
    render: (row) => (
      <div className="pill-group">
        {row.riskFactors.length === 0 ? (
          <span className="muted small">—</span>
        ) : (
          row.riskFactors.map((factor) => (
            <span key={factor} className="risk-badge">
              {factor}
            </span>
          ))
        )}
      </div>
    ),
  },
  {
    id: "group",
    label: "Группа",
    render: (row) => row.vulnerabilityGroup,
  },
];

interface FindingView {
  uid: string;
  reportId: string;
  reportFileName: string;
  createdAt: string;
  finding: NormalizedFinding;
}

interface AppSecRow extends FindingView {
  cvssScore: number;
  priority: PriorityLevel;
  priorityScore: number;
  vulnerabilityType: string;
  attackVector: AttackVector;
  businessComponent: string;
  ownerTeam: string;
  occurrences: number;
  status: StatusValue;
  ageDays: number;
  source: string;
  trend: TrendState;
  slsaLevel: string;
  riskFactors: string[];
  vulnerabilityGroup: string;
}

interface RowOverride {
  status?: StatusValue;
  ownerTeam?: string;
}

interface ColumnConfig {
  id: ColumnId;
  label: string;
  render: (row: AppSecRow) => ReactNode;
}

const PRIORITY_LABELS: Record<PriorityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const STATUS_LABELS: Record<StatusValue, string> = {
  new: "New",
  confirmed: "Confirmed",
  in_progress: "In progress",
  resolved: "Resolved",
};

const ATTACK_VECTOR_LABELS: Record<AttackVector, string> = {
  network: "Network",
  local: "Local",
  physical: "Physical",
  unknown: "Unknown",
};

const TREND_LABELS: Record<TrendState, string> = {
  up: "Рост",
  flat: "Без изменений",
  down: "Улучшается",
};

const TREND_ICONS: Record<TrendState, string> = {
  up: "⬆️",
  flat: "↔️",
  down: "⬇️",
};

const PRIORITY_ORDER: Record<PriorityLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export default function App() {
  const [sessionId] = useState(() => getOrCreateSessionId());
  const [reports, setReports] = useState<SarifReport[]>([]);
  const [filters, setFilters] = useState<FiltersState>(initialFilters);
  const [selectedFinding, setSelectedFinding] =
    useState<FindingView | null>(null);
  const [selectedRowIds, setSelectedRowIds] = useState<string[]>([]);
  const [visibleColumns, setVisibleColumns] =
    useState<ColumnId[]>(DEFAULT_VISIBLE_COLUMNS);
  const [rowOverrides, setRowOverrides] = useState<Record<string, RowOverride>>(
    {}
  );
  const [bulkTeam, setBulkTeam] = useState(TEAM_OPTIONS[0]);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
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
        uid: buildStableUid(report.id, finding.id, index),
        reportId: report.id,
        reportFileName: report.fileName,
        createdAt: report.createdAt,
        finding,
      }))
    );
  }, [reports]);

  const rawAppSecRows = useMemo(
    () => findingsView.map((entry) => buildAppSecRow(entry)),
    [findingsView]
  );

  const resolvedRows = useMemo(() => {
    const occurrencesMap = new Map<string, number>();
    rawAppSecRows.forEach((row) => {
      occurrencesMap.set(
        row.vulnerabilityGroup,
        (occurrencesMap.get(row.vulnerabilityGroup) ?? 0) + 1
      );
    });

    return rawAppSecRows.map((row) => {
      const overrides = rowOverrides[row.uid];
      return {
        ...row,
        occurrences: occurrencesMap.get(row.vulnerabilityGroup) ?? 1,
        ownerTeam: overrides?.ownerTeam ?? row.ownerTeam,
        status: overrides?.status ?? row.status,
      };
    });
  }, [rawAppSecRows, rowOverrides]);

  const filteredRows = useMemo(() => {
    const search = filters.search.trim().toLowerCase();
    return resolvedRows
      .filter((entry) => {
        const severityOk =
          filters.severity === "all" ||
          entry.finding.severity === filters.severity;
        const toolOk =
          filters.tool === "all" || entry.finding.tool.name === filters.tool;
        const reportOk =
          filters.reportId === "all" || entry.reportId === filters.reportId;
        const priorityOk =
          filters.priority.length === 0 ||
          filters.priority.includes(entry.priority);
        const statusOk =
          filters.status.length === 0 ||
          filters.status.includes(entry.status);
        const searchOk =
          !search ||
          [
            entry.finding.message,
            entry.finding.ruleId,
            entry.finding.ruleName,
            entry.finding.location?.file,
            entry.reportFileName,
            entry.ownerTeam,
            entry.businessComponent,
            entry.vulnerabilityType,
          ]
            .filter(Boolean)
            .some((value) => value!.toLowerCase().includes(search));
        return severityOk && toolOk && reportOk && priorityOk && statusOk && searchOk;
      })
      .sort((a, b) => {
        if (a.priority !== b.priority) {
          return PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority];
        }
        if (b.cvssScore !== a.cvssScore) {
          return b.cvssScore - a.cvssScore;
        }
        return b.ageDays - a.ageDays;
      });
  }, [resolvedRows, filters]);

  useEffect(() => {
    if (filteredRows.length === 0) {
      setSelectedFinding(null);
      return;
    }
    setSelectedFinding((prev) => {
      if (!prev) {
        return filteredRows[0];
      }
      const stillExists = filteredRows.find((item) => item.uid === prev.uid);
      return stillExists ?? filteredRows[0];
    });
  }, [filteredRows]);

  useEffect(() => {
    if (!actionMessage) {
      return;
    }
    const timer = window.setTimeout(() => setActionMessage(null), 4000);
    return () => window.clearTimeout(timer);
  }, [actionMessage]);

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

  const groupingData = useMemo(
    () => buildGroupingData(filteredRows, filters.groupBy),
    [filteredRows, filters.groupBy]
  );

  const visibleColumnConfig = useMemo(
    () =>
      COLUMN_CONFIG.filter((column) =>
        visibleColumns.includes(column.id)
      ),
    [visibleColumns]
  );

  const totalRenderedColumns = visibleColumnConfig.length + 1;

  const selectedRowsData = useMemo(
    () =>
      resolvedRows.filter((row) => selectedRowIds.includes(row.uid)),
    [resolvedRows, selectedRowIds]
  );

  const selectedMetrics = useMemo(
    () => computeSelectionMetrics(selectedRowsData),
    [selectedRowsData]
  );

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

  const allVisibleSelected =
    filteredRows.length > 0 &&
    filteredRows.every((row) => selectedRowIds.includes(row.uid));

  const togglePriorityLevel = (level: PriorityLevel) => {
    setFilters((prev) => {
      const alreadyActive = prev.priority.includes(level);
      const nextPriority = alreadyActive
        ? prev.priority.filter((value) => value !== level)
        : [...prev.priority, level];
      return { ...prev, priority: nextPriority };
    });
  };

  const toggleStatusValue = (value: StatusValue) => {
    setFilters((prev) => {
      const alreadyActive = prev.status.includes(value);
      const nextStatus = alreadyActive
        ? prev.status.filter((item) => item !== value)
        : [...prev.status, value];
      return { ...prev, status: nextStatus };
    });
  };

  const handleFindingSelect = (entry: FindingView) => {
    setSelectedFinding(entry);
  };

  const toggleRowSelection = (uid: string) => {
    setSelectedRowIds((prev) => {
      return prev.includes(uid)
        ? prev.filter((id) => id !== uid)
        : [...prev, uid];
    });
  };

  const toggleSelectAll = () => {
    setSelectedRowIds((prev) => {
      if (allVisibleSelected) {
        const visibleIds = new Set(filteredRows.map((row) => row.uid));
        return prev.filter((id) => !visibleIds.has(id));
      }
      const combined = new Set([...prev, ...filteredRows.map((row) => row.uid)]);
      return Array.from(combined);
    });
  };

  const clearSelection = () => {
    setSelectedRowIds([]);
  };

  const toggleColumnVisibility = (columnId: ColumnId) => {
    setVisibleColumns((prev) => {
      if (prev.includes(columnId)) {
        if (prev.length === 1) {
          return prev;
        }
        return prev.filter((item) => item !== columnId);
      }
      return [...prev, columnId];
    });
  };

  const resetColumns = () => {
    setVisibleColumns(DEFAULT_VISIBLE_COLUMNS);
  };

  const handleBulkStatusChange = (status: StatusValue) => {
    if (selectedRowIds.length === 0) {
      return;
    }
    setRowOverrides((prev) => {
      const next = { ...prev };
      selectedRowIds.forEach((uid) => {
        next[uid] = { ...(next[uid] ?? {}), status };
      });
      return next;
    });
    setActionMessage(
      `Статус «${STATUS_LABELS[status]}» применён к ${selectedRowIds.length} находкам`
    );
  };

  const handleBulkAssignTeam = () => {
    if (selectedRowIds.length === 0) {
      return;
    }
    setRowOverrides((prev) => {
      const next = { ...prev };
      selectedRowIds.forEach((uid) => {
        next[uid] = { ...(next[uid] ?? {}), ownerTeam: bulkTeam };
      });
      return next;
    });
    setActionMessage(
      `Команда «${bulkTeam}» назначена для ${selectedRowIds.length} находок`
    );
  };

  const handleBulkMetricsReport = () => {
    if (!selectedMetrics) {
      return;
    }
    setActionMessage(
      `Метрики: ср. CVSS ${selectedMetrics.avgCvss.toFixed(
        1
      )}, p90 возраст ${selectedMetrics.p90Age} дн., задействовано ${selectedMetrics.teamCount} команд`
    );
  };

  const handleResetFilters = () => {
    setFilters(initialFilters);
    setSelectedRowIds([]);
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

            <aside className="details">
              {selectedFinding ? (
                <FindingDetails entry={selectedFinding} />
              ) : (
                <p className="muted">
                  Выберите находку в таблице, чтобы увидеть подробности.
                </p>
              )}
            </aside>
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
            <div className="grouping-control">
              <label>
                Группировка
                <select
                  value={filters.groupBy}
                  onChange={(event) =>
                    setFilters((prev) => ({
                      ...prev,
                      groupBy: event.target.value as GroupingMode,
                    }))
                  }
                >
                  <option value="vulnType">Тип уязвимости</option>
                  <option value="ownerTeam">Проект / команда</option>
                  <option value="source">Источник</option>
                </select>
              </label>
            </div>
            <div className="group-grid">
              {groupingData.length === 0 ? (
                <p className="muted small">Нет данных для выбранной группировки.</p>
              ) : (
                groupingData.map((item) => (
                  <div key={item.key} className="group-card">
                    <p className="muted small">{item.label}</p>
                    <strong>{item.count}</strong>
                  </div>
                ))
              )}
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
            <div className="filter-group advanced">
              <div className="filter-chips">
                <p className="muted small">Приоритет</p>
                <div className="pill-group">
                  {(["critical", "high", "medium", "low"] as PriorityLevel[]).map(
                    (level) => (
                      <button
                        key={level}
                        className={`pill pill--outline ${
                          filters.priority.includes(level) ? "is-active" : ""
                        }`}
                        onClick={() => togglePriorityLevel(level)}
                        type="button"
                      >
                        {PRIORITY_LABELS[level]}
                      </button>
                    )
                  )}
                </div>
              </div>
              <div className="filter-chips">
                <p className="muted small">Статус</p>
                <div className="pill-group">
                  {(
                    ["new", "confirmed", "in_progress", "resolved"] as StatusValue[]
                  ).map((status) => (
                    <button
                      key={status}
                      className={`pill pill--outline ${
                        filters.status.includes(status) ? "is-active" : ""
                      }`}
                      onClick={() => toggleStatusValue(status)}
                      type="button"
                    >
                      {STATUS_LABELS[status]}
                    </button>
                  ))}
                </div>
              </div>
              <button
                className="action-button"
                type="button"
                onClick={handleResetFilters}
              >
                Сбросить фильтры
              </button>
            </div>
          </section>

          <section className="panel panel--content">
            <div className="table-stack">
              <details className="column-controls">
                <summary>Настроить столбцы</summary>
                <div className="column-controls__list">
                  {COLUMN_CONFIG.map((column) => {
                    const isChecked = visibleColumns.includes(column.id);
                    return (
                      <label key={column.id} className="column-toggle">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleColumnVisibility(column.id)}
                          disabled={isChecked && visibleColumns.length === 1}
                        />
                        {column.label}
                      </label>
                    );
                  })}
                </div>
                <button
                  type="button"
                  className="action-button column-controls__reset"
                  onClick={resetColumns}
                  disabled={visibleColumns.length === COLUMN_CONFIG.length}
                >
                  Сбросить столбцы
                </button>
              </details>
              <div className="bulk-actions">
                <div className="bulk-actions__primary">
                  <button
                    className="action-button"
                    type="button"
                    onClick={toggleSelectAll}
                    disabled={filteredRows.length === 0}
                  >
                    {allVisibleSelected ? "Снять выделение" : "Выделить всё"}
                  </button>
                  <button
                    className="action-button"
                    type="button"
                    onClick={clearSelection}
                    disabled={selectedRowIds.length === 0}
                  >
                    Очистить выбор
                  </button>
                  <button
                    className="action-button"
                    type="button"
                    onClick={() => handleBulkStatusChange("confirmed")}
                    disabled={selectedRowIds.length === 0}
                  >
                    Статус: Confirmed
                  </button>
                  <button
                    className="action-button"
                    type="button"
                    onClick={() => handleBulkStatusChange("in_progress")}
                    disabled={selectedRowIds.length === 0}
                  >
                    Статус: In progress
                  </button>
                </div>
                <div className="bulk-actions__secondary">
                  <label>
                    Команда
                    <select
                      value={bulkTeam}
                      onChange={(event) => setBulkTeam(event.target.value)}
                    >
                      {TEAM_OPTIONS.map((team) => (
                        <option key={team} value={team}>
                          {team}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    className="action-button action-button--primary"
                    type="button"
                    onClick={handleBulkAssignTeam}
                    disabled={selectedRowIds.length === 0}
                  >
                    Назначить команде
                  </button>
                  <button
                    className="action-button"
                    type="button"
                    onClick={handleBulkMetricsReport}
                    disabled={!selectedMetrics}
                  >
                    Расчёт метрик
                  </button>
                </div>
              </div>

              {actionMessage && (
                <div className="banner banner--info">{actionMessage}</div>
              )}

              <div className="table-scroll">
                <table className="appsec-table">
                  <thead>
                    <tr>
                      <th>
                        <input
                          type="checkbox"
                          checked={allVisibleSelected}
                          onChange={toggleSelectAll}
                          disabled={filteredRows.length === 0}
                        />
                      </th>
                      {visibleColumnConfig.map((column) => (
                        <th key={column.id}>{column.label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRows.length === 0 ? (
                      <tr>
                        <td colSpan={totalRenderedColumns}>
                          <p className="table-empty">
                            Нет находок под текущие фильтры. Ослабьте фильтры
                            или измените условие возраста.
                          </p>
                        </td>
                      </tr>
                    ) : (
                      filteredRows.map((entry) => (
                        <tr
                          key={entry.uid}
                          className={
                            selectedFinding?.uid === entry.uid ? "is-active" : ""
                          }
                          onClick={() => handleFindingSelect(entry)}
                        >
                          <td>
                            <input
                              type="checkbox"
                              checked={selectedRowIds.includes(entry.uid)}
                              onChange={(event) => {
                                event.stopPropagation();
                                toggleRowSelection(entry.uid);
                              }}
                            />
                          </td>
                          {visibleColumnConfig.map((column) => (
                            <td key={column.id}>{column.render(entry)}</td>
                          ))}
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {selectedMetrics && (
                <div className="selection-summary">
                  <p>
                    Выбрано находок:{" "}
                    <strong>{selectedRowIds.length}</strong>
                  </p>
                  <div className="selection-summary__grid">
                    <div>
                      <span className="muted small">Средний CVSS</span>
                      <strong>{selectedMetrics.avgCvss.toFixed(1)}</strong>
                    </div>
                    <div>
                      <span className="muted small">p90 возраст</span>
                      <strong>{selectedMetrics.p90Age} дн.</strong>
                    </div>
                    <div>
                      <span className="muted small">Макс. возраст</span>
                      <strong>{selectedMetrics.maxAge} дн.</strong>
                    </div>
                    <div>
                      <span className="muted small">Команд задействовано</span>
                      <strong>{selectedMetrics.teamCount}</strong>
                    </div>
                  </div>
                </div>
              )}
            </div>

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

interface GroupingItem {
  key: string;
  label: string;
  count: number;
}

interface SelectionMetrics {
  avgCvss: number;
  maxAge: number;
  p90Age: number;
  teamCount: number;
}

const SEVERITY_CVSS_FALLBACK: Record<NormalizedSeverity, number> = {
  error: 9.1,
  warning: 6.8,
  note: 3.5,
  none: 1,
  pass: 0.1,
  open: 7,
  review: 5,
  informational: 2.5,
  unknown: 5,
};

const SEVERITY_PRIORITY_WEIGHT: Record<NormalizedSeverity, number> = {
  error: 1.5,
  warning: 1,
  note: 0.3,
  none: 0,
  pass: 0,
  open: 1.2,
  review: 0.8,
  informational: 0.2,
  unknown: 0.5,
};

function buildAppSecRow(entry: FindingView): AppSecRow {
  const cvssScore = extractCvssScore(entry.finding);
  const riskFactors = deriveRiskFactors(entry);
  const businessComponent = deriveBusinessComponent(entry);
  const ownerTeam = deriveOwnerTeam(entry, businessComponent);
  const ageDays = calculateAgeDays(entry.createdAt);
  const priorityScore = calculatePriorityScore(
    entry.finding.severity,
    cvssScore,
    riskFactors
  );
  const priority = toPriorityLevel(priorityScore);
  const attackVector = deriveAttackVector(entry.finding, riskFactors);
  const vulnerabilityType = deriveVulnerabilityType(entry.finding);
  const status = deriveStatus(entry.finding, ageDays);
  const trend = deriveTrend(ageDays, entry.finding.severity);
  const slsaLevel = deriveSlsaLevel(entry.finding);
  const vulnerabilityGroup = deriveGroupKey(
    vulnerabilityType,
    businessComponent
  );

  return {
    ...entry,
    cvssScore,
    priority,
    priorityScore,
    vulnerabilityType,
    attackVector,
    businessComponent,
    ownerTeam,
    occurrences: 1,
    status,
    ageDays,
    source: entry.finding.tool.name,
    trend,
    slsaLevel,
    riskFactors,
    vulnerabilityGroup,
  };
}

function extractCvssScore(finding: NormalizedFinding): number {
  const props = finding.properties ?? {};
  const candidates: unknown[] = [
    (props as { cvssScore?: unknown }).cvssScore,
    (props as { cvss?: { baseScore?: unknown } }).cvss?.baseScore,
    (props as { cvss?: { score?: unknown } }).cvss?.score,
    (props as { cvss_v3?: { baseScore?: unknown } }).cvss_v3?.baseScore,
    (props as { severityScore?: unknown }).severityScore,
  ];

  for (const value of candidates) {
    const numeric = toNumber(value);
    if (numeric != null) {
      return Math.min(10, Math.max(0, numeric));
    }
  }

  return SEVERITY_CVSS_FALLBACK[finding.severity] ?? 5;
}

function deriveRiskFactors(entry: FindingView): string[] {
  const tags = entry.finding.tags.map((tag) => tag.toLowerCase());
  const text = `${entry.finding.ruleId} ${entry.finding.ruleName ?? ""} ${
    entry.finding.message
  }`.toLowerCase();
  const location = entry.finding.location?.file?.toLowerCase() ?? "";
  const toolName = entry.finding.tool.name.toLowerCase();
  const result = new Set<string>();

  if (tags.some((tag) => tag.includes("pii") || tag.includes("personal"))) {
    result.add("PII");
  }
  if (text.includes("sql") || text.includes("nosql")) {
    result.add("Data store");
  }
  if (text.includes("password") || text.includes("auth")) {
    result.add("Credentials");
  }
  if (text.includes("xss") || text.includes("script")) {
    result.add("Client impact");
  }
  if (toolName.includes("dast") || location.includes("public")) {
    result.add("External surface");
  }
  if (text.includes("supply") || tags.includes("slsa")) {
    result.add("Supply chain");
  }
  if (text.includes("payment") || text.includes("card")) {
    result.add("PCI scope");
  }

  return Array.from(result);
}

function deriveAttackVector(
  finding: NormalizedFinding,
  riskFactors: string[]
): AttackVector {
  const descriptor = `${finding.ruleId} ${finding.ruleName ?? ""} ${
    finding.message
  }`.toLowerCase();

  if (
    riskFactors.includes("External surface") ||
    descriptor.includes("xss") ||
    descriptor.includes("sql") ||
    descriptor.includes("command injection")
  ) {
    return "network";
  }

  if (
    descriptor.includes("deserialization") ||
    descriptor.includes("local") ||
    descriptor.includes("filesystem")
  ) {
    return "local";
  }

  if (descriptor.includes("physical")) {
    return "physical";
  }

  return "unknown";
}

function deriveBusinessComponent(entry: FindingView): string {
  const file = entry.finding.location?.file;
  if (!file) {
    return "Core Platform";
  }
  const normalized = file.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  const lowered = normalized.toLowerCase();
  if (lowered.includes("auth") || lowered.includes("identity")) {
    return "Identity Service";
  }
  if (lowered.includes("payment") || lowered.includes("billing")) {
    return "Payments Service";
  }
  if (lowered.includes("checkout") || lowered.includes("order")) {
    return "Commerce API";
  }
  if (lowered.includes("mobile") || lowered.includes("ios")) {
    return "Mobile App";
  }
  if (lowered.includes("infra") || lowered.includes("deploy")) {
    return "Platform Infrastructure";
  }
  const segments = normalized.split("/");
  if (segments.length >= 2) {
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0] || "Core Platform";
}

function deriveOwnerTeam(entry: FindingView, businessComponent: string): string {
  const props = entry.finding.properties ?? {};
  const explicitTeam =
    getString(props, "ownerTeam") ??
    getString(props, "team") ??
    getString(props, "project");
  if (explicitTeam) {
    return explicitTeam;
  }

  if (businessComponent.includes("Identity")) {
    return "Identity Platform";
  }
  if (businessComponent.includes("Payments")) {
    return "Payments & Billing";
  }
  if (businessComponent.includes("Mobile")) {
    return "Digital Experience";
  }
  if (businessComponent.includes("Infrastructure")) {
    return "Cloud SecOps";
  }
  return "AppSec Platform";
}

function deriveStatus(
  finding: NormalizedFinding,
  ageDays: number
): StatusValue {
  const props = finding.properties ?? {};
  const explicit = getString(props, "status");
  if (explicit) {
    const normalized = explicit.toLowerCase();
    if (normalized.includes("progress")) {
      return "in_progress";
    }
    if (normalized.includes("confirm")) {
      return "confirmed";
    }
    if (normalized.includes("resolve") || normalized.includes("closed")) {
      return "resolved";
    }
    if (normalized.includes("new")) {
      return "new";
    }
  }

  if (ageDays <= 7) {
    return "new";
  }
  if (ageDays <= 30) {
    return "confirmed";
  }
  return "in_progress";
}

function deriveTrend(ageDays: number, severity: NormalizedSeverity): TrendState {
  if (ageDays > 30 && (severity === "error" || severity === "warning")) {
    return "up";
  }
  if (ageDays < 10) {
    return "down";
  }
  return "flat";
}

function deriveSlsaLevel(finding: NormalizedFinding): string {
  const props = finding.properties ?? {};
  const explicit =
    getString(props, "slsaLevel") ??
    getString(props, "slsa") ??
    getString(props, "supplyLevel");
  if (explicit) {
    return explicit.toUpperCase();
  }

  if (finding.tags.some((tag) => tag.toLowerCase().includes("slsa3"))) {
    return "L3";
  }
  if (finding.severity === "error" || finding.severity === "warning") {
    return "L2";
  }
  return "L1";
}

function deriveVulnerabilityType(finding: NormalizedFinding): string {
  const lowerTags = finding.tags.map((tag) => tag.toLowerCase());
  const cweTag = lowerTags.find((tag) => tag.startsWith("cwe-"));
  if (cweTag) {
    return cweTag.toUpperCase();
  }
  const ruleText = `${finding.ruleName ?? finding.ruleId}`.toLowerCase();
  if (ruleText.includes("sql")) {
    return "SQL Injection";
  }
  if (ruleText.includes("xss")) {
    return "Cross-site scripting";
  }
  if (ruleText.includes("command")) {
    return "OS Commanding";
  }
  if (ruleText.includes("csrf")) {
    return "CSRF";
  }
  if (ruleText.includes("deserialization")) {
    return "Deserialization";
  }
  return capitalize(finding.ruleName ?? finding.ruleId);
}

function deriveGroupKey(vulnerabilityType: string, component: string) {
  return `${vulnerabilityType} · ${component}`;
}

function calculateAgeDays(createdAt: string): number {
  const created = new Date(createdAt).getTime();
  if (Number.isNaN(created)) {
    return 0;
  }
  const diff = Date.now() - created;
  return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
}

function calculatePriorityScore(
  severity: NormalizedSeverity,
  cvssScore: number,
  riskFactors: string[]
): number {
  const base = cvssScore;
  const severityBonus = SEVERITY_PRIORITY_WEIGHT[severity] ?? 0;
  const contextBonus = Math.min(1.5, riskFactors.length * 0.4);
  return Math.min(10, base + severityBonus + contextBonus);
}

function toPriorityLevel(score: number): PriorityLevel {
  if (score >= 9) {
    return "critical";
  }
  if (score >= 7) {
    return "high";
  }
  if (score >= 4) {
    return "medium";
  }
  return "low";
}

function toNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function getString(
  source: Record<string, unknown>,
  key: string
): string | undefined {
  const value = source?.[key];
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  return undefined;
}

function capitalize(value: string) {
  if (!value) {
    return "—";
  }
  return value[0].toUpperCase() + value.slice(1);
}

function buildStableUid(
  reportId: string,
  findingId: string | undefined,
  index: number
): string {
  const normalizedFindingId =
    findingId && findingId.trim().length > 0 ? findingId : `idx-${index}`;
  return `${reportId}::${normalizedFindingId}::${index}`;
}

function buildGroupingData(
  rows: AppSecRow[],
  mode: GroupingMode
): GroupingItem[] {
  const counters = new Map<string, number>();
  rows.forEach((row) => {
    const key =
      mode === "vulnType"
        ? row.vulnerabilityType
        : mode === "ownerTeam"
        ? row.ownerTeam
        : row.source;
    counters.set(key, (counters.get(key) ?? 0) + 1);
  });

  return Array.from(counters.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([key, count]) => ({
      key,
      label: key,
      count,
    }));
}

function computeSelectionMetrics(
  rows: AppSecRow[]
): SelectionMetrics | null {
  if (rows.length === 0) {
    return null;
  }
  const avgCvss =
    rows.reduce((sum, row) => sum + row.cvssScore, 0) / rows.length;
  const ages = rows.map((row) => row.ageDays).sort((a, b) => a - b);
  const p90Index = Math.max(0, Math.ceil(ages.length * 0.9) - 1);
  const teamCount = new Set(rows.map((row) => row.ownerTeam)).size;
  return {
    avgCvss,
    maxAge: ages[ages.length - 1],
    p90Age: ages[p90Index],
    teamCount,
  };
}


