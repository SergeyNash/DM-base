import type { NormalizedSarif, SarifReport } from "./types/sarif";

const FUNCTIONS_BASE =
  import.meta.env.VITE_FUNCTIONS_BASE ?? "/.netlify/functions";

export async function uploadSarifFile(
  file: File,
  sessionId: string
): Promise<SarifReport> {
  const sarifText = await file.text();
  const response = await fetch(`${FUNCTIONS_BASE}/parse-sarif`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      sarif: sarifText,
      fileName: file.name,
      sessionId,
    }),
  });

  if (!response.ok) {
    let errorMessage = "Не удалось загрузить SARIF файл";
    try {
      const data = await response.json();
      if (data?.message) {
        errorMessage = data.message;
      }
    } catch {
      // ignore
    }
    throw new Error(errorMessage);
  }

  const payload = await response.json();
  return mapReport(payload);
}

export async function fetchReports(
  sessionId: string
): Promise<SarifReport[]> {
  const params = new URLSearchParams({ sessionId });
  const response = await fetch(
    `${FUNCTIONS_BASE}/parse-sarif?${params.toString()}`,
    { method: "GET" }
  );

  if (!response.ok) {
    throw new Error("Не удалось получить список отчётов");
  }

  const payload = (await response.json()) as Array<{
    id: string;
    session_id: string;
    file_name: string;
    created_at: string;
    normalized: NormalizedSarif;
  }>;

  return payload.map(mapReport);
}

function mapReport(input: {
  id: string;
  session_id: string;
  file_name: string;
  created_at: string;
  normalized: NormalizedSarif;
}): SarifReport {
  return {
    id: input.id,
    sessionId: input.session_id,
    fileName: input.file_name,
    createdAt: input.created_at,
    normalized: input.normalized,
  };
}



