import type { NormalizedSarif } from "./types/sarif";

const FUNCTIONS_BASE =
  import.meta.env.VITE_FUNCTIONS_BASE ?? "/.netlify/functions";

export async function uploadSarifFile(file: File): Promise<NormalizedSarif> {
  const sarifText = await file.text();
  const response = await fetch(`${FUNCTIONS_BASE}/parse-sarif`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      sarif: sarifText,
      fileName: file.name,
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

  return (await response.json()) as NormalizedSarif;
}


