import type { Handler } from "@netlify/functions";

import { normalizeSarif } from "../../src/lib/normalize-sarif";

const defaultHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
};

const handler: Handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        ...defaultHeaders,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
      body: "",
    };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: defaultHeaders,
      body: JSON.stringify({ message: "Только POST поддерживается" }),
    };
  }

  try {
    const { sarifPayload, fileName } = extractSarifPayload(event);
    const normalized = normalizeSarif(sarifPayload, { fileName });

    return {
      statusCode: 200,
      headers: defaultHeaders,
      body: JSON.stringify(normalized),
    };
  } catch (error) {
    return {
      statusCode: 400,
      headers: defaultHeaders,
      body: JSON.stringify({
        message:
          error instanceof Error
            ? error.message
            : "Не удалось обработать SARIF отчёт",
      }),
    };
  }
};

function extractSarifPayload(event: Parameters<Handler>[0]) {
  const rawBody = decodeBody(event.body ?? "", event.isBase64Encoded);
  if (!rawBody) {
    throw new Error("Тело запроса пустое");
  }

  try {
    const parsed = JSON.parse(rawBody);
    if (parsed && typeof parsed === "object" && "sarif" in parsed) {
      const sarifValue =
        (parsed as { sarif?: unknown }).sarif ??
        (parsed as { sarif?: unknown }).sarif;
      return {
        sarifPayload: sarifValue,
        fileName:
          (parsed as { fileName?: string }).fileName ??
          (parsed as { filename?: string }).filename,
      };
    }

    return {
      sarifPayload: parsed,
      fileName: (parsed as { fileName?: string }).fileName,
    };
  } catch {
    return {
      sarifPayload: rawBody,
      fileName: undefined,
    };
  }
}

function decodeBody(body: string, isBase64?: boolean) {
  return isBase64 ? Buffer.from(body, "base64").toString("utf-8") : body;
}

export { handler };


