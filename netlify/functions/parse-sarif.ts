import type { Handler } from "@netlify/functions";

import { normalizeSarif } from "../../src/lib/normalize-sarif";
import { supabase } from "../lib/supabase-client";

const TABLE_NAME = "sarif_reports";
const MAX_REPORTS_PER_SESSION = 10;

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

  if (event.httpMethod === "GET") {
    return handleGet(event);
  }

  if (event.httpMethod === "POST") {
    return handlePost(event);
  }

  return {
    statusCode: 405,
    headers: defaultHeaders,
    body: JSON.stringify({ message: "Метод не поддерживается" }),
  };
};

async function handleGet(event: Parameters<Handler>[0]) {
  const sessionId = event.queryStringParameters?.sessionId;
  if (!sessionId) {
    return {
      statusCode: 400,
      headers: defaultHeaders,
      body: JSON.stringify({ message: "sessionId обязателен" }),
    };
  }

  const { data, error } = await supabase
    .from(TABLE_NAME)
    .select("*")
    .eq("session_id", sessionId)
    .order("created_at", { ascending: false });

  if (error) {
    return {
      statusCode: 500,
      headers: defaultHeaders,
      body: JSON.stringify({ message: `Supabase error: ${error.message}` }),
    };
  }

  return {
    statusCode: 200,
    headers: defaultHeaders,
    body: JSON.stringify(data ?? []),
  };
}

async function handlePost(event: Parameters<Handler>[0]) {
  try {
    const { sarifPayload, fileName, sessionId } = extractSarifPayload(event);
    if (!sessionId) {
      throw new Error("sessionId обязателен");
    }

    const normalized = normalizeSarif(sarifPayload, { fileName });
    await ensureLimitNotExceeded(sessionId);

    const { data, error } = await supabase
      .from(TABLE_NAME)
      .insert({
        session_id: sessionId,
        file_name: normalized.metadata.fileName ?? fileName ?? "sarif.json",
        normalized,
      })
      .select()
      .single();

    if (error) {
      throw new Error(`Supabase insert error: ${error.message}`);
    }

    return {
      statusCode: 200,
      headers: defaultHeaders,
      body: JSON.stringify(data),
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
}

async function ensureLimitNotExceeded(sessionId: string) {
  const { count, error } = await supabase
    .from(TABLE_NAME)
    .select("*", { count: "exact", head: true })
    .eq("session_id", sessionId);

  if (error) {
    throw new Error(`Supabase count error: ${error.message}`);
  }

  if ((count ?? 0) >= MAX_REPORTS_PER_SESSION) {
    throw new Error(
      `Достигнут лимит ${MAX_REPORTS_PER_SESSION} отчетов для текущей сессии`
    );
  }
}

function extractSarifPayload(event: Parameters<Handler>[0]) {
  const rawBody = decodeBody(event.body ?? "", event.isBase64Encoded);
  if (!rawBody) {
    throw new Error("Тело запроса пустое");
  }

  try {
    const parsed = JSON.parse(rawBody);
    if (parsed && typeof parsed === "object" && "sarif" in parsed) {
      const sarifValue = (parsed as { sarif?: unknown }).sarif;
      return {
        sarifPayload: sarifValue,
        fileName:
          (parsed as { fileName?: string }).fileName ??
          (parsed as { filename?: string }).filename,
        sessionId: (parsed as { sessionId?: string }).sessionId,
      };
    }

    return {
      sarifPayload: parsed,
      fileName: (parsed as { fileName?: string }).fileName,
      sessionId: (parsed as { sessionId?: string }).sessionId,
    };
  } catch {
    return {
      sarifPayload: rawBody,
      fileName: undefined,
      sessionId: undefined,
    };
  }
}

function decodeBody(body: string, isBase64?: boolean) {
  return isBase64 ? Buffer.from(body, "base64").toString("utf-8") : body;
}

export { handler };



