# DM-base

Application security defect management platform: Iteration 1 delivers a SARIF parser + viewer for AppSec инженеров.

## Быстрый старт

```bash
npm install
cd frontend && npm install
cd ..
```

Создайте файл `.env` в корне (и в Netlify env) с переменными:

```
SUPABASE_URL=...
SUPABASE_ANON_KEY=...
# опционально, если есть service-role
SUPABASE_SERVICE_ROLE_KEY=...
```

### Локальная разработка

- `npm run dev:frontend` — UI на Vite (http://localhost:5173)
- `npm run dev` — Netlify Dev (UI + serverless `parse-sarif`)
- `npm test` — Vitest для нормализации SARIF

### Сборка и деплой

- `npm run build` — собирает frontend (Netlify использует `netlify.toml`)
- На Netlify:
  - Build command: `npm run build`
  - Publish directory: `frontend/dist`
  - Functions directory: `netlify/functions`

## Структура

- `/netlify/functions/parse-sarif.ts` — serverless парсер + нормализатор
- `/src/lib/normalize-sarif.ts` — общая логика нормализации
- `/frontend` — React/Vite клиент (upload + фильтры + viewer)
- SARIF fixtures (`AI*.sarif`, `bbs*.sarif`) — для тестов и проверок

## Supabase

- Создайте таблицу `sarif_reports` со столбцами:
  - `id uuid primary key default gen_random_uuid()`
  - `session_id text`
  - `file_name text`
  - `normalized jsonb`
  - `created_at timestamptz default now()`
- Разрешите вставку/чтение для ключа (политика RLS по `session_id`).
- Приложение хранит до 10 отчётов на `session_id`; ID хранится в `localStorage`.

## TODO Iteration 2 (идеи)

- Авторизация и сохранение сессий/проектов
- Аннотации и статус triage
- Интеграции (Jira, Slack)
- Поддержка других форматов отчётов
