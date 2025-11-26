# DM-base

Application security defect management platform: Iteration 1 delivers a SARIF parser + viewer for AppSec инженеров.

## Быстрый старт

```bash
npm install
cd frontend && npm install
cd ..
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

## TODO Iteration 2 (идеи)

- Авторизация и сохранение сессий/проектов
- Аннотации и статус triage
- Интеграции (Jira, Slack)
- Поддержка других форматов отчётов
