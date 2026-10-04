# 221B: one image, one process. Stage 1 builds the UI; stage 2 runs the API, which also serves the UI.
FROM node:20-slim AS ui
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
COPY contract/ ../contract/
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8221
WORKDIR /app
COPY pyproject.toml README.md ./
COPY backend ./backend
COPY sim ./sim
COPY eval ./eval
RUN pip install --no-cache-dir .
COPY contract ./contract
COPY docs ./docs
COPY --from=ui /app/frontend/dist ./frontend/dist
RUN useradd --create-home app && chown -R app /app
USER app
EXPOSE 8221
CMD ["sh", "-c", "uvicorn backend.api.app:app --host 0.0.0.0 --port ${PORT}"]
