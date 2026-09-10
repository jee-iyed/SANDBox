# SANDBox frontend - development image (Vite dev server on 0.0.0.0:3000).
# The browser reaches the backend directly (http://localhost:8001) thanks to
# the backend's permissive CORS (allow_origins=["*"]); no reverse proxy needed.
#
# For a production deployment, build `npm run build` and serve `dist/` behind
# any static server / CDN (or add a dedicated multi-stage target here).

FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 3000

# host 0.0.0.0 is also enforced by vite.config.ts
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]