FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4173

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY --chown=node:node . .
RUN npm run build:client && chown -R node:node /app

USER node
EXPOSE 4173
CMD ["node", "--experimental-strip-types", "server/index.mjs"]
